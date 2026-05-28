package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const (
	ExecutorPort    = "8766"
	QuarantineZone  = "/var/lib/heimdall/quarantine/"
	DBPath          = "/var/lib/heimdall/events.db"
)

type HeimdallVerdict struct {
	ActionRequired string `json:"action_required"`
	Target         string `json:"target"`
	ThreatClass    string `json:"threat_class"`
	Reasoning      string `json:"reasoning"`
	EventID        int64  `json:"event_id"`
	SchemaVersion  string `json:"schema_version"`
}

type ActionResult struct {
	Success      bool   `json:"success"`
	ActionType   string `json:"action_type"`
	Target       string `json:"target"`
	RollbackData string `json:"rollback_data"`
	ExecutedAt   string `json:"executed_at"`
}

func startExecutor() {
	log.Printf("[*] Bifrost Executor starting on port %s...", ExecutorPort)
	http.HandleFunc("/execute", handleVerdict)
	http.HandleFunc("/rollback", handleRollback)
	http.HandleFunc("/health", handleHealth)
	log.Fatal(http.ListenAndServe("127.0.0.1:"+ExecutorPort, nil))
}

func handleVerdict(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Read error", http.StatusBadRequest)
		return
	}

	var verdict HeimdallVerdict
	if err := json.Unmarshal(body, &verdict); err != nil {
		http.Error(w, "Invalid verdict schema", http.StatusBadRequest)
		return
	}

	go dispatchMitigation(verdict)

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"dispatched"}`))
}

func handleRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Read error", http.StatusBadRequest)
		return
	}

	var req struct {
		ActionID int64 `json:"action_id"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	err = rollbackAction(req.ActionID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"rolled_back"}`))
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok","component":"bifrost_executor"}`))
}

func dispatchMitigation(v HeimdallVerdict) {
	if v.Target == "" || v.Target == "null" {
		return
	}

	log.Printf(
		"[!!!] AUTONOMOUS ACTION: %s targeting %s — %s",
		v.ActionRequired, v.Target, v.Reasoning,
	)

	var result ActionResult
	result.ActionType = v.ActionRequired
	result.Target = v.Target
	result.ExecutedAt = time.Now().UTC().Format(time.RFC3339)

	switch v.ActionRequired {
	case "KILL":
		result = killProcess(v)
	case "BLOCK":
		result = blockIP(v)
	case "QUARANTINE":
		result = quarantineFile(v)
	default:
		log.Printf("[*] Non-disruptive action: %s", v.ActionRequired)
		return
	}

	logAction(v.EventID, result)
}

func killProcess(v HeimdallVerdict) ActionResult {
	result := ActionResult{
		ActionType: "KILL",
		Target:     v.Target,
		ExecutedAt: time.Now().UTC().Format(time.RFC3339),
	}

	pid, err := strconv.Atoi(v.Target)
	if err != nil {
		log.Printf("[!] Invalid PID: %v", err)
		result.Success = false
		return result
	}

	// Safety guard — never kill init or kernel threads
	if pid <= 2 {
		log.Printf("[!] SAFETY BLOCK: Refused to kill PID %d", pid)
		result.Success = false
		return result
	}

	// Read process info before killing for rollback record
	cmdline := ""
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	if data, err := os.ReadFile(cmdlinePath); err == nil {
		cmdline = string(data)
	}
	result.RollbackData = fmt.Sprintf(
		`{"pid":%d,"cmdline":"%s","note":"process_killed_cannot_restart"}`,
		pid, cmdline,
	)

	cmd := exec.Command("kill", "-9", strconv.Itoa(pid))
	if err := cmd.Run(); err != nil {
		log.Printf("[!] Kill failed for PID %d: %v", pid, err)
		result.Success = false
		return result
	}

	log.Printf("[+] Killed PID %d. Reason: %s", pid, v.Reasoning)
	result.Success = true
	return result
}

func blockIP(v HeimdallVerdict) ActionResult {
	result := ActionResult{
		ActionType: "BLOCK",
		Target:     v.Target,
		ExecutedAt: time.Now().UTC().Format(time.RFC3339),
	}

	// Validate IP length — prevents injection
	if len(v.Target) > 45 {
		log.Printf("[!] IP too long — block aborted: %s", v.Target)
		result.Success = false
		return result
	}

	result.RollbackData = fmt.Sprintf(
		`{"ip":"%s","action":"ufw_deny","rollback":"ufw delete deny from %s"}`,
		v.Target, v.Target,
	)

	cmd := exec.Command("sudo", "ufw", "insert", "1", "deny", "from", v.Target)
	if err := cmd.Run(); err != nil {
		log.Printf("[!] UFW block failed for %s: %v", v.Target, err)
		result.Success = false
		return result
	}

	log.Printf("[+] Blocked IP: %s. Reason: %s", v.Target, v.Reasoning)
	result.Success = true
	return result
}

func quarantineFile(v HeimdallVerdict) ActionResult {
	result := ActionResult{
		ActionType: "QUARANTINE",
		Target:     v.Target,
		ExecutedAt: time.Now().UTC().Format(time.RFC3339),
	}

	if err := os.MkdirAll(QuarantineZone, 0700); err != nil {
		log.Printf("[!] Cannot create quarantine zone: %v", err)
		result.Success = false
		return result
	}

	originalName := filepath.Base(v.Target)
	destName := fmt.Sprintf(
		"%d_%s.quarantined",
		time.Now().UnixNano(), originalName,
	)
	destPath := filepath.Join(QuarantineZone, destName)

	result.RollbackData = fmt.Sprintf(
		`{"original":"%s","quarantined":"%s","rollback":"mv %s %s"}`,
		v.Target, destPath, destPath, v.Target,
	)

	if err := exec.Command("mv", v.Target, destPath).Run(); err != nil {
		log.Printf("[!] Quarantine move failed: %v", err)
		result.Success = false
		return result
	}

	// Strip all permissions
	_ = exec.Command("chmod", "000", destPath).Run()

	log.Printf("[+] Quarantined: %s → %s", v.Target, destPath)
	result.Success = true
	return result
}

func logAction(eventID int64, result ActionResult) {
	db, err := sql.Open("sqlite3", DBPath)
	if err != nil {
		log.Printf("[!] Cannot open DB for action log: %v", err)
		return
	}
	defer db.Close()

	_, err = db.Exec(`
		INSERT INTO actions
		(event_id, action_type, target, executed_at, success, rollback_data)
		VALUES (?, ?, ?, ?, ?, ?)
	`,
		eventID,
		result.ActionType,
		result.Target,
		result.ExecutedAt,
		result.Success,
		result.RollbackData,
	)
	if err != nil {
		log.Printf("[!] Action log write failed: %v", err)
	}
}

func rollbackAction(actionID int64) error {
	db, err := sql.Open("sqlite3", DBPath)
	if err != nil {
		return fmt.Errorf("DB open failed: %v", err)
	}
	defer db.Close()

	var actionType, rollbackData string
	err = db.QueryRow(`
		SELECT action_type, rollback_data
		FROM actions WHERE id = ?
	`, actionID).Scan(&actionType, &rollbackData)
	if err != nil {
		return fmt.Errorf("Action not found: %v", err)
	}

	log.Printf("[*] Rolling back action %d: %s", actionID, actionType)

	switch actionType {
	case "BLOCK":
		var data struct {
			IP string `json:"ip"`
		}
		if err := json.Unmarshal([]byte(rollbackData), &data); err == nil {
			exec.Command("sudo", "ufw", "delete", "deny", "from", data.IP).Run()
			log.Printf("[+] Rollback: Removed UFW block on %s", data.IP)
		}
	case "QUARANTINE":
		var data struct {
			Original    string `json:"original"`
			Quarantined string `json:"quarantined"`
		}
		if err := json.Unmarshal([]byte(rollbackData), &data); err == nil {
			exec.Command("mv", data.Quarantined, data.Original).Run()
			log.Printf("[+] Rollback: Restored %s", data.Original)
		}
	case "KILL":
		log.Printf("[*] Cannot roll back process kill — process is gone.")
	}

	_, err = db.Exec(`
		UPDATE actions SET rolled_back = 1 WHERE id = ?
	`, actionID)
	return err
}
