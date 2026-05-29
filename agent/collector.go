package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	UnixSocketPath  = "/var/run/bifrost_telemetry.sock"
	PythonEngineURL = "http://127.0.0.1:8765/ingest"
	WorkerCount     = 4
	QueueSize       = 5000
)

// TelemetryEnvelope matches the RawEvent schema in heimdall/schema.py
type TelemetryEnvelope struct {
	Source    string      `json:"source"`
	Timestamp string      `json:"timestamp"`
	Boundary  string      `json:"boundary"`
	Raw       interface{} `json:"raw"`
}

func startCollector() {
	log.Println("[*] Bifrost Telemetry Collector starting...")

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signalChan
		log.Println("[!] Collector shutting down. Cleaning socket...")
		_ = os.Remove(UnixSocketPath)
		os.Exit(0)
	}()

	_ = os.Remove(UnixSocketPath)
	listener, err := net.Listen("unix", UnixSocketPath)
	if err != nil {
		log.Fatalf("[!] Cannot bind Unix socket %s: %v", UnixSocketPath, err)
	}
	defer listener.Close()
	_ = os.Chmod(UnixSocketPath, 0666)

	log.Printf("[+] Collector listening on %s", UnixSocketPath)
	log.Printf("[+] Forwarding to %s", PythonEngineURL)

	queue := make(chan TelemetryEnvelope, QueueSize)

	for w := 1; w <= WorkerCount; w++ {
		go dispatchWorker(queue, w)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[!] Accept error: %v", err)
			continue
		}
		go handleConnection(conn, queue)
	}
}

func handleConnection(conn net.Conn, queue chan<- TelemetryEnvelope) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		boundary := "HOST"
		source := "kernel_extractor"

		if bytes.Contains(line, []byte(`"src_ip"`)) ||
			bytes.Contains(line, []byte(`cowrie`)) {
			boundary = "HONEYPOT"
			source = "cowrie"
		} else if bytes.Contains(line, []byte(`tetragon`)) {
			source = "tetragon"
		}

		var rawData interface{}
		if err := json.Unmarshal(line, &rawData); err != nil {
			rawData = string(line)
		}

		envelope := TelemetryEnvelope{
			Source:    source,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Boundary:  boundary,
			Raw:       rawData,
		}

		select {
		case queue <- envelope:
		default:
			log.Println("[!] Queue full. Dropping telemetry frame.")
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[!] Scanner error: %v", err)
	}
}

func dispatchWorker(queue <-chan TelemetryEnvelope, id int) {
	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	for envelope := range queue {
		payload, err := json.Marshal(envelope)
		if err != nil {
			log.Printf("[!] Worker %d: marshal error: %v", id, err)
			continue
		}

		resp, err := client.Post(
			PythonEngineURL,
			"application/json",
			bytes.NewBuffer(payload),
		)
		if err != nil {
			// Ingest endpoint not ready yet — fail silently
			continue
		}
		resp.Body.Close()
	}
}
