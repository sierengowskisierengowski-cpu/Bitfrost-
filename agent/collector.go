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
	WorkerCount = 4
	QueueSize   = 5000
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

	socketPath := unixSocketPath()
	ingestURL := pythonEngineURL()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signalChan
		log.Println("[!] Collector shutting down. Cleaning socket...")
		_ = os.Remove(socketPath)
		os.Exit(0)
	}()

	_ = os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("[!] Cannot bind Unix socket %s: %v", socketPath, err)
	}
	defer listener.Close()
	_ = os.Chmod(socketPath, 0666)

	log.Printf("[+] Collector listening on %s", socketPath)
	log.Printf("[+] Forwarding to %s", ingestURL)

	queue := make(chan TelemetryEnvelope, QueueSize)

	for w := 1; w <= WorkerCount; w++ {
		go dispatchWorker(queue, w, ingestURL)
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

func dispatchWorker(queue <-chan TelemetryEnvelope, id int, ingestURL string) {
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
			ingestURL,
			"application/json",
			bytes.NewBuffer(payload),
		)
		if err != nil {
			log.Printf("[!] Worker %d: ingest POST failed: %v", id, err)
			continue
		}
		resp.Body.Close()
	}
}
