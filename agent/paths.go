package main

import (
	"os"
	"strings"
)

func envOrDefault(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}

func quarantineZone() string {
	if value := envOrDefault("BIFROST_QUARANTINE_PATH", "HEIMDALL_QUARANTINE_PATH"); value != "" {
		return value
	}
	return "/var/lib/heimdall/quarantine/"
}

func executorDBPath() string {
	if value := envOrDefault("BIFROST_DB_PATH", "HEIMDALL_DB_PATH"); value != "" {
		return value
	}
	return "/var/lib/heimdall/events.db"
}

func unixSocketPath() string {
	if value := envOrDefault("BIFROST_UNIX_SOCKET", "HEIMDALL_UNIX_SOCKET"); value != "" {
		return value
	}
	return "/var/run/bifrost_telemetry.sock"
}

func pythonEngineURL() string {
	if value := envOrDefault("BIFROST_INGEST_URL", "HEIMDALL_INGEST_URL"); value != "" {
		return value
	}
	return "http://127.0.0.1:8765/ingest"
}

func executorPort() string {
	if value := envOrDefault("BIFROST_EXECUTOR_PORT", "HEIMDALL_EXECUTOR_PORT"); value != "" {
		return value
	}
	return "8766"
}
