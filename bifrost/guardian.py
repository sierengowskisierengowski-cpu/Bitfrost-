#!/usr/bin/env python3
"""
Heimdall Guardian v0.1.1
Bifrost Security Platform

Hardened version. Addresses critical issues:
- Queue overflow with drop metrics
- Broad except removed
- LLM schema validation
- Model inference timeouts
- Graceful shutdown with queue drain
- SQLite WAL mode
- CIDR subnet matching
- Bounded retry on queue full
"""

import argparse
import os
import sys
import json
import time
import signal
import logging
import sqlite3
import threading
import ipaddress
from pathlib import Path
from datetime import datetime, timezone
from queue import Queue, Empty

from bifrost.event_queue import METRICS, METRICS_LOCK, safe_enqueue
from bifrost.inference import (
    CircuitBreaker,
    execute_with_retry,
    get_client_timeout,
    get_request_timeout,
)
from bifrost.ollama_client import ollama_chat, parse_json_object, truncate_for_log
from bifrost import paths as bifrost_paths
from bifrost.resilience import (
    configure_sqlite_connection,
    execute_with_db_retry,
    validate_event_envelope,
    verify_config_integrity,
    verify_database_integrity,
)
from logging.handlers import RotatingFileHandler

from bifrost.db_maintenance import WALCheckpointThread
from bifrost.live_monitor import LiveMonitor, apply_monitoring_defaults
from bifrost.mitre import enrich_decision
from bifrost.security import (
    TELEMETRY_TRUST_PREAMBLE,
    get_required_token,
    is_production_mode,
    redact_for_storage,
    safe_json_dumps,
    sanitize_telemetry_for_llm,
)

BIFROST_VERSION = "0.3.0"

VM_TEST_PROFILE_DEFAULTS = {
    "local_url": "http://127.0.0.1:11434/v1",
    "llm_timeout_seconds": 120.0,
    "llm_connect_timeout_seconds": 10.0,
    "llm_read_timeout_seconds": 120.0,
    "llm_num_ctx": 1024,
    "llm_num_predict": 64,
    "llm_num_gpu": 0,
    "llm_temperature": 0.0,
    "ollama_num_parallel": 1,
    "test_mode_enabled": True,
}

SUPPORTED_COWRIE_EVENTS = frozenset({
    "cowrie.command.input",
    "cowrie.login.success",
    "cowrie.session.connect",
    "cowrie.session.file_download",
    "cowrie.login.failed",
    "cowrie.direct-tcpip.request",
})

DESTRUCTIVE_ACTIONS = frozenset({"KILL", "BLOCK", "QUARANTINE"})

HONEYPOT_BREAKOUT_ALERTS = frozenset({
    "honeypot_to_host_connection",
    "container_escape_detected",
})


def _cowrie_event_id(raw: object) -> str | None:
    if not isinstance(raw, dict):
        return None
    event_id = raw.get("eventid") or raw.get("event_id")
    if event_id is None:
        return None
    return str(event_id)


def _is_honeypot_breakout(raw_data: object) -> bool:
    return (
        isinstance(raw_data, dict)
        and raw_data.get("alert") in HONEYPOT_BREAKOUT_ALERTS
    )


def should_route_to_reasoner(event: dict) -> bool:
    """
    Return True when an event should run through compress/reason/store.
    Cowrie honeypot noise is logged-only unless the event type is supported.
    """
    boundary = event.get("boundary", "UNKNOWN")
    raw_data = event.get("raw", {})

    if _is_honeypot_breakout(raw_data):
        return True
    if boundary != "HONEYPOT":
        return True

    eventid = _cowrie_event_id(raw_data)
    return eventid in SUPPORTED_COWRIE_EVENTS


def refresh_runtime_paths(config=None):
    """Resolve paths from env vars and optional config."""
    global CONFIG_PATH, DB_PATH, LOG_PATH
    CONFIG_PATH = bifrost_paths.config_path(config)
    DB_PATH = bifrost_paths.db_path(config)
    LOG_PATH = bifrost_paths.log_path(config)


refresh_runtime_paths()

EVENT_QUEUE = Queue(maxsize=10000)
SHUTDOWN = threading.Event()
COLLECTOR_STOP = threading.Event()

METRICS.setdefault("decisions_made", 0)
METRICS.setdefault("llm_errors", 0)
METRICS.setdefault("fallbacks", 0)
METRICS.setdefault("policy_blocks", 0)
METRICS.setdefault("actions_dispatched", 0)
METRICS.setdefault("invalid_events", 0)
METRICS.setdefault("config_integrity_failures", 0)
METRICS.setdefault("ollama_requests", 0)
METRICS.setdefault("ollama_failures", 0)
METRICS.setdefault("ollama_last_total_duration_ns", 0)
METRICS.setdefault("ollama_last_load_duration_ns", 0)

COMPRESSED_EVENT_NORMALIZE_DEPTH = 3
COMPRESSED_EVENT_BACKFILL_BATCH_SIZE = 500


def setup_logging():
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
    )
    file_handler = RotatingFileHandler(
        LOG_PATH,
        maxBytes=50 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)

    class _FailoverRotatingHandler(logging.Handler):
        """Rotate logs; fall back to stderr if disk is full."""

        def __init__(self, path):
            super().__init__()
            self._primary = file_handler
            self._fallback = logging.StreamHandler(sys.stderr)
            self._stderr_only = False

        def emit(self, record):
            target = self._fallback if self._stderr_only else self._primary
            try:
                target.emit(record)
            except Exception:
                self._stderr_only = True
                self._fallback.emit(record)

        def close(self):
            self._primary.close()
            self._fallback.close()
            super().close()

    root.handlers.clear()
    root.addHandler(_FailoverRotatingHandler(LOG_PATH))
    root.addHandler(stream_handler)
    return logging.getLogger("heimdall.guardian")


def load_config():
    log = logging.getLogger("heimdall.guardian")
    production_mode = (
        os.getenv("HEIMDALL_ENV", "production").strip().lower() == "production"
    )

    def _parse_bool_env(*names):
        for name in names:
            raw = os.getenv(name)
            if raw is None:
                continue
            value = raw.strip().lower()
            if value in {"1", "true", "yes", "on"}:
                return True
            if value in {"0", "false", "no", "off"}:
                return False
        return None

    def _parse_number_env(*names, cast=float):
        for name in names:
            raw = os.getenv(name)
            if raw is None:
                continue
            try:
                return cast(raw.strip())
            except (TypeError, ValueError):
                continue
        return None

    def _normalize_local_url(value):
        url = str(value or "").strip()
        if not url:
            return url
        if url.endswith("/"):
            url = url[:-1]
        if not url.endswith("/v1"):
            url = f"{url}/v1"
        return url

    def _resolve_testing_mode(base_config):
        env_mode = _parse_bool_env(
            "HEIMDALL_TEST_MODE_ENABLED",
            "BIFROST_TEST_MODE_ENABLED",
        )
        if env_mode is not None:
            return env_mode
        return bool(base_config.get("test_mode_enabled", False))

    def _resolve_profile_name(base_config):
        for env_name in (
            "HEIMDALL_CONFIG_PROFILE",
            "BIFROST_CONFIG_PROFILE",
            "HEIMDALL_TEST_PROFILE",
            "BIFROST_TEST_PROFILE",
        ):
            profile = os.getenv(env_name, "").strip()
            if profile:
                return profile.lower()
        profile = str(base_config.get("config_profile") or "").strip().lower()
        return profile

    def _apply_vm_profile(base_config):
        merged = dict(base_config)
        vm_profile = dict(VM_TEST_PROFILE_DEFAULTS)
        vm_profile.update(base_config.get("vm_test_profile", {}))
        merged.update(vm_profile)
        merged["local_url"] = _normalize_local_url(merged.get("local_url"))
        return merged

    def _apply_env_overrides(base_config):
        merged = dict(base_config)
        ollama_host = os.getenv("OLLAMA_HOST", "").strip()
        if ollama_host:
            merged["local_url"] = _normalize_local_url(ollama_host)

        local_url = os.getenv("HEIMDALL_LOCAL_URL", "").strip() or os.getenv(
            "BIFROST_LOCAL_URL", ""
        ).strip()
        if local_url:
            merged["local_url"] = _normalize_local_url(local_url)

        timeout_val = _parse_number_env(
            "HEIMDALL_LLM_TIMEOUT_SECONDS",
            "BIFROST_LLM_TIMEOUT_SECONDS",
            cast=float,
        )
        if timeout_val is not None:
            merged["llm_timeout_seconds"] = float(timeout_val)

        connect_val = _parse_number_env(
            "HEIMDALL_LLM_CONNECT_TIMEOUT_SECONDS",
            "BIFROST_LLM_CONNECT_TIMEOUT_SECONDS",
            cast=float,
        )
        if connect_val is not None:
            merged["llm_connect_timeout_seconds"] = float(connect_val)

        read_val = _parse_number_env(
            "HEIMDALL_LLM_READ_TIMEOUT_SECONDS",
            "BIFROST_LLM_READ_TIMEOUT_SECONDS",
            cast=float,
        )
        if read_val is not None:
            merged["llm_read_timeout_seconds"] = float(read_val)

        num_ctx_val = _parse_number_env(
            "HEIMDALL_LLM_NUM_CTX",
            "BIFROST_LLM_NUM_CTX",
            cast=int,
        )
        if num_ctx_val is not None:
            merged["llm_num_ctx"] = int(num_ctx_val)

        num_predict_val = _parse_number_env(
            "HEIMDALL_LLM_NUM_PREDICT",
            "BIFROST_LLM_NUM_PREDICT",
            cast=int,
        )
        if num_predict_val is not None:
            merged["llm_num_predict"] = int(num_predict_val)

        num_gpu_val = _parse_number_env(
            "HEIMDALL_LLM_NUM_GPU",
            "BIFROST_LLM_NUM_GPU",
            cast=int,
        )
        if num_gpu_val is not None:
            merged["llm_num_gpu"] = int(num_gpu_val)

        temp_val = _parse_number_env(
            "HEIMDALL_LLM_TEMPERATURE",
            "BIFROST_LLM_TEMPERATURE",
            cast=float,
        )
        if temp_val is not None:
            merged["llm_temperature"] = float(temp_val)

        parallel_val = _parse_number_env(
            "OLLAMA_NUM_PARALLEL",
            "HEIMDALL_OLLAMA_NUM_PARALLEL",
            "BIFROST_OLLAMA_NUM_PARALLEL",
            cast=int,
        )
        if parallel_val is not None:
            merged["ollama_num_parallel"] = int(parallel_val)

        test_mode_val = _parse_bool_env(
            "HEIMDALL_TEST_MODE_ENABLED",
            "BIFROST_TEST_MODE_ENABLED",
        )
        if test_mode_val is not None:
            merged["test_mode_enabled"] = test_mode_val

        if merged.get("local_url"):
            merged["local_url"] = _normalize_local_url(merged.get("local_url"))
        return merged

    def _finalize_config(base_config):
        merged = dict(base_config)
        testing_mode = _resolve_testing_mode(merged)
        profile_name = _resolve_profile_name(merged)
        if testing_mode:
            merged["test_mode_enabled"] = True
        if testing_mode or profile_name in {"vm", "vm-test", "vm_test"}:
            merged = _apply_vm_profile(merged)
            merged["config_profile"] = "vm-test"
        merged = _apply_env_overrides(merged)
        merged.setdefault("llm_num_ctx", 1024)
        merged.setdefault("llm_num_predict", 64)
        merged.setdefault("llm_num_gpu", 0)
        merged.setdefault("llm_temperature", 0.0)
        return merged

    if not CONFIG_PATH.exists():
        print("[!] heimdall_config.json not found.")
        print("[!] Run python setup.py first.")
        sys.exit(1)

    with open(CONFIG_PATH) as f:
        config = json.load(f)

    checksum_path = CONFIG_PATH.with_suffix(".sha256")
    if not checksum_path.exists():
        if production_mode:
            log.critical("CRITICAL: Config checksum file missing: %s", checksum_path)
            log.critical(
                "Refusing startup in production mode without config integrity verification."
            )
            sys.exit(1)
        log.warning(
            "Config checksum file missing; skipping integrity verification "
            "in non-production mode."
        )
        return _finalize_config(config)

    import hashlib
    actual = hashlib.sha256(CONFIG_PATH.read_bytes()).hexdigest()
    expected = checksum_path.read_text().strip()
    if actual != expected:
        log.critical("CRITICAL: Config checksum mismatch.")
        log.critical("heimdall_config.json may have been tampered with.")
        sys.exit(1)
    log.info("Config integrity verified.")

    return _finalize_config(config)


def init_database():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    configure_sqlite_connection(conn)
    cursor = conn.cursor()

    ok, detail = verify_database_integrity(conn)
    if not ok:
        conn.close()
        log = logging.getLogger("heimdall.guardian")
        log.critical("Database integrity check failed: %s", detail)
        log.critical("Refusing startup with corrupted database at %s", DB_PATH)
        sys.exit(1)

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            boundary TEXT NOT NULL,
            raw_event TEXT NOT NULL,
            compressed_event TEXT,
            heimdall_decision TEXT,
            action_taken TEXT,
            false_positive INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER REFERENCES events(id),
            action_type TEXT NOT NULL,
            target TEXT,
            session_id TEXT,
            ssh_fingerprint TEXT,
            command_hash TEXT,
            executed_at TEXT NOT NULL,
            success INTEGER DEFAULT 0,
            rollback_data TEXT,
            rolled_back INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS false_positives (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_class TEXT NOT NULL,
            boundary TEXT,
            pattern TEXT,
            marked_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS baseline (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            metric TEXT NOT NULL,
            value TEXT NOT NULL,
            recorded_at TEXT DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_events_timestamp
            ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_boundary
            ON events(boundary);
        CREATE INDEX IF NOT EXISTS idx_actions_event_id
            ON actions(event_id);
    """)

    _ensure_actions_columns(conn)
    _ensure_action_indexes(conn)
    _normalize_compressed_event_rows(conn)

    conn.commit()
    conn.close()
    return str(DB_PATH)


def _ensure_actions_columns(conn: sqlite3.Connection) -> None:
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(actions)")
    columns = {row[1] for row in cursor.fetchall()}
    if "session_id" not in columns:
        cursor.execute("ALTER TABLE actions ADD COLUMN session_id TEXT")
    if "ssh_fingerprint" not in columns:
        cursor.execute("ALTER TABLE actions ADD COLUMN ssh_fingerprint TEXT")
    if "command_hash" not in columns:
        cursor.execute("ALTER TABLE actions ADD COLUMN command_hash TEXT")
    conn.commit()


def _ensure_action_indexes(conn: sqlite3.Connection) -> None:
    cursor = conn.cursor()
    cursor.executescript("""
        CREATE INDEX IF NOT EXISTS idx_actions_session
            ON actions(session_id, executed_at);
        CREATE INDEX IF NOT EXISTS idx_actions_fingerprint
            ON actions(ssh_fingerprint, executed_at);
        CREATE INDEX IF NOT EXISTS idx_actions_behavioral_seq
            ON actions(command_hash, executed_at);
    """)


def _normalize_compressed_event(value):
    if value is None:
        return None

    if not isinstance(value, str):
        return json.dumps(value)

    normalized = value
    for _ in range(COMPRESSED_EVENT_NORMALIZE_DEPTH):
        try:
            decoded = json.loads(normalized)
        except json.JSONDecodeError:
            return normalized

        if isinstance(decoded, str):
            stripped = decoded.strip()
            if stripped.startswith("{") or stripped.startswith("["):
                normalized = stripped
                continue
            return normalized

        if isinstance(decoded, (dict, list)):
            return json.dumps(decoded)

        return normalized

    return normalized


def _normalize_compressed_event_rows(conn):
    read_cursor = conn.cursor()
    read_cursor.execute("""
        SELECT id, compressed_event
        FROM events
        WHERE compressed_event IS NOT NULL
    """)
    update_cursor = conn.cursor()

    while True:
        rows = read_cursor.fetchmany(COMPRESSED_EVENT_BACKFILL_BATCH_SIZE)
        if not rows:
            return

        updates = []
        for event_id, compressed_event in rows:
            normalized = _normalize_compressed_event(compressed_event)
            if normalized != compressed_event:
                updates.append((normalized, event_id))

        if updates:
            update_cursor.executemany("""
                UPDATE events
                SET compressed_event = ?
                WHERE id = ?
            """, updates)


class AuditdCollector(threading.Thread):
    AUDIT_LOG = Path("/var/log/audit/audit.log")
    RETRY_INTERVAL = 0.5

    def __init__(self, queue, log):
        super().__init__(daemon=True, name="collector.auditd")
        self.queue = queue
        self.log = log

    def run(self):
        self.log.info("AuditdCollector started.")
        warned_missing = False

        while not COLLECTOR_STOP.is_set():
            if not self.AUDIT_LOG.exists():
                if not warned_missing:
                    self.log.warning("auditd log not found. Is auditd running?")
                    warned_missing = True
                if COLLECTOR_STOP.wait(self.RETRY_INTERVAL):
                    break
                continue

            warned_missing = False
            try:
                with open(self.AUDIT_LOG, "r") as f:
                    f.seek(0, 2)
                    inode = os.fstat(f.fileno()).st_ino

                    while not COLLECTOR_STOP.is_set():
                        try:
                            current_inode = os.stat(self.AUDIT_LOG).st_ino
                            if current_inode != inode:
                                self.log.info("auditd log rotated. Reopening.")
                                break
                        except OSError:
                            self.log.info("auditd log unavailable. Reopening.")
                            break

                        line = f.readline()
                        if not line:
                            if COLLECTOR_STOP.wait(0.1):
                                break
                            continue

                        if any(key in line for key in [
                            "execve", "EXECVE", "USER_AUTH",
                            "USER_LOGIN", "SYSCALL", "key=exec"
                        ]):
                            event = {
                                "source": "auditd",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "boundary": "HOST",
                                "raw": line.strip()
                            }
                            safe_enqueue(self.queue, event, "auditd", self.log)
            except OSError as e:
                if COLLECTOR_STOP.is_set():
                    break
                self.log.error(f"AuditdCollector file error: {e}")
                if COLLECTOR_STOP.wait(self.RETRY_INTERVAL):
                    break
            except Exception as e:
                self.log.error(f"AuditdCollector unexpected error: {e}")
                break


class HoneypotLogCollector(threading.Thread):
    RETRY_INTERVAL = 0.5

    def __init__(self, queue, log, cowrie_log=None):
        super().__init__(daemon=True, name="collector.cowrie")
        self.queue = queue
        self.log = log
        self.cowrie_log = cowrie_log or bifrost_paths.cowrie_log_path()

    def run(self):
        self.log.info("HoneypotLogCollector started.")
        warned_missing = False

        while not COLLECTOR_STOP.is_set():
            if not self.cowrie_log.exists():
                if not warned_missing:
                    self.log.warning(
                        "Cowrie log not found at %s. Retrying.", self.cowrie_log
                    )
                    warned_missing = True
                if COLLECTOR_STOP.wait(self.RETRY_INTERVAL):
                    break
                continue

            warned_missing = False
            try:
                with open(self.cowrie_log, "r") as f:
                    f.seek(0, 2)
                    inode = os.fstat(f.fileno()).st_ino

                    while not COLLECTOR_STOP.is_set():
                        try:
                            if not self.cowrie_log.exists():
                                self.log.info(
                                    "Cowrie log deleted. Reopening when available."
                                )
                                break
                            current_inode = os.stat(self.cowrie_log).st_ino
                            if current_inode != inode:
                                self.log.info("Cowrie log rotated. Reopening.")
                                break
                        except OSError:
                            self.log.info("Cowrie log unavailable. Reopening.")
                            break

                        line = f.readline()
                        if not line:
                            if COLLECTOR_STOP.wait(0.1):
                                break
                            continue

                        try:
                            entry = json.loads(line.strip())
                            event = {
                                "source": "cowrie",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "boundary": "HONEYPOT",
                                "raw": entry,
                            }
                            safe_enqueue(self.queue, event, "cowrie", self.log)
                        except json.JSONDecodeError as e:
                            self.log.warning(f"Cowrie JSON parse error: {e}")
            except OSError as e:
                if COLLECTOR_STOP.is_set():
                    break
                self.log.error(f"HoneypotLogCollector file error: {e}")
                if COLLECTOR_STOP.wait(self.RETRY_INTERVAL):
                    break
            except Exception as e:
                self.log.error(f"HoneypotLogCollector unexpected error: {e}")
                if COLLECTOR_STOP.wait(self.RETRY_INTERVAL):
                    break


class ProcessWatcher(threading.Thread):
    POLL_INTERVAL = 2.0
    SUSPICIOUS_PATHS = ["/tmp/", "/dev/shm/", "/var/tmp/"]
    KERNEL_THREAD_PATTERN = ["kworker", "kthread", "ksoftirqd"]

    def __init__(self, queue, log):
        super().__init__(daemon=True, name="collector.process")
        self.queue = queue
        self.log = log
        self.seen_pids = set()

    def run(self):
        self.log.info("ProcessWatcher started.")
        while not COLLECTOR_STOP.is_set():
            try:
                for pid_dir in Path("/proc").glob("[0-9]*"):
                    try:
                        pid = int(pid_dir.name)
                    except ValueError:
                        continue

                    if pid in self.seen_pids:
                        continue

                    cmdline_path = pid_dir / "cmdline"
                    exe_path = pid_dir / "exe"

                    if not cmdline_path.exists():
                        continue

                    try:
                        cmdline = cmdline_path.read_text().replace(
                            "\x00", " ").strip()
                        try:
                            resolved_exe = str(exe_path.readlink())
                        except OSError:
                            resolved_exe = ""

                        is_suspicious_path = any(
                            p in resolved_exe for p in self.SUSPICIOUS_PATHS
                        )
                        is_hidden_masquerade = (
                            any(p in cmdline
                                for p in self.KERNEL_THREAD_PATTERN)
                            and not resolved_exe.startswith("/kernel")
                            and resolved_exe != ""
                        )

                        if is_suspicious_path or is_hidden_masquerade:
                            event = {
                                "source": "process.watcher",
                                "timestamp": datetime.now(
                                    timezone.utc).isoformat(),
                                "boundary": "HOST",
                                "raw": {
                                    "pid": pid,
                                    "cmdline": cmdline,
                                    "exe": resolved_exe,
                                    "indicators": {
                                        "scratch_space_exec": is_suspicious_path,
                                        "kernel_masquerade": is_hidden_masquerade
                                    }
                                }
                            }
                            safe_enqueue(
                                self.queue, event, "process.watcher", self.log
                            )

                        self.seen_pids.add(pid)

                    except PermissionError:
                        continue
                    except FileNotFoundError:
                        continue
                    except OSError as e:
                        self.log.warning(f"ProcessWatcher OSError pid={pid}: {e}")
                        continue

                try:
                    current_pids = {
                        int(p.name)
                        for p in Path("/proc").glob("[0-9]*")
                        if p.name.isdigit()
                    }
                    self.seen_pids &= current_pids
                except OSError as e:
                    self.log.warning(f"ProcessWatcher PID scan error: {e}")

                COLLECTOR_STOP.wait(self.POLL_INTERVAL)

            except Exception as e:
                self.log.error(f"ProcessWatcher loop error: {e}")
                time.sleep(1)


class NetworkWatcher(threading.Thread):
    POLL_INTERVAL = 3.0
    HOST_NET = ipaddress.ip_network("192.168.0.0/24")
    HONEYPOT_PORTS = {2222, 23, 445, 1433, 21, 25, 8888, 3389, 5900}

    def __init__(self, queue, log):
        super().__init__(daemon=True, name="collector.network")
        self.queue = queue
        self.log = log
        self.seen_connections = set()

    def run(self):
        self.log.info("NetworkWatcher started.")
        while not COLLECTOR_STOP.is_set():
            try:
                self.scan_connections()
            except Exception as e:
                self.log.error(f"NetworkWatcher scan error: {e}")
            COLLECTOR_STOP.wait(self.POLL_INTERVAL)

    def hex_to_ip(self, hex_ip: str) -> str:
        try:
            addr = int(hex_ip, 16)
            return (f"{addr & 0xFF}.{(addr >> 8) & 0xFF}."
                    f"{(addr >> 16) & 0xFF}.{(addr >> 24) & 0xFF}")
        except Exception:
            return "0.0.0.0"

    def is_host_subnet(self, ip_str: str) -> bool:
        try:
            return ipaddress.ip_address(ip_str) in self.HOST_NET
        except ValueError:
            return False

    def scan_connections(self):
        # Only scan tcp — skip tcp6 until properly implemented
        tcp_file = Path("/proc/net/tcp")
        if not tcp_file.exists():
            return
        try:
            lines = tcp_file.read_text().splitlines()[1:]
            for line in lines:
                parts = line.split()
                if len(parts) < 4:
                    continue
                if parts[3] != "01":
                    continue
                local = parts[1]
                remote = parts[2]
                try:
                    local_ip = self.hex_to_ip(local.split(":")[0])
                    remote_ip = self.hex_to_ip(remote.split(":")[0])
                    local_port = int(local.split(":")[1], 16)
                except (ValueError, IndexError):
                    continue

                conn_key = f"{local_ip}:{local_port}-{remote_ip}"
                if conn_key in self.seen_connections:
                    continue
                self.seen_connections.add(conn_key)

                if (local_port in self.HONEYPOT_PORTS and
                        self.is_host_subnet(remote_ip)):
                    event = {
                        "source": "network_watcher",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "boundary": "HOST",
                        "raw": {
                            "local_ip": local_ip,
                            "local_port": local_port,
                            "remote_ip": remote_ip,
                            "alert": "honeypot_to_host_connection"
                        }
                    }
                    safe_enqueue(
                        self.queue, event, "network_watcher", self.log
                    )
        except OSError as e:
            self.log.warning(f"NetworkWatcher read error: {e}")


class EventRouter(threading.Thread):

    def __init__(self, queue, config, db_path, log):
        super().__init__(daemon=True, name="bifrost.router")
        self.queue = queue
        self.config = apply_monitoring_defaults(config)
        self.db_path = db_path
        self.log = log
        self.event_count = 0
        self.conn = None
        self.db_healthy = True
        self.config_integrity_ok = True
        self.extractor_breaker = CircuitBreaker("guardian_extractor")
        self.analyst_breaker = CircuitBreaker("guardian_analyst")
        self._last_extractor_call_meta = {}
        self._last_analyst_call_meta = {}
        self.setup_inference_clients()
        self.setup_db()
        self.live_monitor = LiveMonitor(self.config, self.log, queue=self.queue)
        self.log.info(
            "Live monitor active: enabled=%s human=%s test_mode=%s structured=%s",
            self.live_monitor.enabled,
            self.live_monitor.human_live_enabled,
            self.live_monitor.test_mode_enabled,
            self.live_monitor.structured_log_path,
        )

    def setup_db(self):
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        configure_sqlite_connection(self.conn)
        ok, detail = verify_database_integrity(self.conn)
        if not ok:
            self.log.critical("Router DB integrity check failed: %s", detail)
            self.db_healthy = False

    def flush_db(self):
        if not self.conn:
            return
        try:
            self.conn.commit()
            self.conn.execute("PRAGMA wal_checkpoint(FULL)")
        except sqlite3.Error as e:
            self.log.warning(f"DB flush error during shutdown: {e}")

    def setup_inference_clients(self):
        try:
            if self.config.get("use_local_llm"):
                self.analyst_client = None
                self.analyst_model = self.config["analyst_model"]
                self.extractor_client = None
                self.extractor_model = self.config["extractor_model"]
            else:
                from openai import OpenAI
                timeout = get_client_timeout(self.config)
                api_key = os.getenv("HEIMDALL_API_KEY", "")
                self.analyst_client = OpenAI(
                    base_url=self.config.get("groq_url", ""),
                    api_key=api_key,
                    timeout=timeout,
                )
                self.analyst_model = self.config.get("groq_model", "")
                self.extractor_client = None
                self.extractor_model = None
        except Exception as e:
            self.log.error(f"Failed to setup inference clients: {e}")
            self.analyst_client = None
            self.extractor_client = None

    def _call_ollama_chat(self, model: str, messages: list[dict], *, temperature: float = 0.0):
        return ollama_chat(
            config=self.config,
            model=model,
            messages=messages,
            logger=self.log,
            temperature=temperature,
        )

    def _record_ollama_timing(self, response: dict) -> None:
        timings = response.get("timings", {})
        with METRICS_LOCK:
            METRICS["ollama_requests"] += 1
            METRICS["ollama_last_total_duration_ns"] = (
                timings.get("total_duration") or 0
            )
            METRICS["ollama_last_load_duration_ns"] = (
                timings.get("load_duration") or 0
            )

    def prewarm_ollama(self) -> None:
        if not self.config.get("use_local_llm"):
            return
        model = self.analyst_model or self.config.get("analyst_model")
        if not model:
            self.log.warning("Skipping Ollama prewarm: analyst model is not configured.")
            return
        try:
            response = self._call_ollama_chat(
                model,
                [{"role": "user", "content": "Reply with OK"}],
                temperature=0.0,
            )
            self._record_ollama_timing(response)
            self.log.info(
                "Ollama prewarm succeeded model=%s duration_ms=%s",
                model,
                response.get("duration_ms"),
            )
        except Exception as exc:
            with METRICS_LOCK:
                METRICS["ollama_failures"] += 1
            self.log.warning(
                "Ollama prewarm failed (non-fatal) model=%s error=%s",
                model,
                exc,
            )

    def compress_event(self, event: dict) -> str:
        extractor_model = str(self.extractor_model or "").strip()
        if self.config.get("use_local_llm") and not extractor_model:
            self._last_extractor_call_meta = {
                "provider": "guardian_extractor",
                "model": None,
                "latency_ms": 0.0,
                "timeout_seconds": float(get_request_timeout(self.config)),
                "retry_attempts": int(self.config.get("llm_retry_attempts", 2)),
                "success": False,
                "failure_reason": "no_extractor_model",
            }
            raw = safe_json_dumps(event.get("raw", {}))
            return sanitize_telemetry_for_llm(raw)[:500]

        if not self.config.get("use_local_llm") and not self.extractor_client:
            self._last_extractor_call_meta = {
                "provider": "guardian_extractor",
                "model": self.extractor_model,
                "latency_ms": 0.0,
                "timeout_seconds": float(get_request_timeout(self.config)),
                "retry_attempts": int(self.config.get("llm_retry_attempts", 2)),
                "success": False,
                "failure_reason": "no_extractor_client",
            }
            raw = safe_json_dumps(event.get("raw", {}))
            return sanitize_telemetry_for_llm(raw)[:500]

        try:
            start = time.monotonic()
            raw = sanitize_telemetry_for_llm(
                safe_json_dumps(event.get("raw", {}))
            )
            messages = [
                {
                    "role": "system",
                    "content": (
                        "You are a security event compressor. "
                        "Strip hex addresses and register states. "
                        "Return compact JSON only. No explanation."
                    ),
                },
                {"role": "user", "content": raw},
            ]
            if self.config.get("use_local_llm"):
                response, error = execute_with_retry(
                    lambda: self._call_ollama_chat(
                        extractor_model,
                        messages,
                        temperature=self.config.get("llm_temperature", 0.0),
                    ),
                    provider="guardian_extractor",
                    config=self.config,
                    logger=self.log,
                    circuit_breaker=self.extractor_breaker,
                )
            else:
                response, error = execute_with_retry(
                    lambda: self.extractor_client.chat.completions.create(
                        model=self.extractor_model,
                        temperature=0.0,
                        messages=messages,
                    ),
                    provider="guardian_extractor",
                    config=self.config,
                    logger=self.log,
                    circuit_breaker=self.extractor_breaker,
                )
            latency_ms = (time.monotonic() - start) * 1000.0
            if not response:
                reason = (
                    "extractor_circuit_open"
                    if error == "circuit_open"
                    else "extractor_error"
                )
                self._last_extractor_call_meta = {
                    "provider": "guardian_extractor",
                    "model": extractor_model or self.extractor_model,
                    "latency_ms": round(latency_ms, 2),
                    "timeout_seconds": float(get_request_timeout(self.config)),
                    "retry_attempts": int(self.config.get("llm_retry_attempts", 2)),
                    "success": False,
                    "failure_reason": reason,
                }
                self.log.warning("Extractor degraded mode: %s", reason)
                with METRICS_LOCK:
                    METRICS["llm_errors"] += 1
                    if self.config.get("use_local_llm"):
                        METRICS["ollama_failures"] += 1
                return sanitize_telemetry_for_llm(
                    safe_json_dumps(event.get("raw", {}))
                )[:500]

            if self.config.get("use_local_llm"):
                self._record_ollama_timing(response)
                content = response["content"]
            else:
                content = response.choices[0].message.content.strip()
            self._last_extractor_call_meta = {
                "provider": "guardian_extractor",
                "model": extractor_model or self.extractor_model,
                "latency_ms": round(latency_ms, 2),
                "timeout_seconds": float(get_request_timeout(self.config)),
                "retry_attempts": int(self.config.get("llm_retry_attempts", 2)),
                "success": True,
                "failure_reason": None,
            }
            if self.config.get("use_local_llm"):
                self._last_extractor_call_meta["ollama_timing"] = response.get("timings", {})
            return sanitize_telemetry_for_llm(
                content
            )
        except Exception as e:
            self._last_extractor_call_meta = {
                "provider": "guardian_extractor",
                "model": extractor_model or self.extractor_model,
                "latency_ms": 0.0,
                "timeout_seconds": float(get_request_timeout(self.config)),
                "retry_attempts": int(self.config.get("llm_retry_attempts", 2)),
                "success": False,
                "failure_reason": str(e),
            }
            self.log.warning(f"Extractor error: {e}. Using raw fallback.")
            with METRICS_LOCK:
                METRICS["llm_errors"] += 1
                if self.config.get("use_local_llm"):
                    METRICS["ollama_failures"] += 1
            return sanitize_telemetry_for_llm(
                safe_json_dumps(event.get("raw", {}))
            )[:500]

    def route_to_heimdall(self, compressed: str) -> dict:
        analyst_model = str(self.analyst_model or "").strip()
        if self.config.get("use_local_llm") and not analyst_model:
            self._last_analyst_call_meta = {
                "provider": "guardian_analyst",
                "model": None,
                "latency_ms": 0.0,
                "timeout_seconds": float(get_request_timeout(self.config)),
                "retry_attempts": int(self.config.get("llm_retry_attempts", 2)),
                "success": False,
                "failure_reason": "no_analyst_model",
            }
            return self._safe_fallback("no_analyst_model")

        if not self.config.get("use_local_llm") and not self.analyst_client:
            self._last_analyst_call_meta = {
                "provider": "guardian_analyst",
                "model": self.analyst_model,
                "latency_ms": 0.0,
                "timeout_seconds": float(get_request_timeout(self.config)),
                "retry_attempts": int(self.config.get("llm_retry_attempts", 2)),
                "success": False,
                "failure_reason": "no_analyst_client",
            }
            return self._safe_fallback("no_analyst_client")

        try:
            baseline = TELEMETRY_TRUST_PREAMBLE + self.config.get(
                "system_baseline", ""
            )
            sanitized = sanitize_telemetry_for_llm(compressed)
            start = time.monotonic()
            messages = [
                {"role": "system", "content": baseline},
                {
                    "role": "user",
                    "content": (
                        "Analyze this security event as JSON:\n"
                        f"{sanitized}"
                    ),
                },
            ]
            if self.config.get("use_local_llm"):
                response, error = execute_with_retry(
                    lambda: self._call_ollama_chat(
                        analyst_model,
                        messages,
                        temperature=self.config.get("llm_temperature", 0.0),
                    ),
                    provider="guardian_analyst",
                    config=self.config,
                    logger=self.log,
                    circuit_breaker=self.analyst_breaker,
                )
            else:
                response, error = execute_with_retry(
                    lambda: self.analyst_client.chat.completions.create(
                        model=self.analyst_model,
                        temperature=0.0,
                        messages=messages,
                    ),
                    provider="guardian_analyst",
                    config=self.config,
                    logger=self.log,
                    circuit_breaker=self.analyst_breaker,
                )
            latency_ms = (time.monotonic() - start) * 1000.0
            if not response:
                self._last_analyst_call_meta = {
                    "provider": "guardian_analyst",
                    "model": self.analyst_model,
                    "latency_ms": round(latency_ms, 2),
                    "timeout_seconds": float(get_request_timeout(self.config)),
                    "retry_attempts": int(self.config.get("llm_retry_attempts", 2)),
                    "success": False,
                    "failure_reason": error or "llm_error",
                }
                with METRICS_LOCK:
                    METRICS["llm_errors"] += 1
                    if self.config.get("use_local_llm"):
                        METRICS["ollama_failures"] += 1
                if error == "circuit_open":
                    return self._safe_fallback("analyst_circuit_open")
                return self._safe_fallback("llm_error")

            if self.config.get("use_local_llm"):
                self._record_ollama_timing(response)
                raw_decision = response["content"]
            else:
                raw_decision = response.choices[0].message.content.strip()

            decision = parse_json_object(raw_decision)
            if not decision:
                self.log.warning(
                    "LLM decision parse failed model=%s preview=%s",
                    self.analyst_model,
                    truncate_for_log(raw_decision),
                )
                return self._safe_fallback("json_decode_error")

            required = [
                "severity", "action_required", "confidence", "reasoning",
                "incident_detected", "boundary", "threat_class",
            ]
            for field in required:
                if field not in decision:
                    self.log.warning(
                        "LLM decision missing field: %s. Using fallback.", field
                    )
                    return self._safe_fallback(f"missing_field_{field}")

            try:
                from heimdall.schema import validate_decision_dict
                validated = validate_decision_dict(decision)
                decision = validated.to_dict()
            except Exception as schema_err:
                self.log.warning(
                    "LLM decision schema validation failed: %s", schema_err
                )
                return self._safe_fallback("schema_validation_error")

            with METRICS_LOCK:
                METRICS["decisions_made"] += 1
            self._last_analyst_call_meta = {
                "provider": "guardian_analyst",
                "model": self.analyst_model,
                "latency_ms": round(latency_ms, 2),
                "timeout_seconds": float(get_request_timeout(self.config)),
                "retry_attempts": int(self.config.get("llm_retry_attempts", 2)),
                "success": True,
                "failure_reason": None,
            }
            if self.config.get("use_local_llm"):
                self._last_analyst_call_meta["ollama_timing"] = response.get("timings", {})

            return decision

        except json.JSONDecodeError as e:
            self._last_analyst_call_meta = {
                "provider": "guardian_analyst",
                "model": self.analyst_model,
                "latency_ms": 0.0,
                "timeout_seconds": float(get_request_timeout(self.config)),
                "retry_attempts": int(self.config.get("llm_retry_attempts", 2)),
                "success": False,
                "failure_reason": "json_decode_error",
            }
            self.log.error(f"LLM returned invalid JSON: {e}")
            with METRICS_LOCK:
                METRICS["llm_errors"] += 1
                if self.config.get("use_local_llm"):
                    METRICS["ollama_failures"] += 1
            return self._safe_fallback("json_decode_error")
        except Exception as e:
            self._last_analyst_call_meta = {
                "provider": "guardian_analyst",
                "model": self.analyst_model,
                "latency_ms": 0.0,
                "timeout_seconds": float(get_request_timeout(self.config)),
                "retry_attempts": int(self.config.get("llm_retry_attempts", 2)),
                "success": False,
                "failure_reason": str(e),
            }
            self.log.error(f"Heimdall reasoning error: {e}")
            with METRICS_LOCK:
                METRICS["llm_errors"] += 1
                if self.config.get("use_local_llm"):
                    METRICS["ollama_failures"] += 1
            return self._safe_fallback("llm_error")

    def _safe_fallback(self, reason: str) -> dict:
        with METRICS_LOCK:
            METRICS["fallbacks"] += 1
        return enrich_decision({
            "schema_version": "0.1.0",
            "incident_detected": False,
            "severity": "LOW",
            "boundary": "UNKNOWN",
            "threat_class": "parser_error",
            "confidence": 0.0,
            "action_required": "LOG",
            "target": None,
            "gjallarhorn_tier": 1,
            "reasoning": f"Safe fallback: {reason}",
            "extractor_model": "unknown",
            "reasoner_model": "safe_fallback",
            "hardware_tier": self.config.get("hardware_tier", "TIER_4")
        })

    def check_executor_integrity(self) -> bool:
        """
        Fail closed for destructive executor dispatch only.
        Never marks the DB unhealthy — reasoning and decision writes continue.
        """
        ok, reason = verify_config_integrity(CONFIG_PATH)
        if not ok:
            if self.config_integrity_ok:
                self.log.critical(
                    "Executor integrity: config check failed: %s. "
                    "Blocking destructive dispatch only.",
                    reason,
                )
                with METRICS_LOCK:
                    METRICS["config_integrity_failures"] += 1
            self.config_integrity_ok = False
            return False

        self.config_integrity_ok = True

        try:
            ok, detail = verify_database_integrity(self.conn)
            if not ok:
                self.log.warning(
                    "Executor integrity: database check failed: %s. "
                    "Blocking destructive dispatch only.",
                    detail,
                )
                return False
        except sqlite3.Error as exc:
            self.log.warning(
                "Executor integrity: database check error: %s. "
                "Blocking destructive dispatch only.",
                exc,
            )
            return False

        return True

    def check_runtime_integrity(self) -> bool:
        """Backward-compatible alias for executor-only integrity checks."""
        return self.check_executor_integrity()

    def _reason_event(self, event: dict, compressed: str) -> dict:
        """Run AI reasoning — never blocked by integrity checks."""
        try:
            decision = enrich_decision(self.route_to_heimdall(compressed))
            decision["model_calls"] = [
                self._last_extractor_call_meta,
                self._last_analyst_call_meta,
            ]
            return decision
        except Exception as exc:
            self.log.error("Reasoner failed: %s", exc, exc_info=True)
            fallback = self._safe_fallback(f"reasoner error: {exc}")
            fallback["model_calls"] = [
                self._last_extractor_call_meta,
                self._last_analyst_call_meta,
            ]
            return fallback

    def _dispatch_enforcement(self, decision: dict, event_id: int) -> str:
        """
        Dispatch destructive actions to the Go executor.
        Integrity checks apply ONLY here — never to reasoning or DB writes.
        """
        if event_id < 1:
            self.log.error(
                "Executor dispatch blocked: event not persisted (event_id=%s)",
                event_id,
            )
            return "event_not_persisted"

        effective = (
            decision.get("action_effective")
            or decision.get("action_required", "NONE")
        )
        if effective not in DESTRUCTIVE_ACTIONS:
            return "no_destructive_action"

        if not decision.get("policy_allowed"):
            return "blocked_by_policy"

        if not self.check_executor_integrity():
            self.log.error(
                "Executor dispatch blocked: runtime integrity check failed "
                "(event_id=%d) — downgrading to ALERT",
                event_id,
            )
            decision["action_effective"] = "ALERT"
            decision["action_required"] = "ALERT"
            decision["policy_allowed"] = False
            decision["policy_rationale"] = (
                "Downgraded: executor integrity check failed"
            )
            decision["execution_result"] = "integrity_check_failed"
            self.update_stored_decision(event_id, decision)
            return "integrity_check_failed"

        from bifrost.router import execute_decision

        dispatch_payload = dict(decision)
        dispatch_payload["action_required"] = effective

        if execute_decision(dispatch_payload, event_id, self.db_path, self.log):
            with METRICS_LOCK:
                METRICS["actions_dispatched"] += 1
            self.log.warning(
                "Executor dispatched: %s target=%s event_id=%d",
                effective,
                dispatch_payload.get("target"),
                event_id,
            )
            return "dispatch_success"

        self.log.error(
            "Executor dispatch failed: %s target=%s event_id=%d",
            effective,
            dispatch_payload.get("target"),
            event_id,
        )
        return "dispatch_failed"

    def apply_policy_gate(self, decision: dict, event: dict) -> dict:
        """Run destructive actions through the policy gate before dispatch."""
        from bifrost.policy import (
            Decision as PolicyDecision,
            ActionType as PolicyActionType,
            evaluate_policy,
            SAFE_DEFAULTS,
            DESTRUCTIVE,
        )

        decision = dict(decision)
        requested = decision.get("action_required", "NONE")
        decision["action_requested"] = requested

        try:
            action_type = PolicyActionType(requested)
        except ValueError:
            action_type = PolicyActionType.LOG
            requested = action_type.value

        if action_type not in DESTRUCTIVE:
            decision["action_effective"] = requested
            decision["policy_allowed"] = True
            return decision

        try:
            target = decision.get("target") or ""
            pid = None
            dest_ip = None
            process_name = None

            if isinstance(target, int):
                pid = target
            elif isinstance(target, str) and target:
                if target.isdigit():
                    pid = int(target)
                elif target.startswith("pid:"):
                    try:
                        pid = int(target.split(":")[1])
                    except (ValueError, IndexError) as err:
                        self.log.debug("Policy: unparsable pid target: %s", err)
                elif "/" not in target and "." in target:
                    dest_ip = target
                elif "/" in target:
                    process_name = Path(target).name

            raw = event.get("raw", {})
            if pid is None and isinstance(raw, dict) and raw.get("pid") is not None:
                try:
                    pid = int(raw["pid"])
                except (TypeError, ValueError) as err:
                    self.log.debug("Policy: unparsable raw pid: %s", err)

            learning_mode = self.config.get(
                "learning_mode", SAFE_DEFAULTS["learning_mode"]
            )
            dry_run = self.config.get("dry_run", SAFE_DEFAULTS["dry_run"])
            autonomous_enabled = self.config.get(
                "autonomous_actions_enabled",
                self.config.get(
                    "autonomous_enabled", SAFE_DEFAULTS["autonomous_enabled"]
                ),
            )

            result = evaluate_policy(
                PolicyDecision(
                    action=action_type,
                    confidence=float(decision.get("confidence", 0.0)),
                    reason=str(decision.get("reasoning", "")),
                    pid=pid,
                    process_name=process_name,
                    destination_ip=dest_ip,
                    is_system_process=False,
                    evidence_count=int(decision.get("evidence_count", 2) or 2),
                    event_window_seconds=int(
                        decision.get("event_window_seconds", 60)
                    ),
                ),
                learning_mode=learning_mode,
                dry_run=dry_run,
                autonomous_enabled=autonomous_enabled,
                confidence_threshold=float(
                    self.config.get(
                        "confidence_threshold",
                        SAFE_DEFAULTS["confidence_threshold"],
                    )
                ),
                min_repeated_evidence_for_destructive=int(
                    self.config.get(
                        "min_evidence_count",
                        SAFE_DEFAULTS["min_repeated_evidence_for_destructive"],
                    )
                ),
                never_block_rfc1918=self.config.get(
                    "never_block_rfc1918", SAFE_DEFAULTS["never_block_rfc1918"]
                ),
                protected_pids_max=int(
                    self.config.get(
                        "protected_pids_max", SAFE_DEFAULTS["protected_pids_max"]
                    )
                ),
            )
        except Exception as exc:
            self.log.error("Policy gate error: %s. Failing closed to ALERT.", exc)
            decision["action_effective"] = "ALERT"
            decision["policy_allowed"] = False
            decision["policy_rationale"] = f"Policy gate error: {exc}"
            with METRICS_LOCK:
                METRICS["policy_blocks"] += 1
            return decision

        decision["action_effective"] = result.downgraded_action.value
        decision["policy_allowed"] = result.allowed
        decision["policy_rationale"] = result.rationale

        if not result.allowed:
            with METRICS_LOCK:
                METRICS["policy_blocks"] += 1
            self.log.info(
                "Policy gate blocked %s -> %s: %s",
                requested,
                decision["action_effective"],
                result.rationale,
            )
        else:
            self.log.warning(
                "Policy gate ALLOWED: %s target=%s",
                decision["action_effective"],
                decision.get("target"),
            )

        return decision

    def maybe_dispatch_to_executor(self, decision: dict, event_id: int) -> str:
        """Deprecated alias — use _dispatch_enforcement."""
        return self._dispatch_enforcement(decision, event_id)

    def store_event(self, event: dict, compressed=None, decision=None) -> int:
        """Persist event and decision. Never blocked by executor integrity checks."""
        stored_event = redact_for_storage(event)
        boundary = stored_event.get("boundary", "UNKNOWN")
        source = stored_event.get("source", "unknown")
        raw = safe_json_dumps(stored_event.get("raw", {}))
        timestamp = stored_event.get(
            "timestamp", datetime.now(timezone.utc).isoformat()
        )
        action = None
        if decision:
            action = (
                decision.get("action_effective")
                or decision.get("action_required", "NONE")
            )

        params = (
            timestamp, source, boundary, raw,
            _normalize_compressed_event(compressed),
            json.dumps(decision) if decision else None,
            action,
        )

        def _insert(conn):
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO events
                (timestamp, source, boundary, raw_event,
                 compressed_event, heimdall_decision, action_taken)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, params)
            conn.commit()
            return cursor.lastrowid

        try:
            row_id, self.conn = execute_with_db_retry(
                self.conn,
                self.db_path,
                _insert,
                self.log,
            )
            return row_id
        except sqlite3.DatabaseError as exc:
            self.log.critical("DB store failed permanently: %s", exc)
            self.db_healthy = False
            return -1
        except sqlite3.Error as exc:
            self.log.error("DB store error: %s", exc)
            return -1

    def update_stored_decision(self, event_id: int, decision: dict) -> bool:
        """Update heimdall_decision and action_taken for an existing event row."""
        if event_id < 1:
            return False

        action = (
            decision.get("action_effective")
            or decision.get("action_required", "NONE")
        )
        params = (json.dumps(decision), action, event_id)

        def _update(conn):
            conn.execute(
                """
                UPDATE events
                SET heimdall_decision = ?, action_taken = ?
                WHERE id = ?
                """,
                params,
            )
            conn.commit()

        try:
            _, self.conn = execute_with_db_retry(
                self.conn,
                self.db_path,
                _update,
                self.log,
            )
            return True
        except sqlite3.Error as exc:
            self.log.error(
                "Failed to update decision for event_id=%s: %s",
                event_id,
                exc,
            )
            return False

    def run(self):
        self.log.info("EventRouter started. Bifrost pipeline active.")
        while not (SHUTDOWN.is_set() and self.queue.empty()):
            event = None
            try:
                event = self.queue.get(timeout=1.0)

                ok, err = validate_event_envelope(event)
                if not ok:
                    with METRICS_LOCK:
                        METRICS["invalid_events"] += 1
                    self.log.warning(
                        "Invalid event dropped: %s source=%s",
                        err,
                        event.get("source", "unknown"),
                    )
                    continue

                boundary = event.get("boundary", "UNKNOWN")
                source = event.get("source", "unknown")

                if not should_route_to_reasoner(event):
                    self.store_event(event)
                    self.live_monitor.record_event(event)
                    self.event_count += 1
                    continue

                self.log.info(
                    f"[{boundary}] [{source}] Routing to Heimdall."
                )

                self.live_monitor.record_pipeline_step(
                    event,
                    step="route_start",
                    status="ok",
                    details={"boundary": boundary, "source": source},
                )
                compressed = self.compress_event(event)
                self.live_monitor.record_pipeline_step(
                    event,
                    step="compress_event",
                    status="ok",
                    details={"model_call": self._last_extractor_call_meta},
                )

                # Step 1: ALWAYS run AI reasoning — never blocked by integrity
                decision = self._reason_event(event, compressed)
                self.live_monitor.record_pipeline_step(
                    event,
                    step="reason_decision",
                    status="ok",
                    details={"model_call": self._last_analyst_call_meta},
                )

                # Step 2: Policy gate (downgrades destructive actions when needed)
                decision = self.apply_policy_gate(decision, event)
                self.live_monitor.record_pipeline_step(
                    event,
                    step="policy_gate",
                    status="ok",
                    details={
                        "policy_allowed": decision.get("policy_allowed"),
                        "policy_rationale": decision.get("policy_rationale"),
                    },
                )

                # Step 3: ALWAYS write decision to SQLite — never blocked
                event_id = self.store_event(event, compressed, decision)
                self.live_monitor.record_pipeline_step(
                    event,
                    step="store_event",
                    status="ok" if event_id > 0 else "error",
                    details={"event_id": event_id},
                )
                if event_id < 1:
                    self.log.error(
                        "Critical: Failed to persist heimdall_decision for "
                        "source=%s boundary=%s",
                        source,
                        boundary,
                    )

                severity = decision.get("severity", "UNKNOWN")
                action = decision.get("action_requested", decision.get("action_required", "NONE"))
                effective = decision.get("action_effective", action)
                confidence = decision.get("confidence", 0.0)

                self.log.info(
                    f"Heimdall: action={action} effective={effective} "
                    f"severity={severity} confidence={confidence:.2f}"
                )

                if effective in ["KILL", "BLOCK", "QUARANTINE"]:
                    if decision.get("policy_allowed"):
                        self.log.warning(
                            f"[!!!] AUTONOMOUS ACTION: {effective} — "
                            f"{decision.get('reasoning', '')}"
                        )
                    else:
                        self.log.warning(
                            f"[!!!] ACTION BLOCKED BY POLICY: {action} — "
                            f"{decision.get('policy_rationale', '')}"
                        )

                execution_result = self._dispatch_enforcement(decision, event_id)
                decision["execution_result"] = execution_result
                self.live_monitor.record_pipeline_step(
                    event,
                    step="executor_dispatch",
                    status="ok" if execution_result != "dispatch_failed" else "error",
                    details={"execution_result": execution_result},
                )
                self.live_monitor.record_event(event, decision)

                tier = decision.get("gjallarhorn_tier", 1)
                self.log.info(f"Gjallarhorn Tier {tier} alert queued.")
                self.event_count += 1

                if self.event_count % 100 == 0:
                    with METRICS_LOCK:
                        self.log.info(
                            f"Bifrost metrics: {json.dumps(METRICS)}"
                        )

            except Empty:
                self.live_monitor.emit_due_summary()
                continue
            except Exception as e:
                self.log.error(f"EventRouter error: {e}", exc_info=True)
                with METRICS_LOCK:
                    METRICS.setdefault("pipeline_errors", 0)
                    METRICS["pipeline_errors"] += 1
            finally:
                if event is not None:
                    self.queue.task_done()

        self.flush_db()
        self.live_monitor.emit_due_summary(force=True)
        self.live_monitor.close()
        if self.conn:
            self.conn.close()


def drain_event_queue(queue: Queue, timeout: float, poll_interval: float = 0.1):
    """
    Wait for all queued tasks to be marked done before the timeout expires.
    Returns (drained, remaining_tasks).
    """
    deadline = time.monotonic() + timeout
    while True:
        remaining = queue.unfinished_tasks
        if remaining <= 0:
            return True, 0
        if time.monotonic() >= deadline:
            return False, remaining
        time.sleep(poll_interval)


def signal_handler(sig, frame):
    print("\n[*] Shutdown signal received. Draining queue...")
    COLLECTOR_STOP.set()


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Bifrost guardian runtime")
    parser.set_defaults(
        dashboard_enabled=None,
        live_monitor_enabled=None,
        human_live_enabled=None,
        test_mode_enabled=None,
    )
    parser.add_argument(
        "--dashboard",
        dest="dashboard_enabled",
        action="store_true",
        help="Enable the local read-only dashboard.",
    )
    parser.add_argument(
        "--no-dashboard",
        dest="dashboard_enabled",
        action="store_false",
        help="Disable the local read-only dashboard.",
    )
    parser.add_argument(
        "--dashboard-host",
        default=None,
        help="Bind address for the dashboard server.",
    )
    parser.add_argument(
        "--dashboard-port",
        type=int,
        default=None,
        help="Bind port for the dashboard server.",
    )
    parser.add_argument(
        "--human-live",
        dest="human_live_enabled",
        action="store_true",
        help="Enable the plain-English live incident feed.",
    )
    parser.add_argument(
        "--no-human-live",
        dest="human_live_enabled",
        action="store_false",
        help="Disable the plain-English live incident feed.",
    )
    parser.add_argument(
        "--test-mode",
        dest="test_mode_enabled",
        action="store_true",
        help="Enable test-mode summaries for controlled lab validation.",
    )
    parser.add_argument(
        "--summary-interval",
        type=int,
        default=None,
        help="Override the test-mode summary interval in seconds.",
    )
    parser.add_argument(
        "--live-monitor-json",
        default=None,
        help="Override the JSONL path for structured live monitor records.",
    )
    return parser.parse_args(argv)


def apply_cli_overrides(config, args):
    merged = apply_monitoring_defaults(config)
    if args.dashboard_enabled is not None:
        merged["dashboard_enabled"] = args.dashboard_enabled
    if args.dashboard_host:
        merged["dashboard_host"] = args.dashboard_host
    if args.dashboard_port is not None:
        merged["dashboard_port"] = args.dashboard_port
    if args.live_monitor_enabled is not None:
        merged["live_monitor_enabled"] = args.live_monitor_enabled
    if args.human_live_enabled is not None:
        merged["human_live_enabled"] = args.human_live_enabled
    if args.test_mode_enabled is not None:
        merged["test_mode_enabled"] = args.test_mode_enabled
    # --test-mode is the one-command entry point: auto-enable all live features
    if args.test_mode_enabled:
        merged.setdefault("dashboard_enabled", True)
        merged["dashboard_enabled"] = True
        merged["live_monitor_enabled"] = True
        merged["human_live_enabled"] = True
    if args.summary_interval is not None:
        merged["test_mode_summary_interval_seconds"] = max(args.summary_interval, 1)
    if args.live_monitor_json:
        merged["live_monitor_jsonl_path"] = args.live_monitor_json
    return merged


def _launch_desktop_window(url: str, log: logging.Logger) -> None:
    """Open the dashboard in a native pywebview desktop window (non-blocking)."""
    _STARTUP_DELAY = 0.5  # seconds — lets the HTTP server finish binding before loading

    def _run() -> None:
        try:
            import webview  # pywebview
        except ImportError:
            log.warning(
                "pywebview is not installed — desktop window unavailable. "
                "Dashboard is accessible at %s",
                url,
            )
            return
        try:
            time.sleep(_STARTUP_DELAY)
            _window = webview.create_window(
                "Bifrost \u2014 Heimdall Dashboard",
                url,
                width=1280,
                height=860,
                resizable=True,
            )
            webview.start()
        except Exception as exc:
            log.warning("Desktop window failed to open: %s", exc)

    t = threading.Thread(target=_run, name="BifrostWebview", daemon=True)
    t.start()


def main(argv=None):
    from bifrost.banner import print_startup_banner

    print_startup_banner(version=BIFROST_VERSION)

    args = parse_args(argv)
    log = setup_logging()
    log.info("=" * 60)
    log.info(f"Heimdall Guardian v{BIFROST_VERSION} starting.")
    log.info("=" * 60)
    sanitize_telemetry_for_llm("guardian_init")

    config = apply_cli_overrides(load_config(), args)
    refresh_runtime_paths(config)

    if is_production_mode() and not get_required_token("BIFROST_INGEST_TOKEN"):
        log.critical(
            "BIFROST_INGEST_TOKEN is required in production mode. "
            "Set it before starting guardian."
        )
        sys.exit(1)

    log.info(
        "Config: tier=%s analyst=%s extractor=%s learning_days=%s",
        config.get("hardware_tier", "UNKNOWN"),
        config.get("analyst_model") or "Cloud Routed",
        config.get("extractor_model") or "Rules Only",
        config.get("learning_period_days", 7),
    )

    db_path = init_database()
    log.info(f"Database initialized: {db_path}")

    wal_thread = WALCheckpointThread(db_path, SHUTDOWN)
    wal_thread.start()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    from bifrost.ingest import IngestServer

    ingest_token = os.getenv("BIFROST_INGEST_TOKEN", "").strip()
    ingest_server = IngestServer(EVENT_QUEUE, ingest_token=ingest_token)
    ingest_server.start()
    log.info("Ingest server started on http://127.0.0.1:8765/ingest")

    dashboard = None
    if config.get("dashboard_enabled"):
        from bifrost.dashboard import DashboardServer
        dashboard = DashboardServer(config, log, db_path=db_path)
        dashboard.start()
        _launch_desktop_window(dashboard.url, log)

    collectors = [
        AuditdCollector(EVENT_QUEUE, log),
        HoneypotLogCollector(
            EVENT_QUEUE,
            log,
            bifrost_paths.cowrie_log_path(config),
        ),
        ProcessWatcher(EVENT_QUEUE, log),
        NetworkWatcher(EVENT_QUEUE, log),
    ]

    for collector in collectors:
        collector.start()
        log.info(f"Collector started: {collector.name}")

    router = EventRouter(EVENT_QUEUE, config, db_path, log)
    router.prewarm_ollama()
    router.start()
    log.info("Bifrost pipeline active.")
    log.info("Heimdall is online. The bridge is watched.")

    while not COLLECTOR_STOP.is_set():
        time.sleep(1.0)

    log.info("Stopping collectors...")
    for collector in collectors:
        collector.join(timeout=2.0)

    log.info("Stopping ingest server...")
    ingest_server.stop()

    if dashboard:
        log.info("Stopping dashboard...")
        dashboard.stop()
        dashboard.join(timeout=3.0)

    log.info("Draining event queue...")
    drained, remaining = drain_event_queue(EVENT_QUEUE, timeout=10.0)
    if drained:
        log.info("Event queue drained successfully.")
    else:
        log.warning("Queue drain timeout. remaining_events=%d", remaining)

    log.info("Stopping router...")
    SHUTDOWN.set()
    router.join(timeout=5.0)
    if router.is_alive():
        log.warning("Router still alive after shutdown timeout.")

    remaining = EVENT_QUEUE.unfinished_tasks
    with METRICS_LOCK:
        log.info(
            "Shutdown summary: processed=%d dropped=%d remaining=%d",
            router.event_count,
            METRICS["events_dropped"],
            remaining,
        )
        log.info(f"Final metrics: {json.dumps(METRICS)}")

    log.info("Heimdall shutdown complete.")
    sys.exit(0)


if __name__ == "__main__":
    main()
