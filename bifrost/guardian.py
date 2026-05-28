#!/usr/bin/env python3
"""
Heimdall Guardian v0.1.0
Bifrost Security Platform

Main runtime loop. Starts on boot, watches forever.
Loads config, initializes all collectors, routes events
through the Bifrost pipeline to Heimdall for decision.

Usage: python -m bifrost.guardian
"""

import os
import sys
import json
import time
import signal
import logging
import sqlite3
import threading
from pathlib import Path
from datetime import datetime, timezone
from queue import Queue, Empty

BIFROST_VERSION = "0.1.0"
CONFIG_PATH = Path("~/Projects/bifrost/heimdall_config.json").expanduser()
DB_PATH = Path("~/Projects/bifrost/db/events.db").expanduser()
LOG_PATH = Path("~/Projects/bifrost/db/guardian.log").expanduser()

EVENT_QUEUE = Queue(maxsize=10000)
SHUTDOWN = threading.Event()


def setup_logging():
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        handlers=[
            logging.FileHandler(LOG_PATH),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger("heimdall.guardian")


def load_config():
    if not CONFIG_PATH.exists():
        print("[!] heimdall_config.json not found.")
        print("[!] Run python setup.py first.")
        sys.exit(1)

    with open(CONFIG_PATH) as f:
        config = json.load(f)

    checksum_path = CONFIG_PATH.with_suffix(".sha256")
    if checksum_path.exists():
        import hashlib
        actual = hashlib.sha256(CONFIG_PATH.read_bytes()).hexdigest()
        expected = checksum_path.read_text().strip()
        if actual != expected:
            print("[!] CRITICAL: Config checksum mismatch.")
            print("[!] heimdall_config.json may have been tampered with.")
            print("[!] Run python setup.py to regenerate.")
            sys.exit(1)
        print("[+] Config integrity verified.")

    return config


def init_database():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()

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

    conn.commit()
    conn.close()
    return str(DB_PATH)


def banner(config):
    tier = config.get("hardware_tier", "UNKNOWN")
    analyst = config.get("analyst_model") or "Cloud Routed"
    extractor = config.get("extractor_model") or "Rules Only"
    learning = config.get("learning_period_days", 7)

    print(f"""
╔══════════════════════════════════════════════════════╗
║           HEIMDALL GUARDIAN v{BIFROST_VERSION}                   ║
║           Bifrost Security Platform                  ║
║                                                      ║
║   Hardware Tier : {tier:<34}║
║   Analyst Model : {analyst:<34}║
║   Extractor     : {extractor:<34}║
║   Learning Days : {str(learning):<34}║
║                                                      ║
║   The Bridge Is Watched. Heimdall Never Sleeps.      ║
╚══════════════════════════════════════════════════════╝
""")


class AuditdCollector(threading.Thread):
    AUDIT_LOG = Path("/var/log/audit/audit.log")

    def __init__(self, queue, log):
        super().__init__(daemon=True, name="collector.auditd")
        self.queue = queue
        self.log = log

    def run(self):
        self.log.info("AuditdCollector started.")
        if not self.AUDIT_LOG.exists():
            self.log.warning("auditd log not found. Is auditd running?")
            return

        with open(self.AUDIT_LOG, "r") as f:
            f.seek(0, 2)
            while not SHUTDOWN.is_set():
                line = f.readline()
                if not line:
                    time.sleep(0.1)
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
                    try:
                        self.queue.put_nowait(event)
                    except Exception:
                        pass


class HoneypotLogCollector(threading.Thread):
    COWRIE_LOG = Path(
        "~/Projects/honeypot/logs/cowrie/cowrie.json"
    ).expanduser()

    def __init__(self, queue, log):
        super().__init__(daemon=True, name="collector.cowrie")
        self.queue = queue
        self.log = log

    def run(self):
        self.log.info("HoneypotLogCollector started.")
        if not self.COWRIE_LOG.exists():
            self.log.warning(f"Cowrie log not found at {self.COWRIE_LOG}")
            return

        with open(self.COWRIE_LOG, "r") as f:
            f.seek(0, 2)
            while not SHUTDOWN.is_set():
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                try:
                    entry = json.loads(line.strip())
                    event = {
                        "source": "cowrie",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "boundary": "HONEYPOT",
                        "raw": entry
                    }
                    self.queue.put_nowait(event)
                except Exception:
                    pass


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
        while not SHUTDOWN.is_set():
            try:
                for pid_dir in Path("/proc").glob("[0-9]*"):
                    pid = int(pid_dir.name)
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
                            self.queue.put_nowait(event)

                        self.seen_pids.add(pid)

                    except (PermissionError, FileNotFoundError):
                        continue

                current_pids = {
                    int(p.name) for p in Path("/proc").glob("[0-9]*")
                }
                self.seen_pids &= current_pids
                SHUTDOWN.wait(self.POLL_INTERVAL)

            except Exception as e:
                self.log.error(f"ProcessWatcher error: {e}")
                time.sleep(1)


class NetworkWatcher(threading.Thread):
    POLL_INTERVAL = 3.0
    HOST_SUBNET = "192.168.0."
    HONEYPOT_PORTS = {2222, 23, 445, 1433, 21, 25, 8888, 3389, 5900}

    def __init__(self, queue, log):
        super().__init__(daemon=True, name="collector.network")
        self.queue = queue
        self.log = log
        self.seen_connections = set()

    def run(self):
        self.log.info("NetworkWatcher started.")
        while not SHUTDOWN.is_set():
            try:
                self.scan_connections()
            except Exception as e:
                self.log.error(f"NetworkWatcher error: {e}")
            time.sleep(self.POLL_INTERVAL)

    def hex_to_ip(self, hex_ip):
        try:
            addr = int(hex_ip, 16)
            return (f"{addr & 0xFF}.{(addr >> 8) & 0xFF}."
                    f"{(addr >> 16) & 0xFF}.{(addr >> 24) & 0xFF}")
        except Exception:
            return "0.0.0.0"

    def scan_connections(self):
        for tcp_file in [Path("/proc/net/tcp"), Path("/proc/net/tcp6")]:
            if not tcp_file.exists():
                continue
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
                    local_ip = self.hex_to_ip(local.split(":")[0])
                    remote_ip = self.hex_to_ip(remote.split(":")[0])
                    local_port = int(local.split(":")[1], 16)
                    conn_key = f"{local_ip}:{local_port}-{remote_ip}"
                    if conn_key in self.seen_connections:
                        continue
                    self.seen_connections.add(conn_key)

                    if (local_port in self.HONEYPOT_PORTS and
                            self.HOST_SUBNET in remote_ip):
                        event = {
                            "source": "network_watcher",
                            "timestamp": datetime.now(
                                timezone.utc).isoformat(),
                            "boundary": "HOST",
                            "raw": {
                                "local_ip": local_ip,
                                "local_port": local_port,
                                "remote_ip": remote_ip,
                                "alert": "honeypot_to_host_connection"
                            }
                        }
                        try:
                            self.queue.put_nowait(event)
                        except Exception:
                            pass
            except Exception:
                pass


class EventRouter(threading.Thread):
    def __init__(self, queue, config, db_path, log):
        super().__init__(daemon=True, name="bifrost.router")
        self.queue = queue
        self.config = config
        self.db_path = db_path
        self.log = log
        self.event_count = 0
        self.setup_inference_clients()

    def setup_inference_clients(self):
        from openai import OpenAI

        if self.config.get("use_local_llm"):
            self.analyst_client = OpenAI(
                base_url=self.config["local_url"],
                api_key="ollama"
            )
            self.analyst_model = self.config["analyst_model"]
            self.extractor_client = OpenAI(
                base_url=self.config["local_url"],
                api_key="ollama"
            )
            self.extractor_model = self.config["extractor_model"]
        else:
            api_key = os.getenv("HEIMDALL_API_KEY", "")
            self.analyst_client = OpenAI(
                base_url=self.config["groq_url"],
                api_key=api_key
            )
            self.analyst_model = self.config["groq_model"]
            self.extractor_client = None
            self.extractor_model = None

    def compress_event(self, event):
        if not self.extractor_client:
            raw = json.dumps(event.get("raw", {}))
            return raw[:500]

        try:
            raw = json.dumps(event.get("raw", {}))
            response = self.extractor_client.chat.completions.create(
                model=self.extractor_model,
                temperature=0.0,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a security event compressor. "
                            "Strip hex addresses, memory dumps, and register "
                            "states. Return only the semantically meaningful "
                            "security-relevant tokens as compact JSON. "
                            "Never add explanation."
                        )
                    },
                    {"role": "user", "content": raw}
                ]
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            self.log.warning(f"Extractor fallback triggered: {e}")
            return json.dumps(event.get("raw", {}))[:500]

    def route_to_heimdall(self, compressed, event):
        try:
            baseline = self.config.get("system_baseline", "")
            response = self.analyst_client.chat.completions.create(
                model=self.analyst_model,
                temperature=0.0,
                messages=[
                    {"role": "system", "content": baseline},
                    {
                        "role": "user",
                        "content": (
                            f"Analyze this security event and return "
                            f"your decision as JSON:\n{compressed}"
                        )
                    }
                ]
            )
            raw_decision = response.choices[0].message.content.strip()
            return json.loads(raw_decision)
        except Exception as e:
            self.log.error(f"Heimdall reasoning error: {e}")
            return None

    def store_event(self, event, compressed=None, decision=None):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        boundary = event.get("boundary", "UNKNOWN")
        source = event.get("source", "unknown")
        raw = json.dumps(event.get("raw", {}))
        timestamp = event.get(
            "timestamp", datetime.now(timezone.utc).isoformat()
        )
        action = decision.get("action_required", "NONE") if decision else None

        cursor.execute("""
            INSERT INTO events
            (timestamp, source, boundary, raw_event,
             compressed_event, heimdall_decision, action_taken)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp, source, boundary, raw,
            json.dumps(compressed) if compressed else None,
            json.dumps(decision) if decision else None,
            action
        ))

        event_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return event_id

    def run(self):
        self.log.info("EventRouter started. Bifrost pipeline active.")
        while not SHUTDOWN.is_set():
            try:
                event = self.queue.get(timeout=1.0)
                boundary = event.get("boundary", "UNKNOWN")
                source = event.get("source", "unknown")

                self.event_count += 1
                if self.event_count % 100 == 0:
                    self.log.info(
                        f"Bifrost: {self.event_count} events processed."
                    )

                raw_data = event.get("raw", {})
                is_breakout = (
                    isinstance(raw_data, dict) and
                    raw_data.get("alert") in [
                        "honeypot_to_host_connection",
                        "container_escape_detected"
                    ]
                )

                if boundary == "HONEYPOT" and not is_breakout:
                    self.store_event(event)
                    continue

                self.log.info(
                    f"[{boundary}] [{source}] Routing to Heimdall."
                )

                compressed = self.compress_event(event)
                decision = self.route_to_heimdall(compressed, event)
                event_id = self.store_event(event, compressed, decision)

                if decision:
                    severity = decision.get("severity", "UNKNOWN")
                    action = decision.get("action_required", "NONE")
                    confidence = decision.get("confidence", 0.0)

                    self.log.info(
                        f"Heimdall: action={action} severity={severity} "
                        f"confidence={confidence}"
                    )

                    if action in ["KILL", "BLOCK", "QUARANTINE"]:
                        self.log.warning(
                            f"[!!!] AUTONOMOUS ACTION: {action} — "
                            f"{decision.get('reasoning', '')}"
                        )

                    tier = decision.get("gjallarhorn_tier", 1)
                    self.log.info(
                        f"Gjallarhorn Tier {tier} alert queued."
                    )

            except Empty:
                continue
            except Exception as e:
                self.log.error(f"EventRouter error: {e}")


def signal_handler(sig, frame):
    print("\n[*] Shutdown signal received. Stopping Heimdall...")
    SHUTDOWN.set()


def main():
    log = setup_logging()
    log.info("=" * 60)
    log.info(f"Heimdall Guardian v{BIFROST_VERSION} starting.")
    log.info("=" * 60)

    config = load_config()
    banner(config)

    db_path = init_database()
    log.info(f"Database initialized: {db_path}")

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start HTTP ingest server
    # Receives events from Go collector agent
    from bifrost.ingest import IngestServer
    ingest_server = IngestServer(EVENT_QUEUE)
    ingest_server.start()
    log.info("Ingest server started on http://127.0.0.1:8765/ingest")

    collectors = [
        AuditdCollector(EVENT_QUEUE, log),
        HoneypotLogCollector(EVENT_QUEUE, log),
        ProcessWatcher(EVENT_QUEUE, log),
        NetworkWatcher(EVENT_QUEUE, log),
    ]

    for collector in collectors:
        collector.start()
        log.info(f"Collector started: {collector.name}")

    router = EventRouter(EVENT_QUEUE, config, db_path, log)
    router.start()
    log.info("Bifrost pipeline active.")
    log.info("Heimdall is online. The bridge is watched.")

    while not SHUTDOWN.is_set():
        time.sleep(1.0)

    log.info("Shutting down...")
    ingest_server.stop()
    for collector in collectors:
        collector.join(timeout=3.0)
    router.join(timeout=3.0)
    log.info("Heimdall shutdown complete.")
    sys.exit(0)


if __name__ == "__main__":
    main()
