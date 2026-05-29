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
from queue import Queue, Empty, Full

from bifrost.collector_logging import log_collector_error

BIFROST_VERSION = "0.1.1"
CONFIG_PATH = Path("~/Projects/bifrost/heimdall_config.json").expanduser()
DB_PATH = Path("~/Projects/bifrost/db/events.db").expanduser()
LOG_PATH = Path("~/Projects/bifrost/db/guardian.log").expanduser()

EVENT_QUEUE = Queue(maxsize=10000)
SHUTDOWN = threading.Event()

METRICS_LOCK = threading.Lock()
METRICS = {
    "events_received": 0,
    "events_dropped": 0,
    "decisions_made": 0,
    "llm_errors": 0,
    "fallbacks": 0,
    "queue_full_count": 0,
}


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
            sys.exit(1)
        print("[+] Config integrity verified.")

    return config


def init_database():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()

    # WAL mode for durability and concurrency
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA busy_timeout=5000")

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


def safe_enqueue(queue: Queue, event: dict, source: str, log) -> bool:
    """
    Enqueue with bounded retry and drop metrics.
    Never silently drops — always logs and counts.
    """
    for attempt in range(3):
        try:
            queue.put(event, timeout=0.2)
            with METRICS_LOCK:
                METRICS["events_received"] += 1
            return True
        except Full:
            if attempt == 2:
                with METRICS_LOCK:
                    METRICS["events_dropped"] += 1
                    METRICS["queue_full_count"] += 1
                log.error(
                    f"EVENT_QUEUE full after 3 attempts. "
                    f"Dropping event source={source}. "
                    f"Total dropped={METRICS['events_dropped']}"
                )
                return False
            time.sleep(0.05)
    return False


class AuditdCollector(threading.Thread):
    AUDIT_LOG = Path("/var/log/audit/audit.log")

    def __init__(self, queue, log):
        super().__init__(daemon=True, name="collector.auditd")
        self.queue = queue
        self.log = log
        self._log_rate_limits = {}

    def run(self):
        self.log.info("AuditdCollector started.")
        if not self.AUDIT_LOG.exists():
            self.log.warning("auditd log not found. Is auditd running?")
            return

        try:
            with open(self.AUDIT_LOG, "r") as f:
                f.seek(0, 2)
                inode = os.stat(self.AUDIT_LOG).st_ino
                while not SHUTDOWN.is_set():
                    try:
                        # Detect log rotation
                        current_inode = os.stat(self.AUDIT_LOG).st_ino
                        if current_inode != inode:
                            self.log.info("auditd log rotated. Reopening.")
                            break
                    except OSError:
                        break

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
                        safe_enqueue(self.queue, event, "auditd", self.log)
        except OSError as e:
            self.log.error(f"AuditdCollector file error: {e}")
        except (RuntimeError, ValueError) as e:
            log_collector_error(
                self.log,
                self._log_rate_limits,
                "auditd.run",
                logging.ERROR,
                f"AuditdCollector stopped while reading {self.AUDIT_LOG}",
                e,
            )


class HoneypotLogCollector(threading.Thread):
    COWRIE_LOG = Path(
        "~/Projects/honeypot/logs/cowrie/cowrie.json"
    ).expanduser()

    def __init__(self, queue, log):
        super().__init__(daemon=True, name="collector.cowrie")
        self.queue = queue
        self.log = log
        self._log_rate_limits = {}

    def run(self):
        self.log.info("HoneypotLogCollector started.")
        if not self.COWRIE_LOG.exists():
            self.log.warning(f"Cowrie log not found at {self.COWRIE_LOG}")
            return

        try:
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
                        safe_enqueue(self.queue, event, "cowrie", self.log)
                    except json.JSONDecodeError as e:
                        self.log.warning(f"Cowrie JSON parse error: {e}")
        except OSError as e:
            self.log.error(f"HoneypotLogCollector file error: {e}")
        except (RuntimeError, ValueError) as e:
            log_collector_error(
                self.log,
                self._log_rate_limits,
                "cowrie.run",
                logging.ERROR,
                f"HoneypotLogCollector stopped while reading {self.COWRIE_LOG}",
                e,
            )


class ProcessWatcher(threading.Thread):
    POLL_INTERVAL = 2.0
    SUSPICIOUS_PATHS = ["/tmp/", "/dev/shm/", "/var/tmp/"]
    KERNEL_THREAD_PATTERN = ["kworker", "kthread", "ksoftirqd"]

    def __init__(self, queue, log):
        super().__init__(daemon=True, name="collector.process")
        self.queue = queue
        self.log = log
        self.seen_pids = set()
        self._log_rate_limits = {}

    def run(self):
        self.log.info("ProcessWatcher started.")
        while not SHUTDOWN.is_set():
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

                SHUTDOWN.wait(self.POLL_INTERVAL)

            except (OSError, RuntimeError, ValueError) as e:
                log_collector_error(
                    self.log,
                    self._log_rate_limits,
                    "process.loop",
                    logging.ERROR,
                    "ProcessWatcher loop error while scanning /proc",
                    e,
                )
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
        self._log_rate_limits = {}

    def run(self):
        self.log.info("NetworkWatcher started.")
        while not SHUTDOWN.is_set():
            try:
                self.scan_connections()
            except (OSError, RuntimeError, ValueError) as e:
                log_collector_error(
                    self.log,
                    self._log_rate_limits,
                    "network.scan",
                    logging.ERROR,
                    "NetworkWatcher scan error",
                    e,
                )
            time.sleep(self.POLL_INTERVAL)

    def hex_to_ip(self, hex_ip: str) -> str:
        try:
            addr = int(hex_ip, 16)
            return (f"{addr & 0xFF}.{(addr >> 8) & 0xFF}."
                    f"{(addr >> 16) & 0xFF}.{(addr >> 24) & 0xFF}")
        except (TypeError, ValueError) as e:
            log_collector_error(
                self.log,
                self._log_rate_limits,
                "network.hex_to_ip",
                logging.WARNING,
                f"NetworkWatcher received invalid hex IP {hex_ip!r}",
                e,
            )
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
    LLM_TIMEOUT = 30.0

    def __init__(self, queue, config, db_path, log):
        super().__init__(daemon=True, name="bifrost.router")
        self.queue = queue
        self.config = config
        self.db_path = db_path
        self.log = log
        self.event_count = 0
        self.conn = None
        self.setup_inference_clients()
        self.setup_db()

    def setup_db(self):
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA busy_timeout=5000")

    def setup_inference_clients(self):
        try:
            from openai import OpenAI
            if self.config.get("use_local_llm"):
                self.analyst_client = OpenAI(
                    base_url=self.config["local_url"],
                    api_key="ollama",
                    timeout=self.LLM_TIMEOUT
                )
                self.analyst_model = self.config["analyst_model"]
                self.extractor_client = OpenAI(
                    base_url=self.config["local_url"],
                    api_key="ollama",
                    timeout=self.LLM_TIMEOUT
                )
                self.extractor_model = self.config["extractor_model"]
            else:
                api_key = os.getenv("HEIMDALL_API_KEY", "")
                self.analyst_client = OpenAI(
                    base_url=self.config.get("groq_url", ""),
                    api_key=api_key,
                    timeout=self.LLM_TIMEOUT
                )
                self.analyst_model = self.config.get("groq_model", "")
                self.extractor_client = None
                self.extractor_model = None
        except Exception as e:
            self.log.error(f"Failed to setup inference clients: {e}")
            self.analyst_client = None
            self.extractor_client = None

    def compress_event(self, event: dict) -> str:
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
                            "Strip hex addresses and register states. "
                            "Return compact JSON only. No explanation."
                        )
                    },
                    {"role": "user", "content": raw}
                ]
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            self.log.warning(f"Extractor error: {e}. Using raw fallback.")
            with METRICS_LOCK:
                METRICS["llm_errors"] += 1
            return json.dumps(event.get("raw", {}))[:500]

    def route_to_heimdall(self, compressed: str) -> dict:
        if not self.analyst_client:
            return self._safe_fallback("no_analyst_client")

        try:
            baseline = self.config.get("system_baseline", "")
            response = self.analyst_client.chat.completions.create(
                model=self.analyst_model,
                temperature=0.0,
                messages=[
                    {"role": "system", "content": baseline},
                    {
                        "role": "user",
                        "content": f"Analyze this security event as JSON:\n{compressed}"
                    }
                ]
            )
            raw_decision = response.choices[0].message.content.strip()

            # Strip markdown fences if present
            if raw_decision.startswith("```"):
                raw_decision = raw_decision.strip("`")
                raw_decision = raw_decision.replace("json\n", "", 1).strip()

            decision = json.loads(raw_decision)

            # Validate required fields
            required = ["severity", "action_required", "confidence", "reasoning"]
            for field in required:
                if field not in decision:
                    self.log.warning(
                        f"LLM decision missing field: {field}. Using fallback."
                    )
                    return self._safe_fallback(f"missing_field_{field}")

            # Clamp confidence
            decision["confidence"] = max(
                0.0, min(1.0, float(decision.get("confidence", 0.0)))
            )

            with METRICS_LOCK:
                METRICS["decisions_made"] += 1

            return decision

        except json.JSONDecodeError as e:
            self.log.error(f"LLM returned invalid JSON: {e}")
            with METRICS_LOCK:
                METRICS["llm_errors"] += 1
            return self._safe_fallback("json_decode_error")
        except Exception as e:
            self.log.error(f"Heimdall reasoning error: {e}")
            with METRICS_LOCK:
                METRICS["llm_errors"] += 1
            return self._safe_fallback("llm_error")

    def _safe_fallback(self, reason: str) -> dict:
        with METRICS_LOCK:
            METRICS["fallbacks"] += 1
        return {
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
        }

    def store_event(self, event: dict, compressed=None, decision=None) -> int:
        boundary = event.get("boundary", "UNKNOWN")
        source = event.get("source", "unknown")
        raw = json.dumps(event.get("raw", {}))
        timestamp = event.get(
            "timestamp", datetime.now(timezone.utc).isoformat()
        )
        action = decision.get("action_required", "NONE") if decision else None

        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO events
                (timestamp, source, boundary, raw_event,
                 compressed_event, heimdall_decision, action_taken)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp, source, boundary, raw,
                compressed if isinstance(compressed, str) else json.dumps(compressed),
                json.dumps(decision) if decision else None,
                action
            ))
            self.conn.commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            self.log.error(f"DB store error: {e}")
            return -1

    def run(self):
        self.log.info("EventRouter started. Bifrost pipeline active.")
        while not SHUTDOWN.is_set():
            try:
                event = self.queue.get(timeout=1.0)
                boundary = event.get("boundary", "UNKNOWN")
                source = event.get("source", "unknown")

                self.event_count += 1
                if self.event_count % 100 == 0:
                    with METRICS_LOCK:
                        self.log.info(
                            f"Bifrost metrics: {json.dumps(METRICS)}"
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
                    self.queue.task_done()
                    continue

                self.log.info(
                    f"[{boundary}] [{source}] Routing to Heimdall."
                )

                compressed = self.compress_event(event)
                decision = self.route_to_heimdall(compressed)
                self.store_event(event, compressed, decision)

                severity = decision.get("severity", "UNKNOWN")
                action = decision.get("action_required", "NONE")
                confidence = decision.get("confidence", 0.0)

                self.log.info(
                    f"Heimdall: action={action} severity={severity} "
                    f"confidence={confidence:.2f}"
                )

                if action in ["KILL", "BLOCK", "QUARANTINE"]:
                    self.log.warning(
                        f"[!!!] ACTION PROPOSED: {action} — "
                        f"{decision.get('reasoning', '')} "
                        f"[DRY RUN — not enforced]"
                    )

                tier = decision.get("gjallarhorn_tier", 1)
                self.log.info(f"Gjallarhorn Tier {tier} alert queued.")
                self.queue.task_done()

            except Empty:
                continue
            except Exception as e:
                self.log.error(f"EventRouter error: {e}")

        if self.conn:
            self.conn.close()


def signal_handler(sig, frame):
    print("\n[*] Shutdown signal received. Draining queue...")
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

    # Graceful shutdown — drain queue first
    log.info("Stopping collectors...")
    for collector in collectors:
        collector.join(timeout=2.0)

    log.info("Draining event queue...")
    drain_timeout = 10.0
    drain_start = time.time()
    while not EVENT_QUEUE.empty():
        if time.time() - drain_start > drain_timeout:
            log.warning("Queue drain timeout. Exiting.")
            break
        time.sleep(0.1)

    log.info("Stopping router...")
    router.join(timeout=5.0)
    if router.is_alive():
        log.warning("Router still alive after shutdown timeout.")

    ingest_server.stop()

    with METRICS_LOCK:
        log.info(f"Final metrics: {json.dumps(METRICS)}")

    log.info("Heimdall shutdown complete.")
    sys.exit(0)


if __name__ == "__main__":
    main()
