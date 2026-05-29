#!/usr/bin/env python3
"""
Bifrost Baseline Engine v0.1.0

The learning period engine. Before Heimdall goes active
it spends 7 days watching and learning what normal looks
like on this specific system.

During learning:
- All events logged but no autonomous action taken
- Process baseline built — what normally runs
- Network baseline built — normal connections
- User behavior baseline — normal login patterns
- Honeypot traffic separated from host traffic

After learning:
- Anomaly detection calibrated to this system
- Active guardian mode enabled
- Gjallarhorn armed
- Heimdall fully online

This is what separates Heimdall from static rule tools.
It knows YOUR system. Not a generic system.
"""

import json
import sqlite3
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import Counter

from bifrost.paths import db_path as resolve_db_path

log = logging.getLogger("heimdall.baseline")


def get_learning_status(config: dict) -> dict:
    """
    Returns the current learning status.
    Checks if the learning period has completed.
    """
    learning_days = config.get("learning_period_days", 7)

    if not resolve_db_path().exists():
        return {
            "mode": "learning",
            "started_at": None,
            "days_elapsed": 0,
            "days_remaining": learning_days,
            "complete": False,
            "event_count": 0
        }

    try:
        conn = sqlite3.connect(str(resolve_db_path()))
        cursor = conn.cursor()

        # Get first event timestamp
        cursor.execute(
            "SELECT MIN(timestamp) FROM events"
        )
        row = cursor.fetchone()
        first_event = row[0] if row and row[0] else None

        # Get total event count
        cursor.execute("SELECT COUNT(*) FROM events")
        count = cursor.fetchone()[0]

        conn.close()

        if not first_event:
            return {
                "mode": "learning",
                "started_at": None,
                "days_elapsed": 0,
                "days_remaining": learning_days,
                "complete": False,
                "event_count": 0
            }

        started = datetime.fromisoformat(first_event.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        elapsed = (now - started).days
        remaining = max(0, learning_days - elapsed)
        complete = elapsed >= learning_days

        return {
            "mode": "active" if complete else "learning",
            "started_at": first_event,
            "days_elapsed": elapsed,
            "days_remaining": remaining,
            "complete": complete,
            "event_count": count
        }

    except Exception as e:
        log.error(f"Learning status check failed: {e}")
        return {
            "mode": "learning",
            "started_at": None,
            "days_elapsed": 0,
            "days_remaining": learning_days,
            "complete": False,
            "event_count": 0
        }


def build_process_baseline() -> dict:
    """
    Analyzes logged events to determine what processes
    normally run on this system. Returns frequency data
    that Heimdall uses to detect anomalies.
    """
    if not resolve_db_path().exists():
        return {}

    try:
        conn = sqlite3.connect(str(resolve_db_path()))
        cursor = conn.cursor()

        cursor.execute("""
            SELECT raw_event FROM events
            WHERE source = 'auditd'
            AND boundary = 'HOST'
            ORDER BY timestamp DESC
            LIMIT 5000
        """)

        rows = cursor.fetchall()
        conn.close()

        process_counts = Counter()

        for row in rows:
            try:
                raw = row[0]
                if isinstance(raw, str):
                    pairs = dict(
                        item.split("=", 1)
                        for item in raw.split()
                        if "=" in item
                    )
                    comm = pairs.get("comm", "").strip('"')
                    if comm:
                        process_counts[comm] += 1
            except Exception:
                continue

        total = sum(process_counts.values())
        baseline = {}
        for proc, count in process_counts.most_common(50):
            baseline[proc] = {
                "count": count,
                "frequency": round(count / total, 4) if total else 0
            }

        return baseline

    except Exception as e:
        log.error(f"Process baseline build failed: {e}")
        return {}


def build_network_baseline() -> dict:
    """
    Analyzes network events to determine normal connection
    patterns. Identifies expected outbound destinations
    and ports so anomalies stand out clearly.
    """
    if not resolve_db_path().exists():
        return {}

    try:
        conn = sqlite3.connect(str(resolve_db_path()))
        cursor = conn.cursor()

        cursor.execute("""
            SELECT raw_event FROM events
            WHERE source = 'network_watcher'
            AND boundary = 'HOST'
            ORDER BY timestamp DESC
            LIMIT 2000
        """)

        rows = cursor.fetchall()
        conn.close()

        port_counts = Counter()
        ip_counts = Counter()

        for row in rows:
            try:
                raw = json.loads(row[0])
                if isinstance(raw, dict):
                    port = raw.get("local_port")
                    ip = raw.get("remote_ip")
                    if port:
                        port_counts[str(port)] += 1
                    if ip:
                        ip_counts[ip] += 1
            except Exception:
                continue

        return {
            "common_ports": dict(port_counts.most_common(20)),
            "common_ips": dict(ip_counts.most_common(20))
        }

    except Exception as e:
        log.error(f"Network baseline build failed: {e}")
        return {}


def build_honeypot_baseline() -> dict:
    """
    Analyzes honeypot traffic patterns to establish
    what normal attack volume looks like. Used to
    detect anomalies in attack patterns — sudden
    changes in volume or type can indicate a targeted
    campaign rather than background noise.
    """
    if not resolve_db_path().exists():
        return {}

    try:
        conn = sqlite3.connect(str(resolve_db_path()))
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                source,
                COUNT(*) as total,
                COUNT(DISTINCT json_extract(raw_event, '$.src_ip')) as unique_ips
            FROM events
            WHERE boundary = 'HONEYPOT'
            GROUP BY source
        """)

        rows = cursor.fetchall()
        conn.close()

        baseline = {}
        for row in rows:
            source, total, unique_ips = row
            baseline[source] = {
                "total_events": total,
                "unique_ips": unique_ips or 0,
                "avg_per_day": round(total / 7, 1)
            }

        return baseline

    except Exception as e:
        log.error(f"Honeypot baseline build failed: {e}")
        return {}


def save_baseline(baseline_data: dict):
    """
    Saves the computed baseline to the database.
    Heimdall reads this on startup to calibrate
    its anomaly detection.
    """
    if not resolve_db_path().exists():
        return

    try:
        conn = sqlite3.connect(str(resolve_db_path()))
        cursor = conn.cursor()

        for metric, value in baseline_data.items():
            cursor.execute("""
                INSERT INTO baseline (metric, value, recorded_at)
                VALUES (?, ?, ?)
            """, (
                metric,
                json.dumps(value),
                datetime.now(timezone.utc).isoformat()
            ))

        conn.commit()
        conn.close()
        log.info("Baseline saved to database.")

    except Exception as e:
        log.error(f"Baseline save failed: {e}")


def load_baseline() -> dict:
    """
    Loads the most recent baseline from the database.
    Returns empty dict if no baseline exists yet.
    """
    if not resolve_db_path().exists():
        return {}

    try:
        conn = sqlite3.connect(str(resolve_db_path()))
        cursor = conn.cursor()

        cursor.execute("""
            SELECT metric, value
            FROM baseline
            ORDER BY recorded_at DESC
            LIMIT 100
        """)

        rows = cursor.fetchall()
        conn.close()

        baseline = {}
        seen = set()
        for metric, value in rows:
            if metric not in seen:
                seen.add(metric)
                try:
                    baseline[metric] = json.loads(value)
                except Exception:
                    baseline[metric] = value

        return baseline

    except Exception as e:
        log.error(f"Baseline load failed: {e}")
        return {}


def compute_and_save_baseline():
    """
    Runs all baseline builders and saves results.
    Called at end of learning period.
    """
    log.info("Computing system baseline...")

    baseline = {
        "process_baseline": build_process_baseline(),
        "network_baseline": build_network_baseline(),
        "honeypot_baseline": build_honeypot_baseline(),
        "computed_at": datetime.now(timezone.utc).isoformat()
    }

    save_baseline(baseline)

    log.info(
        f"Baseline complete. "
        f"Processes: {len(baseline['process_baseline'])} "
        f"Network ports: "
        f"{len(baseline['network_baseline'].get('common_ports', {}))} "
        f"Honeypot sources: {len(baseline['honeypot_baseline'])}"
    )

    return baseline


def build_baseline_context(baseline: dict) -> str:
    """
    Formats the baseline as context for the Heimdall
    system prompt. Tells Heimdall what normal looks
    like on this specific system.
    """
    if not baseline:
        return "No baseline established yet. Treat all anomalies carefully."

    lines = ["[SYSTEM BASELINE — What normal looks like on this system]"]

    proc_baseline = baseline.get("process_baseline", {})
    if proc_baseline:
        top_procs = list(proc_baseline.keys())[:10]
        lines.append(
            f"Normal processes: {', '.join(top_procs)}"
        )

    net_baseline = baseline.get("network_baseline", {})
    if net_baseline:
        common_ports = list(
            net_baseline.get("common_ports", {}).keys()
        )[:10]
        lines.append(
            f"Normal outbound ports: {', '.join(common_ports)}"
        )

    honey_baseline = baseline.get("honeypot_baseline", {})
    if honey_baseline:
        for source, stats in honey_baseline.items():
            lines.append(
                f"Normal {source} volume: "
                f"~{stats.get('avg_per_day', 0)} events/day"
            )

    computed = baseline.get("computed_at", "unknown")
    lines.append(f"Baseline computed: {computed}")

    return "\n".join(lines)


def print_status(config: dict):
    """
    Prints current learning status to console.
    Called on guardian startup.
    """
    status = get_learning_status(config)
    mode = status["mode"].upper()
    elapsed = status["days_elapsed"]
    remaining = status["days_remaining"]
    count = status["event_count"]

    print(f"""
┌─────────────────────────────────────────┐
│  Heimdall Learning Status               │
│                                         │
│  Mode     : {mode:<29}│
│  Elapsed  : {str(elapsed) + ' days':<29}│
│  Remaining: {str(remaining) + ' days':<29}│
│  Events   : {str(count):<29}│
└─────────────────────────────────────────┘
""")

    if status["complete"]:
        print("[+] Learning period complete. Heimdall is fully active.")
    else:
        print(
            f"[*] Learning mode active. "
            f"Heimdall observing for {remaining} more days "
            f"before autonomous response is enabled."
        )


if __name__ == "__main__":
    test_config = {"learning_period_days": 7}
    print_status(test_config)

    print("\nBuilding baseline from current data...")
    baseline = compute_and_save_baseline()
    print("\nBaseline context for Heimdall:")
    print(build_baseline_context(baseline))
