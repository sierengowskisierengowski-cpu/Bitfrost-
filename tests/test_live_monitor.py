#!/usr/bin/env python3

import json
import logging
from queue import Queue

from bifrost.live_monitor import (
    LiveMonitor,
    format_human_incident,
    normalize_monitor_event,
)


def _make_event(
    *,
    source="ingest",
    timestamp="2026-05-30T00:00:00Z",
    src_ip="45.83.64.11",
    process_name="sshd",
    event_type="brute_force_ssh",
    note="Repeated failed root logins",
):
    return {
        "source": source,
        "timestamp": timestamp,
        "boundary": "HOST",
        "raw": {
            "src_ip": src_ip,
            "dest_ip": "192.168.56.10",
            "process_name": process_name,
            "type": event_type,
            "note": note,
            "pid": 4412,
        },
    }


def _make_decision(confidence=0.86, *, action="ALERT", severity="HIGH"):
    return {
        "incident_detected": True,
        "severity": severity,
        "boundary": "HOST",
        "threat_class": "brute_force_ssh",
        "confidence": confidence,
        "action_required": action,
        "action_effective": action,
        "reasoning": "SSH brute-force detected against the lab host.",
        "policy_allowed": True,
    }


def test_normalize_monitor_event_is_deterministic():
    event = _make_event()
    decision = _make_decision()

    first = normalize_monitor_event(event, decision, sequence=1)
    second = normalize_monitor_event(dict(event), dict(decision), sequence=1)

    assert first["fingerprint"] == second["fingerprint"]
    assert first["incident_id"] == second["incident_id"]
    assert first["attacker_identity"] == "45.83.64.11"
    assert first["host"] == "ingest"
    assert first["action_taken"] == "ALERT"


def test_live_monitor_tracks_new_and_repeat_attackers(tmp_path):
    monitor = LiveMonitor(
        {
            "live_monitor_jsonl_path": str(tmp_path / "live_monitor.jsonl"),
            "dedup_cooldown_seconds": 0,
        },
        logging.getLogger("test.live_monitor"),
        queue=Queue(maxsize=32),
    )

    first = monitor.record_event(_make_event(), _make_decision())
    second = monitor.record_event(
        _make_event(timestamp="2026-05-30T00:10:00Z"),
        _make_decision(),
    )

    assert first["attacker_status"] == "new"
    assert second["attacker_status"] == "repeat"
    assert second["recent_count"] == 2
    assert second["repeat_count"] == 2
    assert second["unique_attackers"] == 1

    lines = (tmp_path / "live_monitor.jsonl").read_text().splitlines()
    assert len(lines) == 2
    monitor.close()


def test_live_monitor_audits_suppression_reasons(tmp_path):
    monitor = LiveMonitor(
        {
            "live_monitor_jsonl_path": str(tmp_path / "live_monitor.jsonl"),
            "monitor_safelist": ["45.83.64.11"],
            "live_confidence_threshold": 0.90,
        },
        logging.getLogger("test.live_monitor.suppression"),
    )

    record = monitor.record_event(_make_event(), _make_decision(confidence=0.20))

    assert record["suppression"]["suppressed"] is True
    assert "allowlisted" in record["suppression"]["reasons"]
    assert "below_confidence_threshold" in record["suppression"]["reasons"]
    assert record["suppression"]["possible_false_positive"] is True

    stored = json.loads((tmp_path / "live_monitor.jsonl").read_text().splitlines()[0])
    assert stored["suppression"]["suppressed"] is True
    monitor.close()


def test_human_formatter_includes_required_fields():
    record = {
        "timestamp": "2026-05-30T00:00:00Z",
        "boundary": "HOST",
        "source": "ingest",
        "threat_class": "brute_force_ssh",
        "confidence": 0.88,
        "host": "lab-node-1",
        "severity": "HIGH",
        "summary": "SSH brute-force detected against the lab host.",
        "attacker_identity": "45.83.64.11",
        "attacker_status": "repeat",
        "pattern_status": "new",
        "recent_count": 3,
        "recent_window_seconds": 3600,
        "repeat_count": 5,
        "repeat_window_seconds": 86400,
        "action_taken": "ALERT",
        "outcome": "no_destructive_action",
        "test_mode": True,
    }

    text = format_human_incident(record)

    assert "2026-05-30T00:00:00Z" in text
    assert "lab-node-1" in text
    assert "HIGH" in text
    assert "45.83.64.11" in text
    assert "HOST/ingest" in text
    assert "conf=0.88" in text
    assert "repeat / pattern new" in text
    assert "Action taken: ALERT" in text
