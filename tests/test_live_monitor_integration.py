#!/usr/bin/env python3

import json
import logging
import sqlite3
from queue import Queue

from bifrost import guardian


def _disable_inference_clients(self):
    self.analyst_client = None
    self.analyst_model = None
    self.extractor_client = None
    self.extractor_model = None


def _decision_for(event):
    src_ip = event["raw"].get("src_ip", "unknown")
    return {
        "schema_version": "0.1.0",
        "incident_detected": True,
        "severity": "HIGH",
        "boundary": "HOST",
        "threat_class": event["raw"].get("type", "unknown"),
        "confidence": 0.88,
        "action_required": "ALERT",
        "action_effective": "ALERT",
        "target": src_ip,
        "gjallarhorn_tier": 1,
        "reasoning": f"Detected {event['raw'].get('type')} from {src_ip}.",
        "policy_allowed": True,
    }


def _make_event(index, src_ip="45.83.64.11"):
    return {
        "source": "ingest",
        "timestamp": f"2026-05-30T00:{index:02d}:00Z",
        "boundary": "HOST",
        "raw": {
            "type": "brute_force_ssh",
            "src_ip": src_ip,
            "dest_ip": "192.168.56.10",
            "process_name": "sshd",
            "pid": 4000 + index,
            "note": "Lab replay event",
        },
    }


def test_event_router_emits_human_and_structured_live_monitoring(
    tmp_path,
    monkeypatch,
    caplog,
):
    db_path = tmp_path / "events.db"
    monkeypatch.setattr(guardian, "DB_PATH", db_path)
    monkeypatch.setattr(
        guardian.EventRouter,
        "setup_inference_clients",
        _disable_inference_clients,
    )

    guardian.init_database()
    guardian.SHUTDOWN.clear()
    guardian.COLLECTOR_STOP.clear()

    q = Queue()
    q.put(_make_event(0))

    router = guardian.EventRouter(
        q,
        {
            "hardware_tier": "TIER_4",
            "use_local_llm": False,
            "live_monitor_jsonl_path": str(tmp_path / "live_monitor.jsonl"),
            "dedup_cooldown_seconds": 0,
            "test_mode_enabled": True,
            "test_mode_summary_interval_seconds": 1,
        },
        str(db_path),
        logging.getLogger("test.live_monitor.integration"),
    )
    monkeypatch.setattr(router, "route_to_heimdall", lambda _compressed: _decision_for(_make_event(0)))
    monkeypatch.setattr(router, "compress_event", lambda event: json.dumps(event["raw"]))

    with caplog.at_level(logging.INFO):
        router.start()
        guardian.SHUTDOWN.set()
        router.join(timeout=3)

    try:
        assert not router.is_alive()
        live_monitor_log = tmp_path / "live_monitor.jsonl"
        records = [json.loads(line) for line in live_monitor_log.read_text().splitlines()]
        incident_records = [record for record in records if record["record_type"] == "incident"]
        summary_records = [record for record in records if record["record_type"] == "summary"]

        assert incident_records
        assert incident_records[0]["attacker_status"] == "new"
        assert incident_records[0]["action_taken"] == "ALERT"
        assert isinstance(incident_records[0]["model_calls"], list)
        assert incident_records[0]["test_pass"] in (True, False)
        assert summary_records
        assert any("HOST/ingest" in message for message in caplog.messages)

        with sqlite3.connect(db_path) as conn:
            stored_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        assert stored_events == 1
    finally:
        guardian.SHUTDOWN.clear()
        guardian.COLLECTOR_STOP.clear()


def test_live_monitor_stress_harness_tracks_burst_metrics(tmp_path):
    from bifrost.live_monitor import LiveMonitor

    monitor = LiveMonitor(
        {
            "live_monitor_jsonl_path": str(tmp_path / "live_monitor.jsonl"),
            "dedup_cooldown_seconds": 0,
            "test_mode_enabled": True,
        },
        logging.getLogger("test.live_monitor.stress"),
    )

    for index in range(500):
        monitor.record_event(
            _make_event(index % 60, src_ip=f"203.0.113.{index % 25}"),
            _decision_for(_make_event(index % 60, src_ip=f"203.0.113.{index % 25}")),
        )

    summary = monitor.emit_due_summary(force=True)

    assert summary["total_events"] == 500
    assert summary["incidents"] == 500
    assert "test_passed" in summary
    assert "test_failed" in summary
    assert "strongest_areas" in summary
    assert "weakest_areas" in summary
    assert summary["unique_attackers"] == 25
    assert summary["possible_false_positive_queue"] >= 0

    records = (tmp_path / "live_monitor.jsonl").read_text().splitlines()
    assert len(records) >= 501
    monitor.close()
