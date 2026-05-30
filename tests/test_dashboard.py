#!/usr/bin/env python3

import json
import sqlite3
from datetime import datetime, timezone

from bifrost.dashboard import (
    DISCLAIMER_TEXT,
    build_dashboard_state,
    parse_time_range,
    render_dashboard_html,
)


def _write_jsonl(path, records):
    path.write_text(
        "\n".join(json.dumps(r) for r in records) + "\n",
        encoding="utf-8",
    )


def _make_db(path, timestamps):
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, timestamp TEXT)")
        for ts in timestamps:
            conn.execute("INSERT INTO events (timestamp) VALUES (?)", (ts,))
        conn.commit()


def test_build_dashboard_state_summarizes_jsonl_and_db(tmp_path):
    db_path = tmp_path / "events.db"
    jsonl_path = tmp_path / "live_monitor.jsonl"

    _make_db(db_path, ["2026-05-30T00:00:00Z", "2026-05-30T00:01:00Z"])

    incidents = [
        {
            "record_type": "incident",
            "timestamp": "2026-05-30T12:00:00Z",
            "severity": "HIGH",
            "threat_class": "brute_force_ssh",
            "attacker_identity": "45.83.64.11",
            "policy_allowed": True,
            "action_taken": "ALERT",
            "summary": "SSH brute-force detected.",
            "mitre_attack": [
                {
                    "tactic_id": "TA0006",
                    "tactic": "Credential Access",
                    "technique_id": "T1110",
                    "technique": "Brute Force",
                }
            ],
        },
        {
            "record_type": "incident",
            "timestamp": "2026-05-30T12:01:00Z",
            "severity": "CRITICAL",
            "threat_class": "port_scan",
            "attacker_identity": "203.0.113.7",
            "policy_allowed": False,
            "action_taken": "BLOCK",
            "summary": "Recon activity observed.",
            "mitre_attack": [
                {
                    "tactic_id": "TA0043",
                    "tactic": "Reconnaissance",
                    "technique_id": "T1046",
                    "technique": "Network Service Scanning",
                }
            ],
        },
    ]
    _write_jsonl(jsonl_path, incidents)

    state = build_dashboard_state(
        db_path=db_path,
        live_monitor_jsonl_path=jsonl_path,
        monitor_safelist=["45.83.64.11"],
        incident_limit=10,
        now=datetime(2026, 5, 30, 12, 30, tzinfo=timezone.utc),
    )

    assert state["summary"]["dashboard_incidents"] == 2
    assert state["summary"]["db_events"] == 2
    assert state["summary"]["blocked_actions"] == 1
    assert state["summary"]["unique_attackers"] == 2
    assert state["allowlist"] == ["45.83.64.11"]
    assert state["top_mitre_techniques"][0]["count"] == 1
    assert state["incidents"][0]["threat_class"] == "port_scan"
    assert "test_mode" in state
    assert state["test_mode"]["active"] is False
    assert state["connectivity"]["database_connected"] is True
    assert len(state["attackers"]) == 2
    assert len(state["all_incidents"]) == 2
    assert len(state["blocked_actions"]) == 1


def test_build_dashboard_state_filters_by_time_range(tmp_path):
    db_path = tmp_path / "events.db"
    jsonl_path = tmp_path / "live_monitor.jsonl"
    _make_db(db_path, [])

    records = [
        {
            "record_type": "incident",
            "timestamp": "2026-05-29T12:00:00Z",
            "severity": "LOW",
            "threat_class": "old",
            "attacker_identity": "1.2.3.4",
            "policy_allowed": True,
            "action_taken": "LOG",
            "summary": "old",
            "mitre_attack": [],
        },
        {
            "record_type": "incident",
            "timestamp": "2026-05-30T12:00:00Z",
            "severity": "HIGH",
            "threat_class": "new",
            "attacker_identity": "5.6.7.8",
            "policy_allowed": True,
            "action_taken": "ALERT",
            "summary": "new",
            "mitre_attack": [],
        },
    ]
    _write_jsonl(jsonl_path, records)

    state = build_dashboard_state(
        db_path=db_path,
        live_monitor_jsonl_path=jsonl_path,
        time_range="24h",
        now=datetime(2026, 5, 30, 12, 30, tzinfo=timezone.utc),
    )
    assert state["summary"]["dashboard_incidents"] == 1
    assert state["all_incidents"][0]["threat_class"] == "new"


def test_parse_time_range_defaults():
    assert parse_time_range(None) == "24h"
    assert parse_time_range("7d") == "7d"
    assert parse_time_range("invalid") == "24h"


def test_build_dashboard_state_exposes_test_mode_summary(tmp_path):
    db_path = tmp_path / "events.db"
    jsonl_path = tmp_path / "live_monitor.jsonl"

    _make_db(db_path, ["2026-05-30T01:00:00Z"])

    records = [
        {
            "record_type": "incident",
            "timestamp": "2026-05-30T12:00:00Z",
            "severity": "HIGH",
            "threat_class": "brute_force_ssh",
            "attacker_identity": "45.83.64.11",
            "policy_allowed": True,
            "action_taken": "ALERT",
            "summary": "SSH detected.",
            "mitre_attack": [],
        },
        {
            "record_type": "summary",
            "timestamp": "2026-05-30T12:05:00Z",
            "test_mode": True,
            "total_events": 10,
            "incidents": 3,
            "blocked_actions": 1,
            "unique_attackers": 2,
            "repeat_attackers": 1,
            "new_attackers": 1,
            "repeat_patterns": 2,
            "new_patterns": 1,
            "suppressed": 0,
            "possible_false_positive_queue": 0,
            "test_passed": 8,
            "test_failed": 2,
            "test_pass_rate": 0.8,
            "strongest_areas": ["brute_force_ssh:8"],
            "weakest_areas": ["reasoner_fallback:2"],
            "dropped_events": 0,
            "queue_size": 2,
            "queue_capacity": 512,
        },
    ]
    _write_jsonl(jsonl_path, records)

    state = build_dashboard_state(
        db_path=db_path,
        live_monitor_jsonl_path=jsonl_path,
        now=datetime(2026, 5, 30, 12, 30, tzinfo=timezone.utc),
    )

    tm = state["test_mode"]
    assert tm["active"] is True
    latest = tm["latest_summary"]
    assert latest["test_passed"] == 8
    assert latest["test_failed"] == 2
    assert latest["test_pass_rate"] == 0.8
    assert latest["strongest_areas"] == ["brute_force_ssh:8"]
    assert latest["weakest_areas"] == ["reasoner_fallback:2"]
    assert latest["dropped_events"] == 0
    assert len(tm["recent_summaries"]) == 1


def test_build_dashboard_state_surfaces_latest_of_multiple_summaries(tmp_path):
    db_path = tmp_path / "events.db"
    jsonl_path = tmp_path / "live_monitor.jsonl"

    _make_db(db_path, [])

    def _summary(ts, passed, failed):
        total = passed + failed
        return {
            "record_type": "summary",
            "timestamp": ts,
            "test_mode": True,
            "total_events": total,
            "incidents": passed,
            "blocked_actions": 0,
            "unique_attackers": 1,
            "repeat_attackers": 0,
            "new_attackers": 1,
            "repeat_patterns": 0,
            "new_patterns": 1,
            "suppressed": 0,
            "possible_false_positive_queue": 0,
            "test_passed": passed,
            "test_failed": failed,
            "test_pass_rate": passed / total if total else 0.0,
            "strongest_areas": [],
            "weakest_areas": [],
            "dropped_events": 0,
            "queue_size": 0,
            "queue_capacity": 512,
        }

    summaries = [
        _summary("2026-05-30T10:00:00Z", 5, 1),
        _summary("2026-05-30T11:00:00Z", 9, 0),
        _summary("2026-05-30T12:00:00Z", 12, 3),
    ]
    _write_jsonl(jsonl_path, summaries)

    state = build_dashboard_state(
        db_path=db_path,
        live_monitor_jsonl_path=jsonl_path,
        now=datetime(2026, 5, 30, 12, 30, tzinfo=timezone.utc),
    )

    tm = state["test_mode"]
    assert tm["active"] is True
    assert tm["latest_summary"]["test_passed"] == 12
    assert tm["latest_summary"]["test_failed"] == 3
    assert len(tm["recent_summaries"]) == 3


def test_render_dashboard_html_includes_test_run_panel_when_active(tmp_path):
    db_path = tmp_path / "events.db"
    jsonl_path = tmp_path / "live_monitor.jsonl"

    _make_db(db_path, [])
    records = [
        {
            "record_type": "summary",
            "timestamp": "2026-05-30T12:00:00Z",
            "test_mode": True,
            "total_events": 5,
            "incidents": 2,
            "blocked_actions": 1,
            "unique_attackers": 1,
            "repeat_attackers": 0,
            "new_attackers": 1,
            "repeat_patterns": 0,
            "new_patterns": 1,
            "suppressed": 0,
            "possible_false_positive_queue": 0,
            "test_passed": 4,
            "test_failed": 1,
            "test_pass_rate": 0.8,
            "strongest_areas": ["port_scan:4"],
            "weakest_areas": ["model_call_failed:1"],
            "dropped_events": 0,
            "queue_size": 1,
            "queue_capacity": 512,
        }
    ]
    _write_jsonl(jsonl_path, records)

    state = build_dashboard_state(
        db_path=db_path,
        live_monitor_jsonl_path=jsonl_path,
        now=datetime(2026, 5, 30, 12, 30, tzinfo=timezone.utc),
    )
    html = render_dashboard_html(state)

    assert "Test Run Status" in html
    assert "80.0%" in html
    assert "port_scan:4" in html
    assert "model_call_failed:1" in html
    assert "#080808" in html
    assert "8B5CF6" in html or "rainbow-h" in html
    assert "disclaimer-modal" in html
    assert DISCLAIMER_TEXT[:40] in html
    assert "data-view=\"attackers\"" in html
    assert "stat-card" in html
    assert "stat-row" in html
    assert "JetBrains Mono" in html
    assert "favicon" in html.lower() or "image/svg+xml" in html
    assert "test-run-panel" in html


def test_render_dashboard_html_shows_inactive_panel_when_no_summaries(tmp_path):
    db_path = tmp_path / "events.db"
    jsonl_path = tmp_path / "live_monitor.jsonl"

    _make_db(db_path, [])
    _write_jsonl(jsonl_path, [])

    state = build_dashboard_state(
        db_path=db_path,
        live_monitor_jsonl_path=jsonl_path,
        now=datetime(2026, 5, 30, 12, 30, tzinfo=timezone.utc),
    )
    html = render_dashboard_html(state)

    assert "Test Run Status" in html
    assert "test-run-panel" in html
    assert "test-mode" in html
