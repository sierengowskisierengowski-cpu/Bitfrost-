#!/usr/bin/env python3
"""Enterprise read-only security dashboard for live Bifrost incidents."""

from __future__ import annotations

import html
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qs, urlparse

from bifrost import paths as bifrost_paths

# ── Design tokens (Bifrost rainbow bridge) ──────────────────────────────────
RAINBOW_GRADIENT = (
    "linear-gradient(90deg, #8B5CF6, #4F46E5, #3B82F6, #06B6D4, "
    "#22C55E, #EAB308, #D946EF)"
)
SEVERITY_COLORS = {
    "CRITICAL": "#FF2D2D",
    "HIGH": "#FF6B35",
    "MEDIUM": "#FFD166",
    "LOW": "#4ECDC4",
    "INFO": "#6B7280",
    "UNKNOWN": "#6B7280",
}

TIME_RANGE_SECONDS: dict[str, int | None] = {
    "1h": 3600,
    "24h": 86400,
    "7d": 7 * 86400,
    "30d": 30 * 86400,
    "all": None,
}
DEFAULT_TIME_RANGE = "24h"
INCIDENT_PAGE_SIZE = 25
MIN_INCIDENT_ROWS = 100

DISCLAIMER_TEXT = """
BIFROST SECURITY PLATFORM — AUTHORIZED USE AGREEMENT

This software performs autonomous security monitoring and may execute defensive
actions on the host system when explicitly enabled. By accepting this agreement
you confirm that:

1. AUTHORIZATION: You are authorized to monitor and defend the systems on which
   Bifrost is installed. Unauthorized deployment on networks or systems you do
   not own or have written permission to test is prohibited.

2. RESEARCH & LAB USE: Bifrost is intended for security research, honeypot
   environments, controlled lab networks, and systems you administer. Production
   deployment requires explicit risk assessment and change control.

3. AUTONOMOUS ACTIONS: Enabling autonomous mode may block IP addresses, terminate
   processes, and quarantine files. Misconfiguration can disrupt legitimate services.
   Default installation uses learning mode and dry-run; you must deliberately disable
   safeguards to enable enforcement.

4. DATA HANDLING: Telemetry, credentials observed in honeypots, and security events
   are stored locally. You are responsible for protecting stored data and complying
   with applicable privacy and computer-fraud laws in your jurisdiction.

5. NO WARRANTY: This software is provided as-is without warranty of any kind. The
   authors are not liable for damages arising from use or misuse.

6. INDEMNIFICATION: You agree to hold harmless the project contributors from claims
   arising from your deployment decisions.

Scroll to the bottom of this document to enable the Accept button.
""".strip()

_DISCLAIMER_SESSIONS: set[str] = set()
_DISCLAIMER_COOKIE = "bifrost_disclaimer"


def parse_time_range(value: str | None) -> str:
    key = (value or DEFAULT_TIME_RANGE).strip().lower()
    return key if key in TIME_RANGE_SECONDS else DEFAULT_TIME_RANGE


def _parse_timestamp(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _load_jsonl_records(jsonl_path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not jsonl_path.exists():
        return [], []
    incidents: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    for line in jsonl_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        rtype = record.get("record_type")
        if rtype == "incident":
            incident = dict(record)
            incident["_timestamp_dt"] = _parse_timestamp(record.get("timestamp"))
            incidents.append(incident)
        elif rtype == "summary":
            summary = dict(record)
            summary["_timestamp_dt"] = _parse_timestamp(record.get("timestamp"))
            summaries.append(summary)
    incidents.sort(
        key=lambda item: item.get("_timestamp_dt") or datetime.min.replace(tzinfo=timezone.utc)
    )
    summaries.sort(
        key=lambda item: item.get("_timestamp_dt") or datetime.min.replace(tzinfo=timezone.utc)
    )
    return incidents, summaries


def _filter_by_time_range(
    incidents: list[dict[str, Any]],
    *,
    now: datetime,
    range_key: str,
) -> list[dict[str, Any]]:
    seconds = TIME_RANGE_SECONDS.get(range_key)
    if seconds is None:
        return list(incidents)
    cutoff = now - timedelta(seconds=seconds)
    return [
        inc
        for inc in incidents
        if inc.get("_timestamp_dt") and inc["_timestamp_dt"] >= cutoff
    ]


def _strip_internal(incident: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in incident.items() if not k.startswith("_")}


def _geo_hint(ip: str) -> dict[str, str]:
    ip = str(ip or "").strip()
    if not ip or ip == "unknown":
        return {"flag": "❓", "label": "Unknown", "code": "??"}
    if ip.startswith(("10.", "192.168.", "172.")):
        return {"flag": "🏠", "label": "Private (RFC1918)", "code": "RFC1918"}
    if ip.startswith("127."):
        return {"flag": "🔁", "label": "Loopback", "code": "LOOP"}
    if ":" in ip and (ip.startswith("fe80") or ip == "::1"):
        return {"flag": "🏠", "label": "Private (IPv6)", "code": "RFC4193"}
    return {"flag": "🌐", "label": "External", "code": "EXT"}


def _threat_level_from_incidents(incidents: list[dict[str, Any]]) -> str:
    order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "UNKNOWN": 0}
    best = "INFO"
    best_score = 0
    for inc in incidents:
        sev = str(inc.get("severity") or "UNKNOWN").upper()
        score = order.get(sev, 0)
        if score > best_score:
            best_score = score
            best = sev
    return best


def _build_attacker_profiles(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for inc in incidents:
        ip = str(inc.get("attacker_identity") or "unknown")
        grouped[ip].append(inc)

    profiles: list[dict[str, Any]] = []
    for ip, items in grouped.items():
        timestamps = [i.get("_timestamp_dt") for i in items if i.get("_timestamp_dt")]
        event_types = sorted(
            {
                str(i.get("threat_class") or "unknown")
                for i in items
            }
        )
        geo = _geo_hint(ip)
        profiles.append(
            {
                "ip": ip,
                "country_flag": geo["flag"],
                "country_label": geo["label"],
                "country_code": geo["code"],
                "first_seen": min(timestamps).isoformat().replace("+00:00", "Z")
                if timestamps
                else None,
                "last_seen": max(timestamps).isoformat().replace("+00:00", "Z")
                if timestamps
                else None,
                "total_hits": len(items),
                "threat_level": _threat_level_from_incidents(items),
                "event_types": event_types,
                "events": [
                    {
                        "timestamp": _strip_internal(i).get("timestamp"),
                        "severity": i.get("severity"),
                        "threat_class": i.get("threat_class"),
                        "action_taken": i.get("action_taken"),
                        "summary": i.get("summary"),
                    }
                    for i in sorted(
                        items,
                        key=lambda x: x.get("_timestamp_dt")
                        or datetime.min.replace(tzinfo=timezone.utc),
                        reverse=True,
                    )
                ],
            }
        )
    profiles.sort(key=lambda p: p["total_hits"], reverse=True)
    return profiles


def _build_blocked_actions(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    blocked = []
    for inc in incidents:
        if inc.get("policy_allowed") is False or str(inc.get("action_taken", "")).upper() == "BLOCK":
            blocked.append(_strip_internal(inc))
    blocked.sort(key=lambda x: x.get("timestamp") or "", reverse=True)
    return blocked


def _build_minute_breakdown(
    incidents: list[dict[str, Any]],
    *,
    now: datetime,
) -> list[dict[str, Any]]:
    cutoff = now - timedelta(hours=1)
    buckets: Counter[str] = Counter()
    for incident in incidents:
        ts = incident.get("_timestamp_dt")
        if not ts or ts < cutoff:
            continue
        minute = ts.replace(second=0, microsecond=0).isoformat().replace("+00:00", "Z")
        buckets[minute] += 1
    return [
        {"minute": minute, "count": count}
        for minute, count in sorted(buckets.items())
    ]


def _load_db_summary(db_path: Path) -> dict[str, Any]:
    if not db_path.exists():
        return {
            "total_events": 0,
            "latest_event_timestamp": None,
            "connected": False,
        }
    try:
        with sqlite3.connect(db_path) as conn:
            total_events, latest_timestamp = conn.execute(
                "SELECT COUNT(*), MAX(timestamp) FROM events"
            ).fetchone()
    except sqlite3.Error:
        return {
            "total_events": 0,
            "latest_event_timestamp": None,
            "connected": False,
        }
    return {
        "total_events": int(total_events or 0),
        "latest_event_timestamp": latest_timestamp,
        "connected": True,
    }


def _load_db_events(db_path: Path, *, limit: int = 500) -> list[dict[str, Any]]:
    if not db_path.exists():
        return []
    try:
        with sqlite3.connect(db_path) as conn:
            rows = conn.execute(
                """
                SELECT id, timestamp, source, boundary, action_taken, threat_class
                FROM events
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
    except sqlite3.Error:
        try:
            with sqlite3.connect(db_path) as conn:
                rows = conn.execute(
                    """
                    SELECT id, timestamp, source, boundary, action_taken
                    FROM events
                    ORDER BY timestamp DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
        except sqlite3.Error:
            return []
    events = []
    for row in rows:
        if len(row) >= 6:
            eid, ts, source, boundary, action, threat = row
        else:
            eid, ts, source, boundary, action = row
            threat = None
        events.append(
            {
                "id": eid,
                "timestamp": ts,
                "source": source,
                "boundary": boundary,
                "action_taken": action,
                "threat_class": threat,
            }
        )
    return events


def _live_monitor_active(jsonl_path: Path, *, now: datetime) -> bool:
    if not jsonl_path.exists():
        return False
    try:
        mtime = datetime.fromtimestamp(jsonl_path.stat().st_mtime, tz=timezone.utc)
    except OSError:
        return False
    return (now - mtime) <= timedelta(hours=24)


def _summarize_timeline(
    incidents: list[dict[str, Any]],
    *,
    now: datetime,
    window_minutes: int = 60,
) -> list[dict[str, Any]]:
    buckets: Counter[str] = Counter()
    cutoff = now - timedelta(minutes=window_minutes)
    for incident in incidents:
        ts = incident.get("_timestamp_dt")
        if not ts or ts < cutoff:
            continue
        minute = ts.replace(second=0, microsecond=0).isoformat().replace("+00:00", "Z")
        buckets[minute] += 1
    return [
        {"minute": minute, "count": count}
        for minute, count in sorted(buckets.items())
    ]


def _normalize_severity(value: object) -> str:
    sev = str(value or "LOW").upper()
    if sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        return sev
    return "LOW"


def _confidence_percent(value: object) -> int:
    try:
        raw = float(value)
    except (TypeError, ValueError):
        return 0
    if raw <= 1.0:
        return int(round(max(0.0, min(1.0, raw)) * 100))
    return int(round(max(0.0, min(100.0, raw))))


def _map_incident_for_client(incident: Mapping[str, Any], index: int) -> dict[str, Any]:
    mitre_list = incident.get("mitre_attack") or []
    mitre = mitre_list[0] if mitre_list and isinstance(mitre_list[0], Mapping) else {}
    action = str(
        incident.get("action_taken")
        or incident.get("action_effective")
        or incident.get("action_required")
        or "LOG"
    )
    return {
        "id": str(incident.get("id") or f"inc-{incident.get('timestamp', index)}"),
        "timestamp": str(incident.get("timestamp") or ""),
        "severity": _normalize_severity(incident.get("severity")),
        "threatClass": str(incident.get("threat_class") or "unknown"),
        "attackerIp": str(incident.get("attacker_identity") or "unknown"),
        "mitreTechnique": str(mitre.get("technique_id") or "—"),
        "mitreTechniqueName": str(mitre.get("technique") or "—"),
        "mitreTactic": str(mitre.get("tactic") or "—"),
        "actionTaken": action.upper(),
        "confidenceScore": _confidence_percent(incident.get("confidence")),
        "summary": str(incident.get("summary") or incident.get("reasoning") or ""),
        "model": str(incident.get("reasoner_model") or "heimdall"),
        "latencyMs": int(incident.get("latency_ms") or 0),
    }


def _map_attacker_for_client(profile: Mapping[str, Any]) -> dict[str, Any]:
    events = []
    for item in profile.get("events") or []:
        if not isinstance(item, Mapping):
            continue
        events.append(
            {
                "timestamp": str(item.get("timestamp") or ""),
                "type": str(item.get("threat_class") or "unknown"),
                "command": str(item.get("summary") or item.get("command") or ""),
                "decision": str(item.get("action_taken") or "LOG"),
                "severity": _normalize_severity(item.get("severity")),
            }
        )
    return {
        "ip": str(profile.get("ip") or "unknown"),
        "country": str(profile.get("country_label") or "Unknown"),
        "countryCode": str(profile.get("country_code") or "??"),
        "flag": str(profile.get("country_flag") or "🌐"),
        "firstSeen": str(profile.get("first_seen") or ""),
        "lastSeen": str(profile.get("last_seen") or ""),
        "totalHits": int(profile.get("total_hits") or 0),
        "threatLevel": _normalize_severity(profile.get("threat_level")),
        "attackTypes": list(profile.get("event_types") or []),
        "hassh": str(profile.get("hassh") or "—"),
        "ja4": str(profile.get("ja4") or "—"),
        "events": events,
        "credentials": list(profile.get("credentials") or []),
        "sessions": list(profile.get("sessions") or []),
    }


def _map_live_event_for_client(incident: Mapping[str, Any], index: int) -> dict[str, Any]:
    mapped = _map_incident_for_client(incident, index)
    return {
        "id": f"live-{mapped['id']}",
        "timestamp": mapped["timestamp"],
        "attackerIp": mapped["attackerIp"],
        "attackType": mapped["threatClass"],
        "category": mapped["threatClass"],
        "commandRun": mapped["summary"],
        "decision": mapped["actionTaken"],
        "confidence": mapped["confidenceScore"],
        "model": mapped["model"],
        "latencyMs": mapped["latencyMs"],
        "severity": mapped["severity"],
    }


def build_guardian_client_state(state: Mapping[str, Any]) -> dict[str, Any]:
    """CamelCase guardian payload for the Tauri desktop client."""
    raw_incidents = state.get("all_incidents") or state.get("incidents") or []
    incidents = [
        _map_incident_for_client(inc, idx)
        for idx, inc in enumerate(raw_incidents)
        if isinstance(inc, Mapping)
    ]
    attackers = [
        _map_attacker_for_client(profile)
        for profile in (state.get("attackers") or [])
        if isinstance(profile, Mapping)
    ]
    live_events = [
        _map_live_event_for_client(inc, idx)
        for idx, inc in enumerate(raw_incidents[:200])
        if isinstance(inc, Mapping)
    ]

    summary = state.get("summary") or {}
    settings = state.get("settings") or {}
    top_threats = state.get("top_threat_classes") or []

    categories = [
        {"name": str(item.get("name") or "unknown"), "count": int(item.get("count") or 0)}
        for item in top_threats
        if isinstance(item, Mapping)
    ]

    mitre_counts: Counter[str] = Counter()
    for inc in incidents:
        tactic = str(inc.get("mitreTactic") or "")
        technique = str(inc.get("mitreTechnique") or "")
        if tactic and tactic != "—":
            mitre_counts[f"{tactic}|{technique}"] += 1

    return {
        "incidents": incidents,
        "attackers": attackers,
        "liveEvents": live_events,
        "categories": categories,
        "counters": {
            "eventsPerMin": max(
                int(summary.get("last_hour_incidents") or 0),
                len(state.get("minute_breakdown") or []),
            ),
            "activeAttackers": int(summary.get("unique_attackers") or len(attackers)),
            "queueDepth": int(
                (state.get("test_mode") or {}).get("latest_summary", {}).get(
                    "queue_size", 0
                )
            ),
            "processedToday": int(summary.get("db_events") or 0),
        },
        "aiModel": {
            "model": str(settings.get("analyst_model") or "heimdall"),
            "lastResponseMs": 0,
            "successRate": 99.0,
            "failureRate": 1.0,
            "circuitState": "CLOSED",
            "prewarm": True,
        },
        "hardware": {
            "tier": str(settings.get("hardware_tier") or "TIER_4"),
            "ramUsed": 0.0,
            "ramTotal": 16.0,
            "cpuPercent": 0.0,
            "diskUsed": 0.0,
            "diskTotal": 100.0,
            "uptimeSec": int(settings.get("uptime_seconds") or 0),
        },
        "config": {
            "learningMode": bool(settings.get("learning_mode", True)),
            "dryRun": bool(settings.get("dry_run", True)),
            "autonomous": bool(settings.get("autonomous_actions_enabled", False)),
            "confidenceThreshold": float(settings.get("confidence_threshold") or 0.85),
            "modelsLoaded": [
                m
                for m in (
                    settings.get("analyst_model"),
                    settings.get("extractor_model"),
                )
                if m
            ],
            "hardwareTier": str(settings.get("hardware_tier") or "TIER_4"),
            "databasePath": str(settings.get("db_path") or ""),
            "logPath": str(settings.get("log_path") or ""),
            "cowrieLogPath": "",
            "ingestPort": 8765,
            "dashboardPort": int(settings.get("dashboard_port") or 8766),
            "guardianHost": str(settings.get("dashboard_host") or "127.0.0.1"),
            "tokens": {
                "ingest": bool((settings.get("tokens") or {}).get("ingest")),
                "executor": bool((settings.get("tokens") or {}).get("executor")),
                "dashboard": bool((settings.get("tokens") or {}).get("dashboard")),
            },
        },
        "mitreTacticCounts": [
            {"tactic": key.split("|", 1)[0], "technique": key.split("|", 1)[1], "count": count}
            for key, count in mitre_counts.most_common(24)
        ],
        "timeline": list(state.get("timeline") or []),
    }


def extract_api_slice(state: Mapping[str, Any], path: str) -> dict[str, Any]:
    """Return JSON body for a dashboard API slice endpoint."""
    client = build_guardian_client_state(state)
    if path == "/api/attackers":
        return {"attackers": client["attackers"]}
    if path == "/api/incidents":
        return {"incidents": client["incidents"]}
    if path == "/api/live":
        return {"liveEvents": client["liveEvents"]}
    if path == "/api/timeline":
        return {"timeline": client["timeline"]}
    if path == "/api/mitre":
        return {"mitre": client["mitreTacticCounts"]}
    raise KeyError(path)


API_SLICE_PATHS = frozenset({
    "/api/attackers",
    "/api/incidents",
    "/api/live",
    "/api/timeline",
    "/api/mitre",
})


def build_settings_snapshot(
    config: Mapping[str, Any],
    *,
    db_path: Path,
    log_path: Path,
    started_at: float | None = None,
) -> dict[str, Any]:
    uptime_seconds = time.time() - started_at if started_at else 0
    return {
        "hardware_tier": config.get("hardware_tier", "unknown"),
        "analyst_model": config.get("analyst_model") or config.get("groq_model") or "n/a",
        "extractor_model": config.get("extractor_model") or "n/a",
        "learning_mode": bool(config.get("learning_mode", True)),
        "dry_run": bool(config.get("dry_run", True)),
        "autonomous_actions_enabled": bool(
            config.get("autonomous_actions_enabled", False)
        ),
        "confidence_threshold": config.get("confidence_threshold", 0.85),
        "tokens": {
            "ingest": bool(os.getenv("BIFROST_INGEST_TOKEN", "").strip()),
            "executor": bool(os.getenv("BIFROST_EXECUTOR_TOKEN", "").strip()),
            "dashboard": bool(os.getenv("BIFROST_DASHBOARD_TOKEN", "").strip()),
        },
        "db_path": str(db_path),
        "log_path": str(log_path),
        "uptime_seconds": int(uptime_seconds),
        "dashboard_host": config.get("dashboard_host", "127.0.0.1"),
        "dashboard_port": config.get("dashboard_port", 8766),
    }


def build_dashboard_state(
    *,
    db_path: str | Path,
    live_monitor_jsonl_path: str | Path,
    monitor_safelist: list[str] | None = None,
    incident_limit: int = 50,
    now: datetime | None = None,
    time_range: str = DEFAULT_TIME_RANGE,
    config: Mapping[str, Any] | None = None,
    started_at: float | None = None,
) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    range_key = parse_time_range(time_range)
    db_path = Path(db_path)
    jsonl_path = Path(live_monitor_jsonl_path)
    all_incidents_raw, summaries = _load_jsonl_records(jsonl_path)
    filtered = _filter_by_time_range(all_incidents_raw, now=now, range_key=range_key)

    severity_counts: Counter[str] = Counter()
    threat_counts: Counter[str] = Counter()
    technique_counts: Counter[str] = Counter()
    blocked_actions_count = 0
    unique_attackers = set()

    for incident in filtered:
        severity_counts[str(incident.get("severity") or "UNKNOWN").upper()] += 1
        threat_counts[str(incident.get("threat_class") or "unknown")] += 1
        unique_attackers.add(str(incident.get("attacker_identity") or "unknown"))
        if incident.get("policy_allowed") is False:
            blocked_actions_count += 1
        for mapping in incident.get("mitre_attack") or []:
            if not isinstance(mapping, Mapping):
                continue
            label = (
                f"{mapping.get('technique_id', 'UNKNOWN')} "
                f"{mapping.get('technique', 'Unknown')}"
            ).strip()
            technique_counts[label] += 1

    db_summary = _load_db_summary(db_path)
    last_hour = now - timedelta(hours=1)
    recent_hour_incidents = sum(
        1
        for incident in filtered
        if incident.get("_timestamp_dt") and incident["_timestamp_dt"] >= last_hour
    )

    display_incidents = [
        _strip_internal(inc)
        for inc in sorted(
            filtered,
            key=lambda x: x.get("_timestamp_dt")
            or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )
    ]
    overview_incidents = display_incidents[: max(int(incident_limit), 1)]

    latest_test_summary: dict[str, Any] = {}
    recent_summaries: list[dict[str, Any]] = []
    if summaries:
        latest = summaries[-1]
        latest_test_summary = {k: v for k, v in latest.items() if not k.startswith("_")}
        for s in summaries[-10:]:
            recent_summaries.append({k: v for k, v in s.items() if not k.startswith("_")})

    log_path = bifrost_paths.log_path(config) if config else db_path.parent / "guardian.log"

    payload = {
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "time_range": range_key,
        "connectivity": {
            "database_connected": db_summary["connected"],
            "live_monitor_active": _live_monitor_active(jsonl_path, now=now),
        },
        "summary": {
            "dashboard_incidents": len(filtered),
            "db_events": db_summary["total_events"],
            "blocked_actions": blocked_actions_count,
            "unique_attackers": len(unique_attackers),
            "last_hour_incidents": recent_hour_incidents,
            "latest_db_event_timestamp": db_summary["latest_event_timestamp"],
        },
        "severity_counts": dict(severity_counts.most_common()),
        "top_threat_classes": [
            {"name": name, "count": count}
            for name, count in threat_counts.most_common(12)
        ],
        "top_mitre_techniques": [
            {"name": name, "count": count}
            for name, count in technique_counts.most_common(12)
        ],
        "timeline": _summarize_timeline(filtered, now=now),
        "minute_breakdown": _build_minute_breakdown(all_incidents_raw, now=now),
        "allowlist": sorted(str(item) for item in (monitor_safelist or []) if str(item).strip()),
        "incidents": overview_incidents,
        "all_incidents": display_incidents,
        "blocked_actions": _build_blocked_actions(filtered),
        "attackers": _build_attacker_profiles(filtered),
        "db_events": _load_db_events(db_path),
        "test_mode": {
            "active": bool(latest_test_summary),
            "latest_summary": latest_test_summary,
            "recent_summaries": recent_summaries,
        },
        "settings": build_settings_snapshot(
            config or {},
            db_path=db_path,
            log_path=log_path,
            started_at=started_at,
        ),
        "meta": {
            "incident_page_size": INCIDENT_PAGE_SIZE,
            "min_incident_rows": MIN_INCIDENT_ROWS,
        },
    }
    payload["guardianState"] = build_guardian_client_state(payload)
    return payload


def _severity_badge(severity: str) -> str:
    sev = str(severity).upper()
    color = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["UNKNOWN"])
    return (
        f'<span class="sev-badge" style="--sev-color:{color}">'
        f"{html.escape(sev)}</span>"
    )


def _render_stat_cards_html(state: Mapping[str, Any]) -> str:
    """Server-render stat cards so layout works before JS hydrates."""
    summary = state.get("summary") or {}
    severity = state.get("severity_counts") or {}
    critical_high = int(severity.get("CRITICAL", 0)) + int(severity.get("HIGH", 0))
    cards = [
        ("⬡", "Total Events", summary.get("db_events", 0), "#9D4EDD", "events"),
        ("⚡", "Incidents", summary.get("dashboard_incidents", 0), "#E040FB", "incidents"),
        ("🛡", "Blocked", summary.get("blocked_actions", 0), "#C4607A", "blocked"),
        ("👤", "Unique Attackers", summary.get("unique_attackers", 0), "#06B6D4", "attackers"),
        ("⏱", "Last Hour", summary.get("last_hour_incidents", 0), "#22C55E", "hour"),
        ("🔥", "Critical + High", critical_high, "#FF2D2D", "critical"),
    ]
    parts = []
    for icon, label, value, color, panel in cards:
        parts.append(
            f'<div class="stat-card" data-panel="{html.escape(panel)}">'
            f'<div class="stat-icon">{icon}</div>'
            f'<div class="stat-value" style="color:{color}">{html.escape(str(value))}</div>'
            f'<div class="stat-label">{html.escape(label)}</div>'
            "</div>"
        )
    return "".join(parts)


def _render_timeline_html(state: Mapping[str, Any]) -> str:
    timeline = state.get("timeline") or []
    range_key = str(state.get("time_range") or DEFAULT_TIME_RANGE).upper()
    if not timeline:
        return (
            '<h2 class="card-title">Activity Timeline</h2>'
            '<p class="muted">No activity</p>'
        )
    max_count = max(int(row.get("count", 0)) for row in timeline) or 1
    bars = []
    for row in timeline:
        count = int(row.get("count", 0))
        height = max(12, round((count / max_count) * 120))
        minute = html.escape(str(row.get("minute", "")))
        bars.append(
            f'<div class="tl-bar-wrap" title="{minute} — {count}">'
            f'<div class="tl-bar" style="height:{height}px"></div>'
            f'<div class="tl-lbl">{html.escape(str(count))}</div>'
            "</div>"
        )
    return (
        f'<h2 class="card-title">Activity Timeline <span class="badge">{range_key}</span></h2>'
        f'<div class="tl-chart">{"".join(bars)}</div>'
    )


def _render_test_mode_panel(test_mode: Mapping[str, Any]) -> str:
    if not test_mode.get("active"):
        return (
            '<details id="test-run-panel" class="test-mode card collapsible">'
            '<summary class="card-title">Test Run Status</summary>'
            '<p class="muted">No test-mode summary records found. '
            "Start Guardian with <code>--test-mode</code> to enable live-fire tracking.</p>"
            "</details>"
        )
    s = test_mode.get("latest_summary") or {}
    total = (s.get("test_passed") or 0) + (s.get("test_failed") or 0)
    pass_rate = float(s.get("test_pass_rate") or 0.0)
    pass_pct = f"{pass_rate * 100:.1f}%"
    bar_color = "#22c55e" if pass_rate >= 0.8 else ("#eab308" if pass_rate >= 0.5 else "#ff2d2d")
    bar_pct = int(pass_rate * 100)
    recent_rows = ""
    for row in test_mode.get("recent_summaries") or []:
        rate = float(row.get("test_pass_rate") or 0.0) * 100
        recent_rows += (
            "<tr>"
            f"<td>{html.escape(str(row.get('timestamp', 'n/a')))}</td>"
            f"<td>{html.escape(str(row.get('test_passed', 0)))}</td>"
            f"<td>{html.escape(str(row.get('test_failed', 0)))}</td>"
            f"<td>{html.escape(f'{rate:.1f}%')}</td>"
            f"<td>{html.escape(str(row.get('total_events', 0)))}</td>"
            f"<td>{html.escape(str(row.get('dropped_events', 0)))}</td>"
            "</tr>"
        )
    return f"""<details id="test-run-panel" class="test-mode card collapsible">
  <summary class="card-title">Test Run Status <span class="badge live">LIVE FIRE</span></summary>
  <div class="test-body">
    <div class="pass-rate-row">
      <span class="muted">Pass rate</span>
      <span class="pass-rate-value" style="color:{bar_color}">{html.escape(pass_pct)}</span>
      <span class="muted">{html.escape(str(s.get('test_passed', 0)))} pass / {html.escape(str(s.get('test_failed', 0)))} fail</span>
    </div>
    <div class="pass-bar"><div class="pass-bar-fill" style="width:{bar_pct}%;background:{bar_color}"></div></div>
    <table class="compact-table">
      <thead><tr><th>Time</th><th>Pass</th><th>Fail</th><th>Rate</th><th>Events</th><th>Dropped</th></tr></thead>
      <tbody>{recent_rows or '<tr><td colspan="6" class="muted">No summaries yet</td></tr>'}</tbody>
    </table>
  </div>
</details>"""


def render_dashboard_html(state: Mapping[str, Any]) -> str:
    """Render the full dashboard shell (client hydrates from /api/state)."""
    css = _load_ui_asset("style.css")
    js = _load_ui_asset("app.js")
    bootstrap = json.dumps(state, default=str).replace("</", "<\\/")
    disclaimer_escaped = html.escape(DISCLAIMER_TEXT)
    favicon_svg = (
        "data:image/svg+xml,"
        "%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E"
        "%3Ctext y='82' x='50' text-anchor='middle' font-size='72'%3E🌉%3C/text%3E"
        "%3C/svg%3E"
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="theme-color" content="#080808">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="application-name" content="Bifrost">
  <title>Bifrost — Heimdall Security Dashboard</title>
  <link rel="icon" type="image/svg+xml" href="{favicon_svg}">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&amp;family=JetBrains+Mono:wght@400;600;700&amp;display=swap" rel="stylesheet">
  <style>
{css}
  </style>
</head>
<body class="disclaimer-locked">
<div id="disclaimer-modal" class="modal-overlay" role="dialog" aria-modal="true">
  <div class="modal-card">
    <h1>Authorized Use Agreement</h1>
    <div id="disclaimer-scroll" class="disclaimer-scroll">{disclaimer_escaped.replace(chr(10), '<br>')}</div>
    <button id="disclaimer-accept" class="btn primary" disabled>Accept and Continue</button>
  </div>
</div>

<div class="app-shell" id="app" hidden aria-hidden="true">
  <aside class="sidebar">
    <div class="logo-wrap">
      <span class="logo">Bifrost</span>
      <span class="logo-sub">Rainbow Bridge</span>
    </div>
    <nav class="nav">
      <button type="button" class="nav-item active" data-view="overview">Overview</button>
      <button type="button" class="nav-item" data-view="incidents">Incidents</button>
      <button type="button" class="nav-item" data-view="attackers">Attackers</button>
      <button type="button" class="nav-item" data-view="timeline">Timeline</button>
      <button type="button" class="nav-item" data-view="settings">Settings</button>
    </nav>
  </aside>

  <div class="main-column">
    <header class="top-header">
      <div class="header-title">
        <h1>Heimdall Security Dashboard</h1>
        <span class="ts" id="generated-at"></span>
      </div>
      <div class="status-pills">
        <span class="pill" id="db-status"><span class="dot ok"></span> Database: Connected</span>
        <span class="pill" id="monitor-status"><span class="dot ok"></span> Live Monitor: Active</span>
      </div>
      <div class="header-actions">
        <div class="range-group" id="time-range">
          <button type="button" data-range="1h">1H</button>
          <button type="button" data-range="24h" class="active">24H</button>
          <button type="button" data-range="7d">7D</button>
          <button type="button" data-range="30d">30D</button>
          <button type="button" data-range="all">ALL</button>
        </div>
        <button type="button" class="icon-btn" id="settings-gear" title="Settings">⚙</button>
        <label class="auto-toggle"><input id="auto-refresh" type="checkbox" checked> Auto 5s</label>
      </div>
    </header>

    <main class="content">
      <section id="view-overview" class="view active">
        <div class="stat-row" id="stat-cards">{_render_stat_cards_html(state)}</div>
        {_render_test_mode_panel(state.get("test_mode") or {})}
        <div class="grid-3" id="breakdown-cards"></div>
        <div class="card" id="timeline-card">{_render_timeline_html(state)}</div>
        <div class="card">
          <h2 class="card-title">Recent Incidents <span class="badge" id="incident-count-badge"></span></h2>
          <div class="table-scroll" id="overview-incidents-table"></div>
        </div>
      </section>

      <section id="view-incidents" class="view">
        <div class="card">
          <h2 class="card-title">All Incidents</h2>
          <div class="table-scroll tall" id="incidents-full-table"></div>
          <div class="pager" id="incidents-pager"></div>
        </div>
      </section>

      <section id="view-attackers" class="view">
        <div class="card">
          <div class="card-head-row">
            <h2 class="card-title">Attacker Profiles</h2>
            <select id="attacker-sort">
              <option value="hits">Sort: Hits</option>
              <option value="first_seen">Sort: First Seen</option>
              <option value="last_seen">Sort: Last Seen</option>
              <option value="threat">Sort: Threat Level</option>
            </select>
          </div>
          <div class="table-scroll tall" id="attackers-table"></div>
        </div>
        <div class="card" id="attacker-detail-card" hidden>
          <h2 class="card-title">Attacker Timeline — <span id="attacker-detail-ip"></span></h2>
          <div class="table-scroll" id="attacker-detail-events"></div>
        </div>
      </section>

      <section id="view-timeline" class="view">
        <div class="card" id="timeline-full-card"></div>
      </section>

      <section id="view-settings" class="view">
        <div class="card" id="settings-panel"></div>
      </section>
    </main>
  </div>
</div>

<div id="detail-overlay" class="detail-overlay" hidden>
  <div class="detail-panel">
    <button type="button" class="detail-close" id="detail-close">×</button>
    <div id="detail-content"></div>
  </div>
</div>

<script type="application/json" id="bifrost-bootstrap">{bootstrap}</script>
<script>
{js}
</script>
</body>
</html>"""


def _load_ui_asset(name: str) -> str:
    path = Path(__file__).resolve().parent / "dashboard_ui" / name
    return path.read_text(encoding="utf-8")


_DASHBOARD_CSS = _load_ui_asset("style.css")
_DASHBOARD_JS = _load_ui_asset("app.js")


def _parse_cookie_value(header: str, key: str) -> str | None:
    jar = SimpleCookie()
    try:
        jar.load(header or "")
    except Exception:
        return None
    if key not in jar:
        return None
    return jar[key].value


def _disclaimer_accepted(handler: BaseHTTPRequestHandler) -> bool:
    sid = _parse_cookie_value(handler.headers.get("Cookie", ""), _DISCLAIMER_COOKIE)
    return bool(sid and sid in _DISCLAIMER_SESSIONS)


def _build_handler(server: "DashboardServer"):
    class DashboardHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            path = parsed.path
            query = parse_qs(parsed.query)

            if path in {"/healthz", "/health"}:
                self._write_json({"ok": True})
                return

            if path == "/api/state":
                if not _disclaimer_accepted(self):
                    self.send_response(HTTPStatus.FORBIDDEN)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(b'{"error":"disclaimer_required"}')
                    return
                range_key = parse_time_range(
                    (query.get("range") or [DEFAULT_TIME_RANGE])[0]
                )
                payload = server.build_state(time_range=range_key)
                self._write_json(payload)
                return

            if path == "/api/summary":
                if not _disclaimer_accepted(self):
                    self.send_response(HTTPStatus.FORBIDDEN)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(b'{"error":"disclaimer_required"}')
                    return
                state = server.build_state()
                tm = state.get("test_mode") or {}
                self._write_json(
                    {
                        "active": tm.get("active", False),
                        "latest_summary": tm.get("latest_summary") or {},
                    }
                )
                return

            if path in API_SLICE_PATHS:
                if not _disclaimer_accepted(self):
                    self.send_response(HTTPStatus.FORBIDDEN)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(b'{"error":"disclaimer_required"}')
                    return
                range_key = parse_time_range(
                    (query.get("range") or [DEFAULT_TIME_RANGE])[0]
                )
                state = server.build_state(time_range=range_key)
                self._write_json(extract_api_slice(state, path))
                return

            if path not in {"/", ""}:
                self.send_error(HTTPStatus.NOT_FOUND, "Not found")
                return

            state = server.build_state()
            payload_html = render_dashboard_html(state).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload_html)))
            self.end_headers()
            self.wfile.write(payload_html)

        def do_POST(self) -> None:  # noqa: N802
            if urlparse(self.path).path == "/api/disclaimer/accept":
                sid = secrets.token_urlsafe(24)
                _DISCLAIMER_SESSIONS.add(sid)
                cookie = SimpleCookie()
                cookie[_DISCLAIMER_COOKIE] = sid
                cookie[_DISCLAIMER_COOKIE]["path"] = "/"
                cookie[_DISCLAIMER_COOKIE]["httponly"] = True
                cookie[_DISCLAIMER_COOKIE]["samesite"] = "Strict"
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                for morsel in cookie.values():
                    self.send_header("Set-Cookie", morsel.OutputString())
                self.end_headers()
                self.wfile.write(b'{"status":"accepted"}')
                return
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")

        def log_message(self, fmt: str, *args: Any) -> None:
            server.log.debug("dashboard %s - %s", self.address_string(), fmt % args)

        def _write_json(self, payload: Mapping[str, Any]) -> None:
            encoded = json.dumps(payload, default=str).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    return DashboardHandler


class DashboardServer(threading.Thread):
    def __init__(
        self,
        config: Mapping[str, Any],
        log: logging.Logger,
        *,
        db_path: str | Path,
    ) -> None:
        super().__init__(name="BifrostDashboard", daemon=True)
        self.config = dict(config)
        self.log = log
        self.db_path = Path(db_path)
        self.jsonl_path = Path(
            self.config.get("live_monitor_jsonl_path")
            or bifrost_paths.log_path(self.config).with_name("live_monitor.jsonl")
        )
        self.host = str(self.config.get("dashboard_host") or "127.0.0.1")
        self.port = int(self.config.get("dashboard_port") or 8766)
        self.incident_limit = int(self.config.get("dashboard_incident_limit") or 50)
        self.monitor_safelist = list(self.config.get("monitor_safelist") or [])
        self._server: ThreadingHTTPServer | None = None
        self._started_at = time.time()

    def build_state(self, time_range: str = DEFAULT_TIME_RANGE) -> dict[str, Any]:
        return build_dashboard_state(
            db_path=self.db_path,
            live_monitor_jsonl_path=self.jsonl_path,
            monitor_safelist=self.monitor_safelist,
            incident_limit=self.incident_limit,
            time_range=time_range,
            config=self.config,
            started_at=self._started_at,
        )

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/"

    def run(self) -> None:
        handler = _build_handler(self)
        self._server = ThreadingHTTPServer((self.host, self.port), handler)
        self._server.daemon_threads = True
        self.log.info("Bifrost dashboard listening on %s", self.url)
        self._server.serve_forever(poll_interval=0.5)

    def stop(self) -> None:
        if not self._server:
            return
        self._server.shutdown()
        self._server.server_close()
