#!/usr/bin/env python3
"""Minimal read-only dashboard for live Bifrost incidents."""

from __future__ import annotations

import html
import json
import logging
import sqlite3
import threading
from collections import Counter
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping

from bifrost import paths as bifrost_paths


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
    """Return (incidents, summaries) loaded from the live_monitor JSONL file."""
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
        key=lambda item: item.get("_timestamp_dt") or datetime.max.replace(tzinfo=timezone.utc)
    )
    summaries.sort(
        key=lambda item: item.get("_timestamp_dt") or datetime.max.replace(tzinfo=timezone.utc)
    )
    return incidents, summaries


def _load_incident_records(jsonl_path: Path) -> list[dict[str, Any]]:
    incidents, _ = _load_jsonl_records(jsonl_path)
    return incidents


def _load_db_summary(db_path: Path) -> dict[str, Any]:
    if not db_path.exists():
        return {"total_events": 0, "latest_event_timestamp": None}
    try:
        with sqlite3.connect(db_path) as conn:
            total_events, latest_timestamp = conn.execute(
                "SELECT COUNT(*), MAX(timestamp) FROM events"
            ).fetchone()
    except sqlite3.Error:
        return {"total_events": 0, "latest_event_timestamp": None}
    return {
        "total_events": int(total_events or 0),
        "latest_event_timestamp": latest_timestamp,
    }


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


def build_dashboard_state(
    *,
    db_path: str | Path,
    live_monitor_jsonl_path: str | Path,
    monitor_safelist: list[str] | None = None,
    incident_limit: int = 50,
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    db_path = Path(db_path)
    jsonl_path = Path(live_monitor_jsonl_path)
    incidents, summaries = _load_jsonl_records(jsonl_path)
    recent_incidents = list(reversed(incidents[-max(int(incident_limit), 1):]))

    severity_counts: Counter[str] = Counter()
    threat_counts: Counter[str] = Counter()
    technique_counts: Counter[str] = Counter()
    blocked_actions = 0
    unique_attackers = set()

    for incident in incidents:
        severity_counts[str(incident.get("severity") or "UNKNOWN").upper()] += 1
        threat_counts[str(incident.get("threat_class") or "unknown")] += 1
        unique_attackers.add(str(incident.get("attacker_identity") or "unknown"))
        if incident.get("policy_allowed") is False:
            blocked_actions += 1
        for mapping in incident.get("mitre_attack") or []:
            if not isinstance(mapping, Mapping):
                continue
            label = f"{mapping.get('technique_id', 'UNKNOWN')} {mapping.get('technique', 'Unknown')}".strip()
            technique_counts[label] += 1

    db_summary = _load_db_summary(db_path)
    last_hour = now - timedelta(hours=1)
    recent_hour_incidents = sum(
        1
        for incident in incidents
        if incident.get("_timestamp_dt") and incident["_timestamp_dt"] >= last_hour
    )

    for incident in recent_incidents:
        incident.pop("_timestamp_dt", None)

    # Build test-mode summary data from the latest summary record
    latest_test_summary: dict[str, Any] = {}
    recent_summaries: list[dict[str, Any]] = []
    if summaries:
        latest = summaries[-1]
        latest_test_summary = {k: v for k, v in latest.items() if not k.startswith("_")}
        for s in summaries[-10:]:
            recent_summaries.append({k: v for k, v in s.items() if not k.startswith("_")})

    return {
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "paths": {
            "db_path": str(db_path),
            "live_monitor_jsonl_path": str(jsonl_path),
        },
        "summary": {
            "dashboard_incidents": len(incidents),
            "db_events": db_summary["total_events"],
            "blocked_actions": blocked_actions,
            "unique_attackers": len(unique_attackers),
            "last_hour_incidents": recent_hour_incidents,
            "latest_db_event_timestamp": db_summary["latest_event_timestamp"],
        },
        "severity_counts": dict(severity_counts.most_common()),
        "top_threat_classes": [
            {"name": name, "count": count}
            for name, count in threat_counts.most_common(8)
        ],
        "top_mitre_techniques": [
            {"name": name, "count": count}
            for name, count in technique_counts.most_common(8)
        ],
        "timeline": _summarize_timeline(incidents, now=now),
        "allowlist": sorted(str(item) for item in (monitor_safelist or []) if str(item).strip()),
        "incidents": recent_incidents,
        "test_mode": {
            "active": bool(latest_test_summary),
            "latest_summary": latest_test_summary,
            "recent_summaries": recent_summaries,
        },
    }


def _render_key_values(title: str, items: Mapping[str, Any]) -> str:
    rows = "".join(
        f"<li><strong>{html.escape(str(key))}</strong>: {html.escape(str(value))}</li>"
        for key, value in items.items()
    )
    return f"<section><h2>{html.escape(title)}</h2><ul>{rows or '<li>None</li>'}</ul></section>"


def _render_ranked(title: str, rows: list[dict[str, Any]], key_name: str = "name") -> str:
    items = "".join(
        f"<tr><td>{html.escape(str(row.get(key_name, 'unknown')))}</td><td>{html.escape(str(row.get('count', 0)))}</td></tr>"
        for row in rows
    )
    return (
        f"<section><h2>{html.escape(title)}</h2>"
        "<table><thead><tr><th>Name</th><th>Count</th></tr></thead>"
        f"<tbody>{items or '<tr><td colspan=2>None</td></tr>'}</tbody></table></section>"
    )


def _render_test_mode_panel(test_mode: Mapping[str, Any]) -> str:
    if not test_mode.get("active"):
        return (
            "<div class='card'>"
            "<h2 class='card-title'>Test Run Status</h2>"
            "<p style='color:#b39acb'>No test-mode summary records found. "
            "Start Guardian with <code>--test-mode</code> to enable live-fire tracking.</p>"
            "</div>"
        )
    s = test_mode.get("latest_summary") or {}
    total = (s.get("test_passed") or 0) + (s.get("test_failed") or 0)
    pass_rate = s.get("test_pass_rate", 0.0)
    pass_pct = f"{pass_rate * 100:.1f}%"
    bar_color = "#22c55e" if pass_rate >= 0.8 else ("#f59e0b" if pass_rate >= 0.5 else "#ef4444")
    bar_pct = int(pass_rate * 100)

    strengths = ", ".join(s.get("strongest_areas") or []) or "n/a"
    weaknesses = ", ".join(s.get("weakest_areas") or []) or "n/a"

    queue_size = s.get("queue_size", 0)
    queue_cap = s.get("queue_capacity", 0)
    dropped = s.get("dropped_events", 0)
    queue_label = f"{queue_size}/{queue_cap}" if queue_cap else str(queue_size)
    queue_color = "#ef4444" if queue_size > (queue_cap * 0.8 if queue_cap else 0) else "#22c55e"

    recent_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(row.get('timestamp', 'n/a')))}</td>"
        f"<td>{html.escape(str(row.get('test_passed', 0)))}</td>"
        f"<td>{html.escape(str(row.get('test_failed', 0)))}</td>"
        "<td>" + html.escape(f'{(row.get("test_pass_rate") or 0.0) * 100:.1f}%') + "</td>"
        f"<td>{html.escape(str(row.get('total_events', 0)))}</td>"
        f"<td>{html.escape(str(row.get('dropped_events', 0)))}</td>"
        "</tr>"
        for row in (test_mode.get("recent_summaries") or [])
    )

    return f"""<div class="card" style="border-color:#5b2e7e;margin-bottom:1rem">
  <h2 class="card-title">Test Run Status <span class="badge" style="background:#260c3f;color:#f9a8d4">LIVE FIRE</span></h2>
  <div style="margin-bottom:1rem">
    <div style="display:flex;align-items:center;gap:1rem;flex-wrap:wrap">
      <span style="font-size:0.82rem;color:#b39acb">Pass rate:</span>
      <span style="font-size:2rem;font-weight:800;color:{bar_color}">{html.escape(pass_pct)}</span>
      <span style="font-size:0.82rem;color:#d7b4ff">{html.escape(str(s.get('test_passed', 0)))} pass &nbsp;/&nbsp; {html.escape(str(s.get('test_failed', 0)))} fail &nbsp;/&nbsp; {html.escape(str(total))} total</span>
    </div>
    <div style="background:#1a0f2c;border-radius:6px;height:10px;margin-top:0.5rem;overflow:hidden;border:1px solid #5b2e7e">
      <div style="background:{bar_color};width:{bar_pct}%;height:100%;border-radius:6px;transition:width .5s"></div>
    </div>
  </div>
  <div class="grid-3" style="margin-bottom:0.75rem">
    <div style="background:#1a0f2c;border-radius:8px;padding:0.6rem 0.9rem;border:1px solid #5b2e7e">
      <div style="font-size:0.65rem;color:#b39acb;text-transform:uppercase;letter-spacing:.08em">Events</div>
      <div style="font-size:1.4rem;font-weight:700;color:#c4b5fd">{html.escape(str(s.get('total_events', 0)))}</div>
    </div>
    <div style="background:#1a0f2c;border-radius:8px;padding:0.6rem 0.9rem;border:1px solid #5b2e7e">
      <div style="font-size:0.65rem;color:#b39acb;text-transform:uppercase;letter-spacing:.08em">Incidents</div>
      <div style="font-size:1.4rem;font-weight:700;color:#d946ef">{html.escape(str(s.get('incidents', 0)))}</div>
    </div>
    <div style="background:#1a0f2c;border-radius:8px;padding:0.6rem 0.9rem;border:1px solid #5b2e7e">
      <div style="font-size:0.65rem;color:#b39acb;text-transform:uppercase;letter-spacing:.08em">Blocked</div>
      <div style="font-size:1.4rem;font-weight:700;color:#f472b6">{html.escape(str(s.get('blocked_actions', 0)))}</div>
    </div>
  </div>
  <ul style="font-size:0.82rem;list-style:none;padding:0;display:flex;flex-direction:column;gap:0.3rem">
    <li><span style="color:#b39acb">Unique attackers:</span> {html.escape(str(s.get('unique_attackers', 0)))} &nbsp;<span style="color:#b39acb">(repeat: {html.escape(str(s.get('repeat_attackers', 0)))}, new: {html.escape(str(s.get('new_attackers', 0)))})</span></li>
    <li><span style="color:#b39acb">Suppressed:</span> {html.escape(str(s.get('suppressed', 0)))} &nbsp;<span style="color:#b39acb">(FP queue: {html.escape(str(s.get('possible_false_positive_queue', 0)))})</span></li>
    <li><span style="color:#b39acb">Queue:</span> <span style="color:{queue_color};font-weight:600">{html.escape(queue_label)}</span> &nbsp; <span style="color:#b39acb">Dropped:</span> <span style="color:{'#ef4444' if dropped else '#22c55e'};font-weight:600">{html.escape(str(dropped))}</span></li>
    <li><span style="color:#b39acb">Strongest:</span> <span style="color:#a7f3d0">{html.escape(strengths)}</span></li>
    <li><span style="color:#b39acb">Weakest:</span> <span style="color:#fcd34d">{html.escape(weaknesses)}</span></li>
    <li><span style="color:#b39acb">Last summary:</span> {html.escape(str(s.get('timestamp', 'n/a')))}</li>
  </ul>
  <h3 style="margin-top:1rem;font-size:0.75rem;color:#b39acb;text-transform:uppercase;letter-spacing:.1em">Recent periodic summaries (last 10)</h3>
  <table style="margin-top:0.5rem">
    <thead><tr><th>Time</th><th>Pass</th><th>Fail</th><th>Pass %</th><th>Events</th><th>Dropped</th></tr></thead>
    <tbody>{recent_rows or '<tr><td colspan=6 style="color:#b39acb">No summaries yet</td></tr>'}</tbody>
  </table>
</div>"""


def _severity_badge(severity: str) -> str:
    """Return an HTML badge span for a severity string."""
    sev = str(severity).upper()
    colors = {
        "CRITICAL": ("#ec4899", "#fff"),
        "HIGH": ("#d946ef", "#fff"),
        "MEDIUM": ("#c084fc", "#13091f"),
        "LOW": ("#60a5fa", "#081121"),
        "INFO": ("#c4b5fd", "#13091f"),
    }
    bg, fg = colors.get(sev, ("#5b2e7e", "#fff"))
    return (
        f'<span style="background:{bg};color:{fg};padding:2px 8px;'
        f'border-radius:999px;font-size:0.72rem;font-weight:700;'
        f'letter-spacing:0.05em;white-space:nowrap">'
        f"{html.escape(sev)}</span>"
    )


def render_dashboard_html(state: Mapping[str, Any]) -> str:
    summary = state.get("summary", {})
    severity_counts = state.get("severity_counts", {})
    test_mode = state.get("test_mode") or {}
    generated_at = str(state.get("generated_at", ""))

    # — stat cards row —
    stat_cards = [
        ("Total Events", str(summary.get("db_events", 0)), "#c4b5fd", "⬡"),
        ("Incidents", str(summary.get("dashboard_incidents", 0)), "#d946ef", "⚡"),
        ("Blocked", str(summary.get("blocked_actions", 0)), "#f472b6", "🛡"),
        ("Unique Attackers", str(summary.get("unique_attackers", 0)), "#818cf8", "👤"),
        ("Last Hour", str(summary.get("last_hour_incidents", 0)), "#67e8f9", "⏱"),
    ]
    stat_html = "".join(
        f"""<div class="stat-card">
  <div class="stat-icon" style="color:{color}">{icon}</div>
  <div class="stat-value" style="color:{color}">{html.escape(val)}</div>
  <div class="stat-label">{html.escape(label)}</div>
</div>"""
        for label, val, color, icon in stat_cards
    )

    # — severity breakdown —
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
    sev_rows = ""
    for sev in sev_order:
        cnt = severity_counts.get(sev, 0)
        if cnt:
            sev_rows += (
                f"<tr><td>{_severity_badge(sev)}</td>"
                f"<td style='text-align:right;font-weight:600'>{html.escape(str(cnt))}</td></tr>"
            )
    if not sev_rows:
        sev_rows = "<tr><td colspan=2 style='color:#b39acb'>No incidents yet</td></tr>"

    # — threat classes —
    threat_rows = "".join(
        f"<tr><td>{html.escape(str(row.get('name','?')))}</td>"
        f"<td style='text-align:right'>{html.escape(str(row.get('count',0)))}</td></tr>"
        for row in state.get("top_threat_classes", [])
    ) or "<tr><td colspan=2 style='color:#b39acb'>None</td></tr>"

    # — MITRE techniques —
    mitre_rows = "".join(
        f"<tr><td><code style='font-size:0.78rem'>{html.escape(str(row.get('name','?')))}</code></td>"
        f"<td style='text-align:right'>{html.escape(str(row.get('count',0)))}</td></tr>"
        for row in state.get("top_mitre_techniques", [])
    ) or "<tr><td colspan=2 style='color:#b39acb'>None</td></tr>"

    # — incident rows —
    incident_rows = []
    for incident in state.get("incidents", []):
        mitre_attack = incident.get("mitre_attack") or []
        mitre_summary = ", ".join(
            f"{item.get('technique_id', '?')} {item.get('technique', '?')}"
            for item in mitre_attack
            if isinstance(item, Mapping)
        ) or "—"
        sev = str(incident.get("severity", "UNKNOWN"))
        incident_rows.append(
            "<tr>"
            f"<td style='font-size:0.78rem;white-space:nowrap'>{html.escape(str(incident.get('timestamp','n/a')))}</td>"
            f"<td>{_severity_badge(sev)}</td>"
            f"<td style='font-size:0.82rem'>{html.escape(str(incident.get('threat_class','?')))}</td>"
            f"<td style='font-size:0.82rem'>{html.escape(str(incident.get('attacker_identity','?')))}</td>"
            f"<td style='font-size:0.75rem;color:#d7b4ff'>{html.escape(mitre_summary)}</td>"
            f"<td style='font-size:0.8rem;font-weight:600'>{html.escape(str(incident.get('action_taken','NONE')))}</td>"
            f"<td style='font-size:0.78rem;color:#f4eaff'>{html.escape(str(incident.get('summary','')))}</td>"
            "</tr>"
        )

    incidents_body = "".join(incident_rows) or (
        "<tr><td colspan=7 style='color:#b39acb;text-align:center;padding:1.5rem'>"
        "No incidents recorded yet</td></tr>"
    )

    # — timeline mini-chart —
    timeline_data = state.get("timeline", [])
    if timeline_data:
        max_cnt = max((row.get("count", 0) for row in timeline_data), default=1) or 1
        tl_bars = "".join(
            f"""<div class="tl-bar-wrap" title="{html.escape(str(row.get('minute','')))} — {html.escape(str(row.get('count',0)))} incidents">
  <div class="tl-bar" style="height:{max(4, int(row.get('count',0)/max_cnt*80))}px"></div>
  <div class="tl-cnt">{html.escape(str(row.get('count',0)))}</div>
</div>"""
            for row in timeline_data[-30:]
        )
        timeline_section = f"""<section class="card">
  <h2 class="card-title">Activity Timeline <span class="badge">last 60 min</span></h2>
  <div class="tl-chart">{tl_bars}</div>
</section>"""
    else:
        timeline_section = """<section class="card">
  <h2 class="card-title">Activity Timeline</h2>
  <p style="color:#b39acb;margin:0">No recent activity</p>
</section>"""

    # — allowlist —
    allowlist_items = "".join(
        f"<li>{html.escape(str(e))}</li>" for e in state.get("allowlist", [])
    ) or "<li style='color:#b39acb'>Empty</li>"

    # — test mode panel —
    test_panel = _render_test_mode_panel(test_mode)

    # — paths —
    db_path = html.escape(str(state.get("paths", {}).get("db_path", "n/a")))
    jsonl_path = html.escape(str(state.get("paths", {}).get("live_monitor_jsonl_path", "n/a")))

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Bifrost \u2014 Heimdall Dashboard</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    :root {{
      --bg: #0b0314;
      --surface: #160824;
      --surface2: #221038;
      --border: #5b2e7e;
      --text: #f4eaff;
      --text-dim: #b39acb;
      --accent: #a855f7;
      --accent2: #d946ef;
      --red: #f472b6;
      --orange: #f9a8d4;
      --yellow: #fbcfe8;
      --green: #67e8f9;
      --teal: #818cf8;
    }}
    html {{ font-size: 15px; }}
    body {{
      font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }}

    /* ── Header ── */
    .header {{
      background: linear-gradient(135deg, #210a33 0%, #341058 50%, #1a0930 100%);
      border-bottom: 1px solid var(--border);
      padding: 0 1.75rem;
      display: flex;
      align-items: center;
      gap: 1rem;
      height: 62px;
    }}
    .logo {{
      font-size: 1.25rem;
      font-weight: 800;
      letter-spacing: -0.02em;
      background: linear-gradient(90deg, #c4b5fd, #d946ef, #f472b6, #818cf8);
      background-size: 200%;
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      animation: shimmer 4s linear infinite;
    }}
    @keyframes shimmer {{ to {{ background-position: -200%; }} }}
    .logo-sub {{
      font-size: 0.72rem;
      color: var(--text-dim);
      letter-spacing: 0.12em;
      text-transform: uppercase;
      margin-left: 0.25rem;
    }}
    .header-spacer {{ flex: 1; }}
    .live-dot {{
      width: 8px; height: 8px;
      border-radius: 50%;
      background: var(--green);
      box-shadow: 0 0 8px var(--green);
      animation: pulse 2s ease-in-out infinite;
    }}
    @keyframes pulse {{
      0%, 100% {{ opacity: 1; box-shadow: 0 0 8px var(--green); }}
      50% {{ opacity: 0.55; box-shadow: 0 0 3px var(--green); }}
    }}
    .live-label {{ font-size: 0.72rem; color: var(--green); font-weight: 600; letter-spacing: 0.06em; }}
    .ts {{ font-size: 0.72rem; color: var(--text-dim); }}
    .refresh-btn {{
      background: var(--surface2);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 5px 14px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 0.78rem;
      transition: border-color .2s;
    }}
    .refresh-btn:hover {{ border-color: var(--accent); color: #fff; }}
    .auto-toggle {{ font-size: 0.75rem; color: var(--text-dim); display: flex; align-items: center; gap: 5px; }}
    .auto-toggle input {{ accent-color: var(--accent); }}

    /* ── Layout ── */
    .main {{ padding: 1.5rem 1.75rem; flex: 1; }}

    /* ── Stat cards ── */
    .stat-row {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 1rem;
      margin-bottom: 1.5rem;
    }}
    .stat-card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1rem 1.25rem;
      display: flex;
      flex-direction: column;
      gap: 0.25rem;
      transition: border-color .2s, transform .15s;
    }}
    .stat-card:hover {{ border-color: var(--accent); transform: translateY(-2px); }}
    .stat-icon {{ font-size: 1.4rem; line-height: 1; }}
    .stat-value {{ font-size: 2rem; font-weight: 800; line-height: 1; letter-spacing: -0.03em; }}
    .stat-label {{ font-size: 0.72rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.08em; }}

    /* ── Grid / cards ── */
    .grid-2 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1rem; margin-bottom: 1rem; }}
    .grid-3 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1rem; margin-bottom: 1rem; }}
    .card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.1rem 1.25rem;
      margin-bottom: 1rem;
    }}
    .card-title {{
      font-size: 0.82rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: #d7b4ff;
      margin-bottom: 0.85rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}
    .badge {{
      background: #33144f;
      color: #f9a8d4;
      font-size: 0.65rem;
      padding: 2px 7px;
      border-radius: 999px;
      font-weight: 600;
      text-transform: none;
      letter-spacing: 0.04em;
    }}

    /* ── Tables ── */
    table {{ width: 100%; border-collapse: collapse; font-size: 0.82rem; }}
    th {{
      font-size: 0.7rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: var(--text-dim);
      padding: 0.5rem 0.5rem;
      border-bottom: 1px solid var(--border);
      text-align: left;
    }}
    td {{
      padding: 0.55rem 0.5rem;
      border-bottom: 1px solid #0f1e34;
      vertical-align: top;
    }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: rgba(217,70,239,0.08); }}

    /* ── Timeline chart ── */
    .tl-chart {{
      display: flex;
      align-items: flex-end;
      gap: 3px;
      height: 90px;
      overflow-x: auto;
      padding-bottom: 0.25rem;
    }}
    .tl-bar-wrap {{
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 2px;
      min-width: 18px;
    }}
    .tl-bar {{
      width: 14px;
      background: linear-gradient(180deg, #d946ef, #818cf8);
      border-radius: 3px 3px 0 0;
      transition: height .3s;
    }}
    .tl-cnt {{ font-size: 0.6rem; color: var(--text-dim); }}

    /* ── Paths row ── */
    .paths-row {{ font-size: 0.72rem; color: var(--text-dim); margin-bottom: 1.25rem; }}
    .paths-row code {{ color: #f9a8d4; background: #210a33; padding: 1px 5px; border-radius: 4px; }}

    ul {{ padding-left: 1.2rem; }}
    li {{ font-size: 0.82rem; padding: 0.2rem 0; }}
    code {{ color: #f9a8d4; font-size: 0.82rem; }}

    /* ── Incidents table ── */
    .incidents-wrap {{ overflow-x: auto; }}

    /* ── Scrollbar ── */
    ::-webkit-scrollbar {{ width: 6px; height: 6px; }}
    ::-webkit-scrollbar-track {{ background: var(--bg); }}
    ::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 3px; }}
  </style>
</head>
<body>
<header class="header">
  <div>
    <span class="logo">⬡ Bifrost</span>
    <span class="logo-sub">Heimdall Dashboard</span>
  </div>
  <div class="header-spacer"></div>
  <div class="live-dot"></div>
  <span class="live-label">LIVE</span>
  <span class="ts">{html.escape(generated_at)}</span>
  <button class="refresh-btn" type="button" onclick="window.location.reload()">↺ Refresh</button>
  <label class="auto-toggle">
    <input id="auto-refresh" type="checkbox" checked aria-label="Toggle automatic refresh">
    Auto 5s
  </label>
</header>

<main class="main">
  <div class="paths-row">
    DB: <code>{db_path}</code> &nbsp;·&nbsp; JSONL: <code>{jsonl_path}</code>
  </div>

  <!-- Stat cards -->
  <div class="stat-row">{stat_html}</div>

  <!-- Test-mode panel -->
  {test_panel}

  <!-- Middle grid: severity + threats + MITRE -->
  <div class="grid-3">
    <div class="card">
      <h2 class="card-title">Severity Breakdown</h2>
      <table>
        <thead><tr><th>Level</th><th style="text-align:right">Count</th></tr></thead>
        <tbody>{sev_rows}</tbody>
      </table>
    </div>
    <div class="card">
      <h2 class="card-title">Top Threat Classes</h2>
      <table>
        <thead><tr><th>Class</th><th style="text-align:right">Hits</th></tr></thead>
        <tbody>{threat_rows}</tbody>
      </table>
    </div>
    <div class="card">
      <h2 class="card-title">Top MITRE Techniques</h2>
      <table>
        <thead><tr><th>Technique</th><th style="text-align:right">Hits</th></tr></thead>
        <tbody>{mitre_rows}</tbody>
      </table>
    </div>
  </div>

  <!-- Timeline -->
  {timeline_section}

  <!-- Recent Incidents -->
  <div class="card">
    <h2 class="card-title">Recent Incidents <span class="badge">last 50</span></h2>
    <div class="incidents-wrap">
      <table>
        <thead>
          <tr>
            <th>Timestamp</th><th>Severity</th><th>Threat</th><th>Attacker</th>
            <th>MITRE</th><th>Action</th><th>Summary</th>
          </tr>
        </thead>
        <tbody>{incidents_body}</tbody>
      </table>
    </div>
  </div>

  <!-- Allowlist -->
  <div class="card">
    <h2 class="card-title">Monitor Allowlist</h2>
    <ul>{allowlist_items}</ul>
  </div>
</main>

<script>
(function() {{
  var refreshTimer = null;
  function scheduleRefresh() {{
    clearTimeout(refreshTimer);
    var toggle = document.getElementById('auto-refresh');
    if (toggle && toggle.checked) {{
      refreshTimer = setTimeout(function() {{ window.location.reload(); }}, 5000);
    }}
  }}
  var toggle = document.getElementById('auto-refresh');
  if (toggle) {{
    toggle.addEventListener('change', scheduleRefresh);
  }}
  scheduleRefresh();
}})();
</script>
</body>
</html>"""


def _build_handler(server: "DashboardServer"):
    class DashboardHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            state = server.build_state()
            if self.path in {"/healthz", "/health"}:
                self._write_json({"ok": True, "generated_at": state["generated_at"]})
                return
            if self.path == "/api/state":
                self._write_json(state)
                return
            if self.path == "/api/summary":
                tm = state.get("test_mode") or {}
                payload: dict[str, Any] = {
                    "active": tm.get("active", False),
                    "latest_summary": tm.get("latest_summary") or {},
                }
                self._write_json(payload)
                return
            if self.path not in {"/", ""}:
                self.send_error(HTTPStatus.NOT_FOUND, "Not found")
                return
            payload_html = render_dashboard_html(state).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload_html)))
            self.end_headers()
            self.wfile.write(payload_html)

        def log_message(self, fmt: str, *args: Any) -> None:
            server.log.debug("dashboard %s - %s", self.address_string(), fmt % args)

        def _write_json(self, payload: Mapping[str, Any]) -> None:
            encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
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

    def build_state(self) -> dict[str, Any]:
        return build_dashboard_state(
            db_path=self.db_path,
            live_monitor_jsonl_path=self.jsonl_path,
            monitor_safelist=self.monitor_safelist,
            incident_limit=self.incident_limit,
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
