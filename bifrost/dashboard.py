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


def _load_incident_records(jsonl_path: Path) -> list[dict[str, Any]]:
    if not jsonl_path.exists():
        return []
    incidents: list[dict[str, Any]] = []
    for line in jsonl_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("record_type") != "incident":
            continue
        incident = dict(record)
        incident["_timestamp_dt"] = _parse_timestamp(record.get("timestamp"))
        incidents.append(incident)
    incidents.sort(
        key=lambda item: item.get("_timestamp_dt") or datetime.max.replace(tzinfo=timezone.utc)
    )
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
    incidents = _load_incident_records(jsonl_path)
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


def render_dashboard_html(state: Mapping[str, Any]) -> str:
    incidents = []
    for incident in state.get("incidents", []):
        mitre_attack = incident.get("mitre_attack") or []
        mitre_summary = ", ".join(
            f"{item.get('technique_id', 'UNKNOWN')} {item.get('technique', 'Unknown')}"
            for item in mitre_attack
            if isinstance(item, Mapping)
        ) or "n/a"
        incidents.append(
            "<tr>"
            f"<td>{html.escape(str(incident.get('timestamp', 'n/a')))}</td>"
            f"<td>{html.escape(str(incident.get('severity', 'UNKNOWN')))}</td>"
            f"<td>{html.escape(str(incident.get('threat_class', 'unknown')))}</td>"
            f"<td>{html.escape(str(incident.get('attacker_identity', 'unknown')))}</td>"
            f"<td>{html.escape(mitre_summary)}</td>"
            f"<td>{html.escape(str(incident.get('action_taken', 'NONE')))}</td>"
            f"<td>{html.escape(str(incident.get('summary', '')))}</td>"
            "</tr>"
        )

    timeline = "".join(
        f"<tr><td>{html.escape(str(row.get('minute')))}</td><td>{html.escape(str(row.get('count')))}</td></tr>"
        for row in state.get("timeline", [])
    )
    allowlist = "".join(
        f"<li>{html.escape(str(entry))}</li>" for entry in state.get("allowlist", [])
    )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Bifrost Dashboard</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 1.5rem; background: #0f172a; color: #e2e8f0; }}
    h1, h2 {{ color: #f8fafc; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 1rem; }}
    section {{ background: #111827; border: 1px solid #334155; border-radius: 8px; padding: 1rem; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid #334155; padding: 0.45rem; text-align: left; vertical-align: top; }}
    th {{ color: #93c5fd; }}
    code {{ color: #bfdbfe; }}
    ul {{ padding-left: 1.2rem; }}
  </style>
</head>
<body>
  <h1>Bifrost Live Dashboard</h1>
  <p>Generated at {html.escape(str(state.get("generated_at")))}</p>
  <p>
    <button type="button" onclick="window.location.reload()">Refresh now</button>
    <label style="margin-left:0.75rem;">
    <input id="auto-refresh" type="checkbox" checked aria-label="Toggle automatic dashboard refresh">
      Auto-refresh every 5s
    </label>
  </p>
  <p>DB: <code>{html.escape(str(state.get("paths", {}).get("db_path", "n/a")))}</code><br>
     JSONL: <code>{html.escape(str(state.get("paths", {}).get("live_monitor_jsonl_path", "n/a")))}</code></p>
  <div class="grid">
    {_render_key_values("Summary", state.get("summary", {}))}
    {_render_key_values("Severity Counts", state.get("severity_counts", {}))}
    <section><h2>Allowlist</h2><ul>{allowlist or '<li>Empty</li>'}</ul></section>
  </div>
  <div class="grid">
    {_render_ranked("Top Threat Classes", state.get("top_threat_classes", []))}
    {_render_ranked("Top MITRE Techniques", state.get("top_mitre_techniques", []))}
  </div>
  <section>
    <h2>Timeline (last 60 minutes)</h2>
    <table>
      <thead><tr><th>Minute</th><th>Incidents</th></tr></thead>
      <tbody>{timeline or '<tr><td colspan=2>No recent incidents</td></tr>'}</tbody>
    </table>
  </section>
  <section>
    <h2>Recent Incidents</h2>
    <table>
      <thead>
        <tr>
          <th>Timestamp</th><th>Severity</th><th>Threat</th><th>Attacker</th><th>MITRE</th><th>Action</th><th>Summary</th>
        </tr>
      </thead>
      <tbody>{''.join(incidents) or '<tr><td colspan=7>No incidents recorded yet</td></tr>'}</tbody>
    </table>
  </section>
  <script>
    setInterval(function () {{
      var toggle = document.getElementById('auto-refresh');
      if (toggle && toggle.checked) {{
        window.location.reload();
      }}
    }}, 5000);
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
            if self.path not in {"/", ""}:
                self.send_error(HTTPStatus.NOT_FOUND, "Not found")
                return
            payload = render_dashboard_html(state).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

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
