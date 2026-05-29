#!/usr/bin/env python3
"""
Gjallarhorn Dashboard v0.1.1

Minimal web dashboard for Bifrost.
Localhost only. Auto-refreshes every 10 seconds.
Pure Python stdlib. XSS-safe. Clean DB handling.
"""

from __future__ import annotations
import html
import json
import logging
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from bifrost.paths import db_path as resolve_db_path

log = logging.getLogger("heimdall.dashboard")
DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 8080


def _query(sql: str, params: tuple = ()) -> list:
    if not resolve_db_path().exists():
        return []
    try:
        with sqlite3.connect(str(resolve_db_path())) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(sql, params)
            return [dict(r) for r in cursor.fetchall()]
    except Exception as e:
        log.error(f"Dashboard DB error: {e}")
        return []


def get_stats() -> dict:
    if not resolve_db_path().exists():
        return {}
    try:
        with sqlite3.connect(str(resolve_db_path())) as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM events")
            total = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM events WHERE boundary='HONEYPOT'")
            honeypot = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM events WHERE boundary='HOST'")
            host = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM actions")
            actions = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM events WHERE false_positive=1")
            fp = c.fetchone()[0]
        return {
            "total_events": total,
            "honeypot_events": honeypot,
            "host_events": host,
            "actions_taken": actions,
            "false_positives": fp,
        }
    except Exception as e:
        log.error(f"Stats error: {e}")
        return {}


def get_decisions(limit: int = 20) -> list:
    return _query("""
        SELECT
            e.timestamp,
            e.source,
            e.boundary,
            e.action_taken,
            json_extract(e.heimdall_decision, "$.severity") as severity,
            json_extract(e.heimdall_decision, "$.threat_class") as threat_class,
            json_extract(e.heimdall_decision, "$.confidence") as confidence,
            json_extract(e.heimdall_decision, "$.reasoning") as reasoning,
            json_extract(e.heimdall_decision, "$.action_effective") as action_effective,
            json_extract(e.heimdall_decision, "$.policy_rationale") as policy_rationale
        FROM events e
        WHERE e.heimdall_decision IS NOT NULL
        ORDER BY e.created_at DESC
        LIMIT ?
    """, (limit,))


def get_actions(limit: int = 10) -> list:
    return _query("""
        SELECT executed_at, action_type, target, success, rolled_back
        FROM actions
        ORDER BY executed_at DESC
        LIMIT ?
    """, (limit,))


def e(val) -> str:
    """HTML-escape a value safely."""
    return html.escape(str(val or ""))


HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="10">
<title>Heimdall</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#080808;color:#C8C0C0;font-family:monospace;padding:20px}}
h1{{color:#7B5EA7;margin-bottom:5px}}
h2{{color:#C4607A;margin:20px 0 8px}}
.mode{{background:#1a1a1a;border-left:3px solid #C4607A;padding:6px 12px;margin-bottom:15px;font-size:0.9em}}
.stats{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:10px}}
.stat{{background:#111;border:1px solid #7B5EA7;padding:12px 18px;min-width:120px}}
.stat-label{{font-size:0.75em;color:#888}}
.stat-val{{font-size:1.8em;color:#C4607A;font-weight:bold}}
table{{width:100%;border-collapse:collapse}}
th{{background:#111;color:#7B5EA7;padding:7px;text-align:left;font-size:0.8em}}
td{{padding:5px 7px;border-bottom:1px solid #141414;font-size:0.78em;vertical-align:top}}
.CRITICAL{{color:#ff4444;font-weight:bold}}
.HIGH{{color:#ff8800}}
.MEDIUM{{color:#ffcc00}}
.LOW{{color:#88cc88}}
.INFO{{color:#666}}
</style>
</head>
<body>
<h1>Heimdall Guardian</h1>
<div class="mode">Mode: {mode_str} &nbsp;|&nbsp; Auto-refresh: 10s</div>
<h2>System Stats</h2>
<div class="stats">
  <div class="stat"><div class="stat-label">Total Events</div>
    <div class="stat-val">{total_events}</div></div>
  <div class="stat"><div class="stat-label">Host Events</div>
    <div class="stat-val">{host_events}</div></div>
  <div class="stat"><div class="stat-label">Honeypot</div>
    <div class="stat-val">{honeypot_events}</div></div>
  <div class="stat"><div class="stat-label">Actions</div>
    <div class="stat-val">{actions_taken}</div></div>
  <div class="stat"><div class="stat-label">False Pos</div>
    <div class="stat-val">{false_positives}</div></div>
</div>
<h2>Recent Actions</h2>
<table>
<tr><th>Time</th><th>Action</th><th>Target</th>
    <th>Success</th><th>Rolled Back</th></tr>
{action_rows}
</table>
<h2>Recent Decisions</h2>
<table>
<tr><th>Time</th><th>Source</th><th>Boundary</th><th>Severity</th>
    <th>Threat</th><th>Conf</th><th>Requested</th><th>Effective</th>
    <th>Reasoning</th><th>Policy</th></tr>
{decision_rows}
</table>
</body>
</html>"""


class DashboardHandler(BaseHTTPRequestHandler):

    brain_ref = None
    api_token = None

    def log_message(self, format, *args):
        pass

    def _check_token(self) -> bool:
        if not self.api_token:
            return True
        token = self.headers.get("X-Bifrost-Token", "")
        return token == self.api_token

    def do_GET(self):
        if self.path.startswith("/api/"):
            if not self._check_token():
                self.send_response(401)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self._set_common_headers()
                self.end_headers()
                self.wfile.write(b'{"error":"unauthorized"}')
                return

        if self.path == "/api/stats":
            self._json(get_stats())
            return
        if self.path == "/api/decisions":
            self._json(get_decisions())
            return
        if self.path == "/api/actions":
            self._json(get_actions())
            return
        if self.path == "/health":
            self._json({"status": "ok", "component": "bifrost_dashboard"})
            return

        self._serve_html()

    def _serve_html(self):
        stats = get_stats()
        decisions = get_decisions()
        actions = get_actions()

        mode_parts = []
        if self.brain_ref:
            s = self.brain_ref.get_status()
            if s.get("learning_mode"):
                mode_parts.append("LEARNING")
            if s.get("dry_run"):
                mode_parts.append("DRY RUN")
            if not s.get("autonomous_enabled"):
                mode_parts.append("AUTONOMOUS DISABLED")
        mode_str = " | ".join(mode_parts) if mode_parts else "UNKNOWN"

        action_rows = ""
        for a in actions:
            action_rows += (
                f"<tr>"
                f"<td>{e(a.get('executed_at'))}</td>"
                f"<td>{e(a.get('action_type'))}</td>"
                f"<td>{e(a.get('target'))}</td>"
                f"<td>{'Yes' if a.get('success') else 'No'}</td>"
                f"<td>{'Yes' if a.get('rolled_back') else 'No'}</td>"
                f"</tr>"
            )
        if not action_rows:
            action_rows = "<tr><td colspan=5>No actions yet</td></tr>"

        decision_rows = ""
        for d in decisions:
            sev = d.get("severity") or "INFO"
            conf = d.get("confidence") or 0
            try:
                conf_str = f"{float(conf):.0%}"
            except Exception:
                conf_str = "N/A"
            decision_rows += (
                f"<tr>"
                f"<td>{e(d.get('timestamp'))}</td>"
                f"<td>{e(d.get('source'))}</td>"
                f"<td>{e(d.get('boundary'))}</td>"
                f"<td class='{e(sev)}'>{e(sev)}</td>"
                f"<td>{e(d.get('threat_class'))}</td>"
                f"<td>{conf_str}</td>"
                f"<td>{e(d.get('action_taken'))}</td>"
                f"<td>{e(d.get('action_effective'))}</td>"
                f"<td>{e(str(d.get('reasoning',''))[:80])}</td>"
                f"<td>{e(str(d.get('policy_rationale',''))[:60])}</td>"
                f"</tr>"
            )
        if not decision_rows:
            decision_rows = (
                "<tr><td colspan=10>No decisions yet</td></tr>"
            )

        html_out = HTML.format(
            mode_str=e(mode_str),
            total_events=stats.get("total_events", 0),
            host_events=stats.get("host_events", 0),
            honeypot_events=stats.get("honeypot_events", 0),
            actions_taken=stats.get("actions_taken", 0),
            false_positives=stats.get("false_positives", 0),
            action_rows=action_rows,
            decision_rows=decision_rows,
        )

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self._set_common_headers()
        self.end_headers()
        self.wfile.write(html_out.encode())

    def _set_common_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'"
        )
    def _json(self, data):
        payload = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self._set_common_headers()
        self.end_headers()
        self.wfile.write(payload)


class DashboardServer(threading.Thread):

    def __init__(self, config: dict, brain_ref=None):
        super().__init__(daemon=True, name="gjallarhorn.dashboard")
        self.config = config
        self.server = None
        DashboardHandler.brain_ref = brain_ref
        DashboardHandler.api_token = config.get("dashboard_api_token")

    def run(self):
        try:
            self.server = ThreadingThreadingHTTPServer(
                (DASHBOARD_HOST, DASHBOARD_PORT),
                DashboardHandler
            )
            log.info(
                f"Dashboard on http://{DASHBOARD_HOST}:{DASHBOARD_PORT}"
            )
            self.server.serve_forever()
        except Exception as e:
            log.error(f"Dashboard error: {e}")

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
