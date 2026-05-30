#!/usr/bin/env python3
"""Bifrost Demo v0.1.0 — dry-run replay demo."""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from bifrost.policy import ActionType, Decision, evaluate_policy

BANNER = """
╔══════════════════════════════════════════════════════════╗
║         BIFROST SECURITY PLATFORM — DEMO                 ║
║         Dry Run Mode — No Enforcement                    ║
║                                                          ║
║  learning_mode=true  dry_run=true  autonomous=false      ║
║  All actions are simulated. Nothing is enforced.         ║
╚══════════════════════════════════════════════════════════╝
"""

SEV_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[93m",
    "MEDIUM": "\033[94m",
    "LOW": "\033[92m",
    "INFO": "\033[90m",
}
RESET = "\033[0m"
BOLD = "\033[1m"


def now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def colorize(text, severity):
    return f"{SEV_COLORS.get(severity, '')}{text}{RESET}"


def simple_detect(event):
    et = event.get("type", "unknown")
    sev = float(event.get("severity", 0.2))
    dest_ip = event.get("dest_ip")
    pid = event.get("pid")
    proc = event.get("process_name")
    is_sys = bool(event.get("is_system_process", False))
    evidence = int(event.get("evidence_count", 1))

    if et == "port_scan":
        action, conf = ActionType.BLOCK, max(0.75, sev)
        reason = "Port-scan pattern — systematic connection probing"
    elif et == "suspicious_spawn":
        action, conf = ActionType.KILL, max(0.85, sev)
        reason = "Suspicious process spawn — possible dropper execution"
    elif et == "benign_web":
        action, conf = ActionType.LOG, min(0.3, sev)
        reason = "Normal web traffic — no threat indicators"
    elif et == "brute_force_ssh":
        action, conf = ActionType.ALERT, max(0.65, sev)
        reason = "SSH credential brute force — honeypot zone (expected noise; no host action)"
    elif et == "scratch_space_exec":
        action, conf = ActionType.KILL, max(0.90, sev)
        reason = "Execve from scratch space (/tmp) — high-confidence dropper execution"
    elif et == "systemd_persistence":
        action, conf = ActionType.ALERT, max(0.82, sev)
        reason = "Systemd unit file written — possible persistence installation"
    elif et == "credential_theft_chain":
        action, conf = ActionType.BLOCK, max(0.92, sev)
        reason = "Credential theft chain — /etc/passwd read + outbound exfil detected"
    elif et == "container_breakout":
        action, conf = ActionType.KILL, max(0.97, sev)
        reason = "Container namespace violation — host filesystem access from container"
    elif et == "suid_binary_created":
        action, conf = ActionType.QUARANTINE, max(0.88, sev)
        reason = "SUID binary created in /tmp — privilege escalation staging"
    elif et == "dependency_down":
        action, conf = ActionType.LOG, min(0.4, sev)
        reason = "Inference endpoint unreachable — safe degradation mode active"
    else:
        action, conf = ActionType.ALERT, min(0.6, sev)
        reason = "Unknown event type — escalating for review"

    return Decision(
        action=action,
        confidence=conf,
        reason=reason,
        pid=pid,
        process_name=proc,
        destination_ip=dest_ip,
        is_system_process=is_sys,
        evidence_count=evidence,
        event_window_seconds=60,
    )


def run_demo(scenario_path, out_log, use_color=True):
    out_log.parent.mkdir(parents=True, exist_ok=True)
    print(BANNER)
    print(f"  Scenario : {scenario_path.name}")
    print(f"  Audit log: {out_log}")
    print()

    lines = [line for line in scenario_path.read_text().splitlines() if line.strip()]
    total = len(lines)
    incidents = 0
    blocked = 0

    print(f"{'─' * 70}")

    with out_log.open("a", encoding="utf-8") as logf:
        for i, raw in enumerate(lines, 1):
            try:
                event = json.loads(raw)
            except json.JSONDecodeError as je:
                print(f"  [!] Skipping malformed line: {je}")
                continue
            event_id = event.get("event_id", str(uuid.uuid4()))
            event_type = event.get("type", "unknown")
            note = event.get("note", "")

            decision = simple_detect(event)
            policy_result = evaluate_policy(
                decision,
                learning_mode=True,
                dry_run=True,
                autonomous_enabled=False,
            )

            conf = decision.confidence
            if conf >= 0.90:
                severity = "CRITICAL"
            elif conf >= 0.75:
                severity = "HIGH"
            elif conf >= 0.50:
                severity = "MEDIUM"
            elif conf >= 0.25:
                severity = "LOW"
            else:
                severity = "INFO"

            if decision.action in (ActionType.KILL, ActionType.BLOCK, ActionType.QUARANTINE):
                incidents += 1
            if not policy_result.allowed:
                blocked += 1

            sev_str = colorize(f"[{severity}]", severity) if use_color else f"[{severity}]"
            print(f"Event {i}/{total}  {sev_str}  {event_type}  id={event_id}")
            if note:
                print(f"  Note     : {note}")
            bold_on = BOLD if use_color else ""
            bold_off = RESET if use_color else ""
            print(f"  Requested: {bold_on}{decision.action.value}{bold_off}  confidence={conf:.0%}")
            print(f"  Effective: {policy_result.downgraded_action.value}  allowed={policy_result.allowed}")
            print(f"  Reason   : {decision.reason[:80]}")
            print(f"  Policy   : {policy_result.rationale[:60]}")
            print(f"{'─' * 70}")

            record = {
                "ts": now_iso(),
                "event_id": event_id,
                "event_type": event_type,
                "action_requested": decision.action.value,
                "action_effective": policy_result.downgraded_action.value,
                "allowed": policy_result.allowed,
                "confidence": round(conf, 3),
                "severity": severity,
                "reason": decision.reason,
                "policy_rationale": policy_result.rationale,
                "rollback_id": None,
                "note": note,
            }
            logf.write(json.dumps(record) + "\n")

    print()
    print(f"{'═' * 70}")
    print(f"  SUMMARY — {scenario_path.name}")
    print(f"{'─' * 70}")
    print(f"  Events processed : {total}")
    print(f"  Incidents flagged: {incidents}")
    print(f"  Actions proposed : {incidents}")
    print(f"  Actions taken    : 0  (dry_run=True)")
    print(f"  Policy blocked   : {blocked}")
    print(f"  Audit log        : {out_log}")
    print(f"{'═' * 70}")
    print()
    print("  Safe mode active. No changes were made to your system.")
    print()


def main():
    ap = argparse.ArgumentParser(description="Bifrost dry-run demo")
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--out", default="logs/decision_audit.jsonl")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    scenario = Path(args.scenario)
    if not scenario.exists():
        print(f"[!] Scenario not found: {scenario}")
        for replay_file in sorted(Path("examples/replay").glob("*.jsonl")):
            print(f"    {replay_file}")
        sys.exit(1)

    run_demo(scenario, Path(args.out), use_color=not args.no_color)


if __name__ == "__main__":
    main()
