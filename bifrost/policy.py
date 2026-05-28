#!/usr/bin/env python3
"""
Bifrost Policy Gate v0.1.0

The safety governor. Every decision from Heimdall
passes through here before reaching the executor.

No action reaches the executor without passing:
  - Mode check (learning / dry-run / autonomous)
  - Confidence threshold check
  - Evidence count check for destructive actions
  - Protected target check (PIDs, processes, RFC1918)

This is the last line of defense before system impact.
Safe by default. Always.
"""

from __future__ import annotations
import ipaddress
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

log = logging.getLogger("heimdall.policy")


# ── Action types (mirror schema for standalone use) ──────────────────

class ActionType(str, Enum):
    KILL       = "KILL"
    BLOCK      = "BLOCK"
    QUARANTINE = "QUARANTINE"
    ALERT      = "ALERT"
    LOG        = "LOG"
    NONE       = "NONE"


DESTRUCTIVE = {ActionType.KILL, ActionType.BLOCK, ActionType.QUARANTINE}


# ── Decision input to policy gate ────────────────────────────────────

@dataclass
class Decision:
    action:               ActionType
    confidence:           float
    reason:               str
    pid:                  Optional[int]   = None
    process_name:         Optional[str]   = None
    destination_ip:       Optional[str]   = None
    is_system_process:    bool            = False
    evidence_count:       int             = 1
    event_window_seconds: int             = 60


# ── Policy gate result ───────────────────────────────────────────────

@dataclass
class PolicyResult:
    allowed:           bool
    downgraded_action: ActionType
    rationale:         str
    original_action:   ActionType = ActionType.NONE


# ── Safe defaults ────────────────────────────────────────────────────

SAFE_DEFAULTS = {
    "learning_mode":                      True,
    "dry_run":                            True,
    "autonomous_enabled":                 False,
    "confidence_threshold":               0.85,
    "min_repeated_evidence_for_destructive": 2,
    "never_block_rfc1918":                True,
    "protected_pids_max":                 100,
    "protected_process_names": [
        "systemd", "init", "sshd", "dockerd",
        "python3", "journald", "auditd",
        "NetworkManager", "wpa_supplicant",
        "kthreadd", "kworker"
    ],
}


def _is_rfc1918(ip_str: str) -> bool:
    """Returns True if IP is in private RFC1918 space."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private
    except ValueError:
        return False


def evaluate_policy(
    decision: Decision,
    learning_mode: bool                        = True,
    dry_run: bool                              = True,
    autonomous_enabled: bool                   = False,
    confidence_threshold: float                = 0.85,
    min_repeated_evidence_for_destructive: int = 2,
    never_block_rfc1918: bool                  = True,
    protected_pids_max: int                    = 100,
    protected_process_names: list              = None,
) -> PolicyResult:
    """
    Evaluates a Heimdall decision against policy gates.

    Returns a PolicyResult with:
      - allowed: whether the action may proceed
      - downgraded_action: what will actually happen
      - rationale: human-readable explanation

    Gates run in priority order. First gate that fires
    blocks the action and returns immediately.
    """

    if protected_process_names is None:
        protected_process_names = SAFE_DEFAULTS["protected_process_names"]

    original = decision.action

    # Non-destructive actions always pass
    if original not in DESTRUCTIVE:
        return PolicyResult(
            allowed=True,
            downgraded_action=original,
            rationale="Non-destructive action — always allowed.",
            original_action=original,
        )

    # Gate 1 — Mode check
    # Learning mode, dry run, or autonomous disabled
    # all block destructive actions
    if learning_mode:
        return PolicyResult(
            allowed=False,
            downgraded_action=ActionType.ALERT,
            rationale=(
                "Enforcement disabled by safe mode "
                "(learning/dry-run/autonomous flag). "
                f"Would have: {original.value}."
            ),
            original_action=original,
        )

    if dry_run:
        return PolicyResult(
            allowed=False,
            downgraded_action=ActionType.ALERT,
            rationale=(
                "Enforcement disabled by safe mode "
                "(learning/dry-run/autonomous flag). "
                f"Would have: {original.value}."
            ),
            original_action=original,
        )

    if not autonomous_enabled:
        return PolicyResult(
            allowed=False,
            downgraded_action=ActionType.ALERT,
            rationale=(
                "Enforcement disabled by safe mode "
                "(learning/dry-run/autonomous flag). "
                f"Would have: {original.value}."
            ),
            original_action=original,
        )

    # Gate 2 — Confidence threshold
    if decision.confidence < confidence_threshold:
        return PolicyResult(
            allowed=False,
            downgraded_action=ActionType.ALERT,
            rationale=(
                f"Confidence {decision.confidence:.2f} "
                f"below required threshold {confidence_threshold:.2f}."
            ),
            original_action=original,
        )

    # Gate 3 — Evidence count for destructive actions
    if decision.evidence_count < min_repeated_evidence_for_destructive:
        return PolicyResult(
            allowed=False,
            downgraded_action=ActionType.ALERT,
            rationale=(
                f"Insufficient repeated evidence: "
                f"got {decision.evidence_count}, "
                f"need {min_repeated_evidence_for_destructive} "
                f"for destructive action."
            ),
            original_action=original,
        )

    # Gate 4 — Protected PID check (KILL only)
    if original == ActionType.KILL:
        if decision.pid is not None and decision.pid <= protected_pids_max:
            return PolicyResult(
                allowed=False,
                downgraded_action=ActionType.ALERT,
                rationale=(
                    f"Protected PID: {decision.pid} is below "
                    f"minimum allowed PID {protected_pids_max}. "
                    f"Refusing KILL."
                ),
                original_action=original,
            )

        # Gate 5 — Protected process name check
        if decision.process_name in protected_process_names:
            return PolicyResult(
                allowed=False,
                downgraded_action=ActionType.ALERT,
                rationale=(
                    f"Protected process: {decision.process_name} "
                    f"is on the protected process list. "
                    f"Refusing KILL."
                ),
                original_action=original,
            )

        # Gate 6 — System process flag
        if decision.is_system_process:
            return PolicyResult(
                allowed=False,
                downgraded_action=ActionType.ALERT,
                rationale=(
                    "System process flag set. "
                    "Refusing KILL on system process."
                ),
                original_action=original,
            )

    # Gate 7 — RFC1918 protection (BLOCK only)
    if original == ActionType.BLOCK and never_block_rfc1918:
        if decision.destination_ip and _is_rfc1918(decision.destination_ip):
            return PolicyResult(
                allowed=False,
                downgraded_action=ActionType.ALERT,
                rationale=(
                    f"Protected RFC1918 target: {decision.destination_ip}. "
                    f"Never block private IP ranges."
                ),
                original_action=original,
            )

    # All gates passed
    log.warning(
        f"Policy ALLOW: action={original.value} "
        f"confidence={decision.confidence:.2f} "
        f"evidence={decision.evidence_count} "
        f"target_pid={decision.pid} "
        f"target_ip={decision.destination_ip}"
    )

    return PolicyResult(
        allowed=True,
        downgraded_action=original,
        rationale=f"Allowed by policy: all gates passed.",
        original_action=original,
    )


def evaluate_with_precheck(
    decision: Decision,
    learning_mode: bool      = True,
    dry_run: bool            = True,
    autonomous_enabled: bool = False,
) -> tuple:
    """
    Convenience wrapper used by the demo script.
    Returns (PolicyResult, notes_list).
    """
    notes = []

    if learning_mode:
        notes.append("learning_mode=true")
    if dry_run:
        notes.append("dry_run=true")
    if not autonomous_enabled:
        notes.append("autonomous_enabled=false")

    result = evaluate_policy(
        decision,
        learning_mode=learning_mode,
        dry_run=dry_run,
        autonomous_enabled=autonomous_enabled,
    )

    return result, notes
