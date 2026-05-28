#!/usr/bin/env python3
"""
tests/test_policy_gate.py
Unit tests for Bifrost policy gate behavior.
Run: python -m pytest tests/test_policy_gate.py -v
"""
from bifrost.policy import (
    Decision,
    ActionType,
    evaluate_policy,
)


def mk_decision(
    action=ActionType.ALERT,
    confidence=0.9,
    pid=None,
    process_name=None,
    destination_ip=None,
    is_system_process=False,
    evidence_count=2,
):
    return Decision(
        action=action,
        confidence=confidence,
        reason="test",
        pid=pid,
        process_name=process_name,
        destination_ip=destination_ip,
        is_system_process=is_system_process,
        evidence_count=evidence_count,
        event_window_seconds=60,
    )


def test_safe_mode_blocks_enforcement_learning_mode():
    d = mk_decision(action=ActionType.KILL, confidence=0.99, evidence_count=3)
    r = evaluate_policy(d, learning_mode=True, dry_run=False, autonomous_enabled=True)
    assert r.allowed is False
    assert r.downgraded_action == ActionType.ALERT


def test_safe_mode_blocks_enforcement_dry_run():
    d = mk_decision(action=ActionType.BLOCK, confidence=0.99, evidence_count=3)
    r = evaluate_policy(d, learning_mode=False, dry_run=True, autonomous_enabled=True)
    assert r.allowed is False
    assert r.downgraded_action == ActionType.ALERT


def test_safe_mode_blocks_when_autonomous_disabled():
    d = mk_decision(action=ActionType.QUARANTINE, confidence=0.99, evidence_count=3)
    r = evaluate_policy(d, learning_mode=False, dry_run=False, autonomous_enabled=False)
    assert r.allowed is False
    assert r.downgraded_action == ActionType.ALERT


def test_confidence_threshold_blocks():
    d = mk_decision(action=ActionType.KILL, confidence=0.2, evidence_count=3)
    r = evaluate_policy(d, learning_mode=False, dry_run=False, autonomous_enabled=True)
    assert r.allowed is False
    assert r.downgraded_action == ActionType.ALERT
    assert "below required threshold" in r.rationale


def test_destructive_action_requires_repeated_evidence():
    d = mk_decision(action=ActionType.KILL, confidence=0.99, evidence_count=1)
    r = evaluate_policy(
        d,
        learning_mode=False,
        dry_run=False,
        autonomous_enabled=True,
        min_repeated_evidence_for_destructive=2,
    )
    assert r.allowed is False
    assert r.downgraded_action == ActionType.ALERT
    assert "Insufficient repeated evidence" in r.rationale


def test_protected_pid_blocked_for_kill():
    d = mk_decision(action=ActionType.KILL, confidence=0.99, pid=1, evidence_count=3)
    r = evaluate_policy(d, learning_mode=False, dry_run=False, autonomous_enabled=True)
    assert r.allowed is False
    assert r.downgraded_action == ActionType.ALERT
    assert "protected" in r.rationale.lower()


def test_protected_process_name_blocked_for_kill():
    d = mk_decision(
        action=ActionType.KILL,
        confidence=0.99,
        process_name="systemd",
        evidence_count=3,
    )
    r = evaluate_policy(d, learning_mode=False, dry_run=False, autonomous_enabled=True)
    assert r.allowed is False
    assert r.downgraded_action == ActionType.ALERT


def test_system_process_blocked_for_kill():
    d = mk_decision(
        action=ActionType.KILL,
        confidence=0.99,
        is_system_process=True,
        evidence_count=3,
    )
    r = evaluate_policy(d, learning_mode=False, dry_run=False, autonomous_enabled=True)
    assert r.allowed is False
    assert r.downgraded_action == ActionType.ALERT


def test_private_ip_blocked_for_block_action():
    d = mk_decision(
        action=ActionType.BLOCK,
        confidence=0.95,
        destination_ip="192.168.1.10",
        evidence_count=3,
    )
    r = evaluate_policy(d, learning_mode=False, dry_run=False, autonomous_enabled=True)
    assert r.allowed is False
    assert r.downgraded_action == ActionType.ALERT


def test_allowed_action_passes_all_checks():
    d = mk_decision(
        action=ActionType.BLOCK,
        confidence=0.95,
        destination_ip="8.8.8.8",
        evidence_count=3,
    )
    r = evaluate_policy(d, learning_mode=False, dry_run=False, autonomous_enabled=True)
    assert r.allowed is True
    assert r.downgraded_action == ActionType.BLOCK
    assert "Allowed by policy" in r.rationale
