#!/usr/bin/env python3

import logging

import pytest

from bifrost import guardian


def _make_kill_decision():
    return {
        "schema_version": "0.1.0",
        "incident_detected": True,
        "severity": "CRITICAL",
        "boundary": "HOST",
        "threat_class": "fileless_execution",
        "confidence": 0.99,
        "action_required": "KILL",
        "target": "5678",
        "gjallarhorn_tier": 2,
        "reasoning": "exec from /dev/shm",
        "extractor_model": "deterministic",
        "reasoner_model": "deterministic_rules",
        "hardware_tier": "TIER_4",
        "evidence_count": 3,
    }


def _make_router(config_overrides=None):
    config = {
        "hardware_tier": "TIER_4",
        "use_local_llm": False,
        "learning_mode": False,
        "dry_run": False,
        "autonomous_actions_enabled": True,
        "confidence_threshold": 0.85,
        "min_evidence_count": 2,
    }
    if config_overrides:
        config.update(config_overrides)

    router = guardian.EventRouter.__new__(guardian.EventRouter)
    router.config = config
    router.log = logging.getLogger("test.guardian.policy")
    router.db_path = "/tmp/test-events.db"
    return router


def test_policy_gate_blocks_kill_in_learning_mode():
    router = _make_router({"learning_mode": True})
    event = {"raw": {"pid": 5678}}

    result = router.apply_policy_gate(_make_kill_decision(), event)

    assert result["policy_allowed"] is False
    assert result["action_effective"] == "ALERT"
    assert "learning" in result["policy_rationale"].lower()


def test_policy_gate_blocks_kill_in_dry_run():
    router = _make_router({"dry_run": True})
    event = {"raw": {"pid": 5678}}

    result = router.apply_policy_gate(_make_kill_decision(), event)

    assert result["policy_allowed"] is False
    assert result["action_effective"] == "ALERT"


def test_policy_gate_blocks_kill_when_autonomous_disabled():
    router = _make_router({"autonomous_actions_enabled": False})
    event = {"raw": {"pid": 5678}}

    result = router.apply_policy_gate(_make_kill_decision(), event)

    assert result["policy_allowed"] is False
    assert result["action_effective"] == "ALERT"


def test_policy_gate_allows_kill_when_all_gates_pass():
    router = _make_router()
    event = {"raw": {"pid": 5678}}

    result = router.apply_policy_gate(_make_kill_decision(), event)

    assert result["policy_allowed"] is True
    assert result["action_effective"] == "KILL"


def test_maybe_dispatch_skips_executor_when_policy_blocks(monkeypatch):
    router = _make_router({"learning_mode": True})
    event = {"raw": {"pid": 5678}}
    decision = router.apply_policy_gate(_make_kill_decision(), event)

    calls = []
    monkeypatch.setattr(
        "bifrost.router.execute_decision",
        lambda *args, **kwargs: calls.append(args) or True,
    )

    router.maybe_dispatch_to_executor(decision, event_id=42)

    assert calls == []


def test_maybe_dispatch_calls_executor_when_policy_allows(monkeypatch):
    router = _make_router()
    event = {"raw": {"pid": 5678}}
    decision = router.apply_policy_gate(_make_kill_decision(), event)

    calls = []
    monkeypatch.setattr(
        "bifrost.router.execute_decision",
        lambda payload, event_id, db_path, log_ref: (
            calls.append((payload["action_required"], event_id)) or True
        ),
    )

    router.maybe_dispatch_to_executor(decision, event_id=99)

    assert calls == [("KILL", 99)]
