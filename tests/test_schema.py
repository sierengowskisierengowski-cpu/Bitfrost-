#!/usr/bin/env python3
"""
tests/test_schema.py

Unit tests for Bifrost schema contracts.
Run: python -m pytest tests/test_schema.py -v
"""

import pytest
from heimdall.schema import (
    RawEvent, Decision, ActionType, Severity, Boundary,
    SCHEMA_VERSION, validate_decision_dict, validate_raw_event,
    DESTRUCTIVE_ACTIONS, SAFE_ACTIONS
)


class TestRawEvent:

    def test_valid_event(self):
        e = RawEvent.from_dict({
            "source": "auditd",
            "timestamp": "2026-05-28T03:00:00Z",
            "boundary": "HOST",
            "raw": {"key": "value"}
        })
        assert e.source == "auditd"
        assert e.boundary.value == "HOST"

    def test_unknown_field_rejected(self):
        with pytest.raises(Exception):
            RawEvent.from_dict({
                "source": "auditd",
                "timestamp": "2026-05-28T03:00:00Z",
                "boundary": "HOST",
                "raw": {},
                "unknown_field": "should_fail"
            })

    def test_empty_source_rejected(self):
        with pytest.raises(Exception):
            RawEvent.from_dict({
                "source": "",
                "timestamp": "2026-05-28T03:00:00Z",
                "boundary": "HOST",
                "raw": {}
            })

    def test_timestamp_preserved_as_zulu(self):
        e = RawEvent.from_dict({
            "source": "cowrie",
            "timestamp": "2026-05-28T03:00:00+00:00",
            "boundary": "HONEYPOT",
            "raw": {}
        })
        assert e.timestamp.endswith("Z")

    def test_missing_timestamp_gets_default(self):
        e = RawEvent.from_dict({
            "source": "cowrie",
            "timestamp": "",
            "boundary": "HONEYPOT",
            "raw": {}
        })
        assert e.timestamp.endswith("Z")
        assert len(e.timestamp) > 0

    def test_invalid_boundary_rejected(self):
        with pytest.raises(Exception):
            RawEvent.from_dict({
                "source": "auditd",
                "timestamp": "2026-05-28T03:00:00Z",
                "boundary": "INVALID_BOUNDARY",
                "raw": {}
            })

    def test_empty_source_alone_rejected(self):
        with pytest.raises(Exception):
            validate_raw_event({
                "source": "",
                "timestamp": "2026-05-28T03:00:00Z",
                "boundary": "HOST",
                "raw": {}
            })

    def test_bad_timestamp_alone_rejected(self):
        with pytest.raises(Exception):
            validate_raw_event({
                "source": "auditd",
                "timestamp": "not-a-timestamp",
                "boundary": "HOST",
                "raw": {}
            })

    def test_to_dict_roundtrip(self):
        d = {
            "source": "auditd",
            "timestamp": "2026-05-28T03:00:00Z",
            "boundary": "HOST",
            "raw": {"pid": 1234}
        }
        e = RawEvent.from_dict(d)
        result = e.to_dict()
        assert result["source"] == "auditd"
        assert result["boundary"] == "HOST"


class TestDecision:

    def test_valid_decision(self):
        d = Decision.from_dict({
            "incident_detected": True,
            "severity": "HIGH",
            "boundary": "HOST",
            "threat_class": "credential_theft",
            "confidence": 0.92,
            "action_required": "ALERT",
            "reasoning": "test reason",
            "extractor_model": "qwen",
            "reasoner_model": "qwen",
            "hardware_tier": "TIER_1"
        })
        assert d.incident_detected is True
        assert d.severity == Severity.HIGH
        assert d.action_required == ActionType.ALERT

    def test_unknown_field_rejected(self):
        with pytest.raises(Exception):
            Decision.from_dict({
                "incident_detected": True,
                "action_required": "ALERT",
                "unknown_extra_field": "must_fail"
            })

    def test_schema_version_locked(self):
        d = Decision.from_dict({
            "schema_version": "9.9.9",
            "incident_detected": False,
            "action_required": "NONE"
        })
        assert d.schema_version == SCHEMA_VERSION

    def test_confidence_clamped_high(self):
        d = Decision.from_dict({
            "confidence": 999.0,
            "action_required": "NONE"
        })
        assert d.confidence <= 1.0

    def test_confidence_clamped_low(self):
        d = Decision.from_dict({
            "confidence": -5.0,
            "action_required": "NONE"
        })
        assert d.confidence >= 0.0

    def test_reasoning_truncated(self):
        long_reason = "x" * 500
        d = Decision.from_dict({
            "reasoning": long_reason,
            "action_required": "NONE"
        })
        assert len(d.reasoning) <= 200

    def test_contradictory_payload_downgraded(self):
        d = Decision.from_dict({
            "incident_detected": False,
            "action_required": "KILL",
            "confidence": 0.99
        })
        assert d.action_required == ActionType.ALERT

    def test_safe_fallback(self):
        d = Decision.safe_fallback("test_error")
        assert d.action_required == ActionType.ALERT
        assert d.incident_detected is True
        assert d.confidence == 0.5
        assert "test_error" in d.reasoning

    def test_is_destructive(self):
        for action in ("KILL", "BLOCK", "QUARANTINE"):
            d = Decision.from_dict({
                "incident_detected": True,
                "action_required": action,
                "confidence": 0.9
            })
            assert d.is_destructive()

    def test_is_safe(self):
        for action in ("ALERT", "LOG", "NONE"):
            d = Decision.from_dict({
                "action_required": action
            })
            assert d.is_safe()

    def test_validate_decision_dict_bad_action(self):
        result = validate_decision_dict({"action_required": "EXPLODE"})
        assert result.action_required == ActionType.ALERT

    def test_to_dict_roundtrip(self):
        d = Decision.from_dict({
            "incident_detected": True,
            "severity": "CRITICAL",
            "action_required": "ALERT",
            "confidence": 0.95,
            "threat_class": "breakout"
        })
        result = d.to_dict()
        assert result["severity"] == "CRITICAL"
        assert result["confidence"] == 0.95
        assert result["schema_version"] == SCHEMA_VERSION

    def test_event_id_accepts_string(self):
        import uuid
        d = Decision.from_dict({
            "action_required": "NONE",
            "event_id": str(uuid.uuid4())
        })
        assert isinstance(d.event_id, str)

    def test_event_id_accepts_none(self):
        d = Decision.from_dict({"action_required": "NONE"})
        assert d.event_id is None


class TestActionTypes:

    def test_destructive_set(self):
        assert ActionType.KILL in DESTRUCTIVE_ACTIONS
        assert ActionType.BLOCK in DESTRUCTIVE_ACTIONS
        assert ActionType.QUARANTINE in DESTRUCTIVE_ACTIONS

    def test_safe_set(self):
        assert ActionType.ALERT in SAFE_ACTIONS
        assert ActionType.LOG in SAFE_ACTIONS
        assert ActionType.NONE in SAFE_ACTIONS

    def test_no_overlap(self):
        overlap = DESTRUCTIVE_ACTIONS & SAFE_ACTIONS
        assert len(overlap) == 0
