#!/usr/bin/env python3

import logging
from types import SimpleNamespace

from bifrost import guardian


def _make_router(monkeypatch, response_text):
    monkeypatch.setattr(guardian.EventRouter, "setup_inference_clients", lambda self: None)
    monkeypatch.setattr(guardian.EventRouter, "setup_db", lambda self: None)

    router = guardian.EventRouter(
        queue=None,
        config={
            "system_baseline": "You are Heimdall-Core.",
            "hardware_tier": "TIER_4",
        },
        db_path=":memory:",
        log=logging.getLogger("tests.guardian"),
    )
    router.analyst_model = "test-model"
    router.analyst_client = SimpleNamespace(
        chat=SimpleNamespace(
            completions=SimpleNamespace(
                create=lambda **kwargs: SimpleNamespace(
                    choices=[
                        SimpleNamespace(
                            message=SimpleNamespace(content=response_text)
                        )
                    ]
                )
            )
        )
    )
    return router


def test_route_to_heimdall_validates_llm_decision_schema(monkeypatch):
    router = _make_router(
        monkeypatch,
        """
        {
          "incident_detected": true,
          "severity": "HIGH",
          "boundary": "HOST",
          "threat_class": "credential_theft",
          "confidence": 9.5,
          "action_required": "ALERT",
          "gjallarhorn_tier": 1,
          "reasoning": "validated",
          "extractor_model": "qwen",
          "reasoner_model": "groq",
          "hardware_tier": "TIER_4"
        }
        """,
    )

    decision = router.route_to_heimdall('{"event":"test"}')

    assert decision["severity"] == "HIGH"
    assert decision["action_required"] == "ALERT"
    assert decision["confidence"] == 1.0
    assert decision["gjallarhorn_tier"] == 1


def test_route_to_heimdall_falls_back_when_required_field_missing(monkeypatch):
    router = _make_router(
        monkeypatch,
        """
        {
          "incident_detected": true,
          "severity": "HIGH",
          "boundary": "HOST",
          "threat_class": "credential_theft",
          "confidence": 0.9,
          "action_required": "ALERT",
          "reasoning": "missing tier"
        }
        """,
    )

    decision = router.route_to_heimdall('{"event":"test"}')

    assert decision["action_required"] == "LOG"
    assert decision["reasoning"] == "Safe fallback: missing_required_fields"


def test_route_to_heimdall_falls_back_on_schema_validation_error(monkeypatch):
    router = _make_router(
        monkeypatch,
        """
        {
          "incident_detected": true,
          "severity": "HIGH",
          "boundary": "HOST",
          "threat_class": "credential_theft",
          "confidence": 0.9,
          "action_required": "EXPLODE",
          "gjallarhorn_tier": 1,
          "reasoning": "bad action"
        }
        """,
    )

    decision = router.route_to_heimdall('{"event":"test"}')

    assert decision["action_required"] == "LOG"
    assert decision["reasoning"] == "Safe fallback: decision_validation_error"
