#!/usr/bin/env python3

import json
import logging
import sys
import types

from bifrost import extractor, guardian, reasoner
from bifrost import inference as inference_utils


class _FakeResponse:
    def __init__(self, content: str):
        self.choices = [
            types.SimpleNamespace(
                message=types.SimpleNamespace(content=content)
            )
        ]


class _FakeClient:
    def __init__(self, outcomes, create_calls):
        self._outcomes = outcomes
        self._create_calls = create_calls
        self.chat = types.SimpleNamespace(
            completions=types.SimpleNamespace(create=self._create)
        )

    def _create(self, **kwargs):
        self._create_calls.append(kwargs)
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return _FakeResponse(outcome)


def _reset_breaker(breaker):
    breaker.failure_count = 0
    breaker.open_until = 0.0


def test_route_to_groq_retries_and_uses_timeout(monkeypatch):
    create_calls = []
    init_kwargs = []
    outcomes = [
        TimeoutError("timed out"),
        TimeoutError("timed out"),
        json.dumps({
            "incident_detected": True,
            "severity": "HIGH",
            "boundary": "HOST",
            "threat_class": "test",
            "confidence": 0.9,
            "action_required": "ALERT",
            "reasoning": "retry success",
        }),
    ]

    class _OpenAI:
        def __init__(self, **kwargs):
            init_kwargs.append(kwargs)
            self._client = _FakeClient(outcomes, create_calls)
            self.chat = self._client.chat

    _reset_breaker(reasoner.INFERENCE_CIRCUIT_BREAKERS["groq"])
    monkeypatch.setenv("HEIMDALL_API_KEY", "test-key")
    monkeypatch.setattr(inference_utils.time, "sleep", lambda _: None)
    monkeypatch.setitem(sys.modules, "openai", types.SimpleNamespace(OpenAI=_OpenAI))

    result = reasoner.route_to_groq(
        "prompt",
        "baseline",
        {
            "groq_model": "groq-test",
            "llm_timeout_seconds": 1.5,
            "llm_retry_attempts": 2,
            "llm_retry_backoff_seconds": 0.0,
            "llm_retry_max_backoff_seconds": 0.0,
        },
    )

    assert result is not None
    assert result["reasoning"] == "retry success"
    assert len(create_calls) == 3
    assert init_kwargs[0]["timeout"] == 1.5


def test_route_to_groq_opens_circuit_breaker_after_failure(monkeypatch):
    create_calls = []
    outcomes = [TimeoutError("timed out")]

    class _OpenAI:
        def __init__(self, **kwargs):
            self._client = _FakeClient(outcomes, create_calls)
            self.chat = self._client.chat

    breaker = reasoner.INFERENCE_CIRCUIT_BREAKERS["groq"]
    _reset_breaker(breaker)
    monkeypatch.setenv("HEIMDALL_API_KEY", "test-key")
    monkeypatch.setitem(sys.modules, "openai", types.SimpleNamespace(OpenAI=_OpenAI))

    config = {
        "groq_model": "groq-test",
        "llm_retry_attempts": 0,
        "llm_circuit_breaker_failures": 1,
        "llm_circuit_breaker_reset_seconds": 60.0,
    }

    assert reasoner.route_to_groq("prompt", "baseline", config) is None
    assert breaker.open_until > 0
    assert reasoner.route_to_groq("prompt", "baseline", config) is None
    assert len(create_calls) == 1


def test_guardian_analyst_circuit_breaker_uses_safe_fallback():
    create_calls = []
    router = guardian.EventRouter.__new__(guardian.EventRouter)
    router.config = {
        "hardware_tier": "TIER_4",
        "system_baseline": "baseline",
        "llm_retry_attempts": 0,
        "llm_circuit_breaker_failures": 1,
        "llm_circuit_breaker_reset_seconds": 60.0,
    }
    router.log = logging.getLogger("tests.guardian")
    router.analyst_model = "groq-test"
    router.analyst_breaker = inference_utils.CircuitBreaker()
    router.analyst_client = _FakeClient([TimeoutError("timed out")], create_calls)

    first = router.route_to_heimdall("{}")
    second = router.route_to_heimdall("{}")

    assert first["reasoning"] == "Safe fallback: llm_error"
    assert second["reasoning"] == "Safe fallback: analyst_circuit_open"
    assert len(create_calls) == 1


def test_extractor_circuit_breaker_falls_back_to_deterministic(monkeypatch):
    create_calls = []
    init_kwargs = []
    outcomes = [TimeoutError("timed out")]

    class _OpenAI:
        def __init__(self, **kwargs):
            init_kwargs.append(kwargs)
            self._client = _FakeClient(outcomes, create_calls)
            self.chat = self._client.chat

    _reset_breaker(extractor.EXTRACTOR_CIRCUIT_BREAKER)
    monkeypatch.setitem(sys.modules, "openai", types.SimpleNamespace(OpenAI=_OpenAI))

    event = {
        "source": "process.watcher",
        "timestamp": "2026-05-28T03:00:00Z",
        "boundary": "HOST",
        "raw": {"cmdline": "wget http://malware", "exe": "/usr/bin/wget"},
    }
    config = {
        "hardware_tier": "TIER_2",
        "use_extractor": True,
        "extractor_model": "extractor-test",
        "llm_timeout_seconds": 2.0,
        "llm_retry_attempts": 0,
        "llm_circuit_breaker_failures": 1,
        "llm_circuit_breaker_reset_seconds": 60.0,
    }

    first = extractor.compress_event(event, config)
    second = extractor.compress_event(event, config)

    assert first["extraction_method"] == "deterministic"
    assert second["extraction_method"] == "deterministic"
    assert first["extractor_model"] == "extractor-test"
    assert len(create_calls) == 1
    assert init_kwargs[0]["timeout"] == 2.0
