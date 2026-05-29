#!/usr/bin/env python3

import socket
import time
from typing import Callable, Optional

DEFAULT_REQUEST_TIMEOUT = 5.0
DEFAULT_RETRY_ATTEMPTS = 2
DEFAULT_RETRY_BACKOFF_SECONDS = 0.25
DEFAULT_RETRY_MAX_BACKOFF_SECONDS = 1.0
DEFAULT_CIRCUIT_BREAKER_FAILURES = 3
DEFAULT_CIRCUIT_BREAKER_RESET_SECONDS = 30.0


def _get_float(config: dict, key: str, default: float) -> float:
    try:
        return max(0.0, float(config.get(key, default)))
    except (TypeError, ValueError):
        return default


def _get_int(config: dict, key: str, default: int) -> int:
    try:
        return max(0, int(config.get(key, default)))
    except (TypeError, ValueError):
        return default


def get_request_timeout(config: dict) -> float:
    return max(0.1, _get_float(
        config, "llm_timeout_seconds", DEFAULT_REQUEST_TIMEOUT
    ))


def get_retry_attempts(config: dict) -> int:
    return _get_int(config, "llm_retry_attempts", DEFAULT_RETRY_ATTEMPTS)


def get_retry_backoff(config: dict) -> float:
    return _get_float(
        config,
        "llm_retry_backoff_seconds",
        DEFAULT_RETRY_BACKOFF_SECONDS
    )


def get_retry_backoff_cap(config: dict) -> float:
    return max(
        get_retry_backoff(config),
        _get_float(
            config,
            "llm_retry_max_backoff_seconds",
            DEFAULT_RETRY_MAX_BACKOFF_SECONDS
        )
    )


def get_circuit_breaker_failures(config: dict) -> int:
    return max(1, _get_int(
        config,
        "llm_circuit_breaker_failures",
        DEFAULT_CIRCUIT_BREAKER_FAILURES
    ))


def get_circuit_breaker_reset_seconds(config: dict) -> float:
    return max(
        1.0,
        _get_float(
            config,
            "llm_circuit_breaker_reset_seconds",
            DEFAULT_CIRCUIT_BREAKER_RESET_SECONDS
        )
    )


def is_timeout_error(exc: Exception) -> bool:
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return True
    name = exc.__class__.__name__.lower()
    message = str(exc).lower()
    return "timeout" in name or "timed out" in message or "deadline" in message


class CircuitBreaker:
    def __init__(
        self,
        failure_threshold: int = DEFAULT_CIRCUIT_BREAKER_FAILURES,
        reset_timeout: float = DEFAULT_CIRCUIT_BREAKER_RESET_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.failure_threshold = max(1, int(failure_threshold))
        self.reset_timeout = max(1.0, float(reset_timeout))
        self._clock = clock
        self.failure_count = 0
        self.open_until = 0.0

    def configure(self, config: dict):
        self.failure_threshold = get_circuit_breaker_failures(config)
        self.reset_timeout = get_circuit_breaker_reset_seconds(config)

    def allow_request(self) -> bool:
        now = self._clock()
        if self.open_until and now >= self.open_until:
            self.failure_count = 0
            self.open_until = 0.0
        return self.open_until == 0.0

    def record_success(self):
        self.failure_count = 0
        self.open_until = 0.0

    def record_failure(self):
        self.failure_count += 1
        if self.failure_count >= self.failure_threshold:
            self.open_until = self._clock() + self.reset_timeout


def execute_with_retry(
    operation: Callable[[], object],
    *,
    provider: str,
    config: dict,
    logger,
    circuit_breaker: Optional[CircuitBreaker] = None,
):
    if circuit_breaker:
        circuit_breaker.configure(config)
        if not circuit_breaker.allow_request():
            logger.warning(
                "%s circuit breaker open. Using degraded mode.", provider
            )
            return None, "circuit_open"

    attempts = get_retry_attempts(config) + 1
    backoff = get_retry_backoff(config)
    backoff_cap = get_retry_backoff_cap(config)
    last_error = None

    for attempt in range(1, attempts + 1):
        try:
            result = operation()
            if circuit_breaker:
                circuit_breaker.record_success()
            return result, None
        except Exception as exc:
            last_error = exc
            if attempt >= attempts:
                break
            wait_time = min(backoff, backoff_cap)
            error_kind = "timeout" if is_timeout_error(exc) else "error"
            logger.warning(
                "%s %s on attempt %s/%s. Retrying in %.2fs.",
                provider,
                error_kind,
                attempt,
                attempts,
                wait_time,
            )
            time.sleep(wait_time)
            backoff = min(backoff * 2, backoff_cap)

    if circuit_breaker:
        circuit_breaker.record_failure()

    logger.warning("%s request failed after %s attempts: %s", provider, attempts, last_error)
    return None, last_error
