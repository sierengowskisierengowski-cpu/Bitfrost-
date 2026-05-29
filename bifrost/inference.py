#!/usr/bin/env python3
"""
Bifrost Inference v0.1.0

Circuit breaker, retry logic, and timeout management
for all LLM inference calls in the Bifrost pipeline.

Prevents a slow or failing model from blocking the
entire event processing pipeline.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Optional

log = logging.getLogger("heimdall.inference")

TIER_TIMEOUTS = {
    "TIER_1": 60.0,
    "TIER_2": 45.0,
    "TIER_3": 30.0,
    "TIER_4": 15.0,
}

DEFAULT_TIMEOUT = 30.0
MAX_RETRIES = 2
RETRY_DELAY = 1.0


def get_request_timeout(config: Any = "TIER_4") -> float:
    """Return request timeout from config dict or hardware tier string."""
    if isinstance(config, dict):
        if "llm_timeout_seconds" in config:
            return float(config["llm_timeout_seconds"])
        tier = config.get("hardware_tier", "TIER_4")
        return TIER_TIMEOUTS.get(tier, DEFAULT_TIMEOUT)
    if isinstance(config, str):
        return TIER_TIMEOUTS.get(config, DEFAULT_TIMEOUT)
    return DEFAULT_TIMEOUT


class CircuitBreaker:
    """
    Circuit breaker for LLM inference calls.

    Uses monotonic open_until timestamp. When open, calls are skipped
    and execute_with_retry returns (None, "circuit_open").
    """

    def __init__(
        self,
        name: str = "",
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
    ):
        self.name = name or "unnamed"
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.open_until = 0.0
        self._lock = threading.Lock()

    def _apply_config(self, config: dict) -> None:
        if "llm_circuit_breaker_failures" in config:
            self.failure_threshold = int(config["llm_circuit_breaker_failures"])
        if "llm_circuit_breaker_reset_seconds" in config:
            self.recovery_timeout = float(config["llm_circuit_breaker_reset_seconds"])

    def is_open(self) -> bool:
        return time.monotonic() < self.open_until

    def _record_success(self) -> None:
        with self._lock:
            self.failure_count = 0
            self.open_until = 0.0

    def _record_failure(self, logger: logging.Logger) -> None:
        with self._lock:
            self.failure_count += 1
            if self.failure_count >= self.failure_threshold:
                self.open_until = time.monotonic() + self.recovery_timeout
                logger.error(
                    "CircuitBreaker %s: OPEN after %d failures. "
                    "Retry in %.0fs.",
                    self.name,
                    self.failure_count,
                    self.recovery_timeout,
                )

    def reset(self) -> None:
        with self._lock:
            self.failure_count = 0
            self.open_until = 0.0
        log.info("CircuitBreaker %s: manually reset.", self.name)

    def get_status(self) -> dict:
        return {
            "name": self.name,
            "open": self.is_open(),
            "failure_count": self.failure_count,
            "failure_threshold": self.failure_threshold,
            "open_until": self.open_until,
        }


def execute_with_retry(
    fn: Callable[[], Any],
    *,
    provider: str = "",
    config: Optional[dict] = None,
    logger: Optional[logging.Logger] = None,
    circuit_breaker: Optional[CircuitBreaker] = None,
    **_ignored,
) -> tuple[Any, Optional[str]]:
    """
    Execute fn with retry and optional circuit breaker.

    Returns (result, error_code). error_code is None on success,
    "circuit_open" when the breaker blocks the call, or "llm_error"
    when all attempts fail.
    """
    config = config or {}
    logger = logger or log

    max_retries = int(config.get("llm_retry_attempts", MAX_RETRIES))
    attempts = max(1, max_retries + 1)
    delay = float(config.get("llm_retry_backoff_seconds", RETRY_DELAY))
    max_backoff = float(config.get("llm_retry_max_backoff_seconds", max(delay, RETRY_DELAY)))

    if circuit_breaker is not None:
        circuit_breaker._apply_config(config)
        if circuit_breaker.is_open():
            logger.warning(
                "CircuitBreaker %s: OPEN. Skipping %s call.",
                circuit_breaker.name,
                provider or "inference",
            )
            return None, "circuit_open"

    last_error: Optional[Exception] = None
    for attempt in range(1, attempts + 1):
        try:
            result = fn()
            if circuit_breaker is not None:
                circuit_breaker._record_success()
            return result, None
        except Exception as exc:
            last_error = exc
            if circuit_breaker is not None:
                circuit_breaker._record_failure(logger)

            if attempt < attempts:
                sleep_for = min(delay * attempt, max_backoff)
                logger.warning(
                    "Attempt %d/%d failed for %s: %s. Retrying in %.2fs.",
                    attempt,
                    attempts,
                    provider or "inference",
                    exc,
                    sleep_for,
                )
                time.sleep(sleep_for)
            else:
                logger.error(
                    "All %d attempts failed for %s. Last error: %s",
                    attempts,
                    provider or "inference",
                    exc,
                )

    return None, "llm_error" if last_error else "llm_error"
