#!/usr/bin/env python3

import logging
import time


COLLECTOR_LOG_RATE_LIMIT_SECONDS = 60.0


def log_collector_error(log: logging.Logger, rate_limits: dict[str, float],
                        key: str, level: int,
                        context: str, exc: Exception) -> None:
    """Log a collector failure once per key within the throttle window.

    The ``rate_limits`` mapping is expected to be owned by a single collector
    instance so repeated failures are throttled per collector, not globally.
    """
    now = time.monotonic()
    if now - rate_limits.get(key, 0.0) < COLLECTOR_LOG_RATE_LIMIT_SECONDS:
        return
    rate_limits[key] = now
    log.log(level, f"{context}: {type(exc).__name__}: {exc}")
