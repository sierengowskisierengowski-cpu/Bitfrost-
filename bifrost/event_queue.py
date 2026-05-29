#!/usr/bin/env python3
"""Shared event queue helpers and drop metrics."""

import logging
import threading
import time
from queue import Full, Queue

METRICS_LOCK = threading.Lock()
METRICS = {
    "events_received": 0,
    "events_dropped": 0,
    "queue_full_count": 0,
}


def safe_enqueue(queue: Queue, event: dict, source: str, log: logging.Logger) -> bool:
    """
    Enqueue with bounded retry and drop metrics.
    Never silently drops — always logs and counts.
    """
    for attempt in range(3):
        try:
            queue.put(event, timeout=0.2)
            with METRICS_LOCK:
                METRICS["events_received"] += 1
            return True
        except Full:
            if attempt == 2:
                with METRICS_LOCK:
                    METRICS["events_dropped"] += 1
                    METRICS["queue_full_count"] += 1
                    dropped = METRICS["events_dropped"]
                log.error(
                    "EVENT_QUEUE full after 3 attempts. "
                    "Dropping event source=%s. Total dropped=%d",
                    source,
                    dropped,
                )
                return False
            time.sleep(0.05)
    return False
