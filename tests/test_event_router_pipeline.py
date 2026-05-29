#!/usr/bin/env python3

import logging
import sqlite3
import threading
from queue import Queue

import pytest

from bifrost import guardian


def make_config():
    return {
        "hardware_tier": "TIER_4",
        "use_local_llm": False,
        "analyst_model": None,
        "system_baseline": "You are Heimdall-Core.",
        "router_stage_queue_size": 2,
        "router_compress_workers": 2,
        "router_reason_workers": 2,
        "router_storage_workers": 1,
    }


def make_event(source="auditd", boundary="HOST", alert=None):
    raw = {"command": "touch /tmp/payload"}
    if alert is not None:
        raw["alert"] = alert

    return {
        "source": source,
        "boundary": boundary,
        "timestamp": "2026-05-29T00:00:00Z",
        "raw": raw,
    }


def make_logger(name):
    logger = logging.getLogger(name)
    logger.handlers = []
    logger.addHandler(logging.NullHandler())
    logger.propagate = False
    return logger


def init_test_db(tmp_path, monkeypatch):
    db_path = tmp_path / "events.db"
    monkeypatch.setattr(guardian, "DB_PATH", db_path)
    return guardian.init_database()


@pytest.fixture(autouse=True)
def reset_shutdown():
    guardian.SHUTDOWN.clear()
    yield
    guardian.SHUTDOWN.set()
    guardian.SHUTDOWN.clear()


def test_event_router_uses_parallel_pipeline_workers(tmp_path, monkeypatch):
    monkeypatch.setattr(
        guardian.EventRouter,
        "setup_inference_clients",
        lambda self: (
            setattr(self, "analyst_client", None),
            setattr(self, "extractor_client", None),
            setattr(self, "analyst_model", None),
            setattr(self, "extractor_model", None),
        ),
    )

    db_path = init_test_db(tmp_path, monkeypatch)
    inbound = Queue(maxsize=4)
    router = guardian.EventRouter(
        inbound,
        make_config(),
        db_path,
        make_logger("test.router.parallel"),
    )

    release = threading.Event()
    both_started = threading.Event()
    concurrency = {"active": 0, "max_active": 0}
    concurrency_lock = threading.Lock()

    def compress_event(event):
        with concurrency_lock:
            concurrency["active"] += 1
            concurrency["max_active"] = max(
                concurrency["max_active"], concurrency["active"]
            )
            if concurrency["active"] >= 2:
                both_started.set()

        assert release.wait(timeout=2.0)

        with concurrency_lock:
            concurrency["active"] -= 1

        return f"compressed:{event['source']}"

    monkeypatch.setattr(router, "compress_event", compress_event)
    monkeypatch.setattr(
        router,
        "route_to_heimdall",
        lambda compressed: {
            "severity": "LOW",
            "action_required": "LOG",
            "confidence": 0.1,
            "reasoning": f"processed:{compressed}",
            "gjallarhorn_tier": 1,
        },
    )

    router.start()
    inbound.put(make_event(source="one"))
    inbound.put(make_event(source="two"))

    try:
        assert both_started.wait(timeout=2.0)
    finally:
        release.set()

    inbound.join()
    guardian.SHUTDOWN.set()
    router.join(timeout=5.0)

    assert concurrency["max_active"] >= 2
    assert router.compress_queue.maxsize == 2
    assert router.reason_queue.maxsize == 2
    assert router.storage_queue.maxsize == 2

    with sqlite3.connect(db_path) as conn:
        stored = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert stored == 2


def test_event_router_honeypot_fast_path_skips_llm_stages(tmp_path, monkeypatch):
    monkeypatch.setattr(
        guardian.EventRouter,
        "setup_inference_clients",
        lambda self: (
            setattr(self, "analyst_client", None),
            setattr(self, "extractor_client", None),
            setattr(self, "analyst_model", None),
            setattr(self, "extractor_model", None),
        ),
    )

    db_path = init_test_db(tmp_path, monkeypatch)
    inbound = Queue(maxsize=2)
    router = guardian.EventRouter(
        inbound,
        make_config(),
        db_path,
        make_logger("test.router.honeypot"),
    )

    compress_calls = []
    reason_calls = []
    monkeypatch.setattr(
        router, "compress_event", lambda event: compress_calls.append(event)
    )
    monkeypatch.setattr(
        router, "route_to_heimdall", lambda compressed: reason_calls.append(compressed)
    )

    router.start()
    inbound.put(make_event(boundary="HONEYPOT"))
    inbound.join()
    guardian.SHUTDOWN.set()
    router.join(timeout=5.0)

    assert compress_calls == []
    assert reason_calls == []

    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT boundary, heimdall_decision FROM events"
        ).fetchone()

    assert row == ("HONEYPOT", None)
