#!/usr/bin/env python3

import logging
import sqlite3
import threading
import time
from queue import Queue

from bifrost import guardian


def _make_event(index):
    return {
        "source": "test",
        "timestamp": f"2026-05-29T14:4{index}:00Z",
        "boundary": "HOST",
        "raw": {"index": index, "message": "queued"},
    }


def _disable_inference_clients(self):
    self.analyst_client = None
    self.analyst_model = None
    self.extractor_client = None
    self.extractor_model = None


def test_drain_event_queue_times_out_with_remaining_work():
    q = Queue()
    q.put({"pending": True})

    drained, remaining = guardian.drain_event_queue(
        q, timeout=0.05, poll_interval=0.01
    )

    assert drained is False
    assert remaining == 1


def test_event_router_processes_queued_events_before_exit(tmp_path, monkeypatch):
    db_path = tmp_path / "events.db"
    monkeypatch.setattr(guardian, "DB_PATH", db_path)
    monkeypatch.setattr(
        guardian.EventRouter,
        "setup_inference_clients",
        _disable_inference_clients,
    )

    guardian.init_database()
    guardian.SHUTDOWN.clear()
    guardian.COLLECTOR_STOP.clear()

    q = Queue()
    q.put(_make_event(1))
    q.put(_make_event(2))

    router = guardian.EventRouter(
        q,
        {"hardware_tier": "TIER_4", "use_local_llm": False},
        str(db_path),
        logging.getLogger("test.guardian.shutdown"),
    )
    router.start()

    guardian.SHUTDOWN.set()
    router.join(timeout=3)

    try:
        assert not router.is_alive()
        assert router.event_count == 2
        assert q.unfinished_tasks == 0

        with sqlite3.connect(db_path) as conn:
            stored_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

        assert stored_events == 2
    finally:
        guardian.SHUTDOWN.clear()
        guardian.COLLECTOR_STOP.clear()


def test_drain_event_queue_waits_for_task_completion():
    q = Queue()
    q.put({"pending": True})

    def worker():
        q.get(timeout=1)
        time.sleep(0.05)
        q.task_done()

    thread = threading.Thread(target=worker)
    thread.start()

    try:
        drained, remaining = guardian.drain_event_queue(
            q, timeout=1.0, poll_interval=0.01
        )
    finally:
        thread.join(timeout=1)

    assert drained is True
    assert remaining == 0
