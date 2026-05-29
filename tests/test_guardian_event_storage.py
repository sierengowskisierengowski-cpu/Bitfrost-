#!/usr/bin/env python3

import json
import logging
from queue import Queue

import pytest

from bifrost import guardian


@pytest.mark.parametrize(
    "compressed",
    [
        {"event_type": "process.watcher", "path": "/tmp/dropper.sh"},
        '{"event_type":"process.watcher","path":"/tmp/dropper.sh"}',
        '"{\\"event_type\\":\\"process.watcher\\",\\"path\\":\\"/tmp/dropper.sh\\"}"',
    ],
)
def test_store_event_normalizes_compressed_event_json(tmp_path, monkeypatch, compressed):
    db_path = tmp_path / "events.db"
    monkeypatch.setattr(guardian, "DB_PATH", db_path)
    guardian.init_database()

    router = guardian.EventRouter(
        Queue(),
        {"hardware_tier": "TIER_4", "use_local_llm": False},
        str(db_path),
        logging.getLogger("test.guardian"),
    )

    try:
        event_id = router.store_event(
            {
                "source": "auditd",
                "timestamp": "2026-05-29T00:00:00Z",
                "boundary": "HOST",
                "raw": {"exe": "/tmp/dropper.sh"},
            },
            compressed=compressed,
        )
        stored = router.conn.execute(
            "SELECT compressed_event FROM events WHERE id = ?",
            (event_id,),
        ).fetchone()[0]
    finally:
        router.conn.close()

    assert json.loads(stored) == {
        "event_type": "process.watcher",
        "path": "/tmp/dropper.sh",
    }
    assert isinstance(json.loads(stored), dict)
