#!/usr/bin/env python3

import json
import hashlib
import logging
import sqlite3

import pytest

from bifrost import guardian


def _write_config(tmp_path, payload):
    config_path = tmp_path / "heimdall_config.json"
    config_path.write_text(json.dumps(payload))
    return config_path


def test_load_config_fails_when_checksum_missing_in_production(tmp_path, monkeypatch, caplog):
    config_path = _write_config(tmp_path, {"learning_mode": False})
    monkeypatch.setattr(guardian, "CONFIG_PATH", config_path)
    monkeypatch.setenv("HEIMDALL_ENV", "production")

    with pytest.raises(SystemExit) as excinfo:
        guardian.load_config()

    assert excinfo.value.code == 1
    assert "checksum file missing" in caplog.text.lower()


def test_load_config_allows_missing_checksum_in_non_production(tmp_path, monkeypatch):
    expected = {"learning_mode": True, "k": "v"}
    config_path = _write_config(tmp_path, expected)
    monkeypatch.setattr(guardian, "CONFIG_PATH", config_path)
    monkeypatch.setenv("HEIMDALL_ENV", "development")

    actual = guardian.load_config()

    assert actual == expected


def test_load_config_fails_on_checksum_mismatch(tmp_path, monkeypatch, caplog):
    config_path = _write_config(tmp_path, {"learning_mode": False})
    checksum_path = config_path.with_suffix(".sha256")
    checksum_path.write_text(hashlib.sha256(b"tampered").hexdigest())
    monkeypatch.setattr(guardian, "CONFIG_PATH", config_path)
    monkeypatch.setenv("HEIMDALL_ENV", "production")

    with pytest.raises(SystemExit) as excinfo:
        guardian.load_config()

    assert excinfo.value.code == 1
    assert "checksum mismatch" in caplog.text.lower()


def test_store_event_normalizes_double_encoded_compressed_event(tmp_path, monkeypatch):
    db_path = tmp_path / "events.db"
    monkeypatch.setattr(guardian, "DB_PATH", db_path)
    guardian.init_database()

    router = guardian.EventRouter(
        guardian.EVENT_QUEUE,
        {"use_local_llm": False},
        str(db_path),
        logging.getLogger("test.guardian"),
    )

    event_id = router.store_event(
        {
            "source": "auditd",
            "boundary": "HOST",
            "raw": {"pid": 1234},
            "timestamp": "2026-05-29T00:00:00Z",
        },
        compressed=json.dumps('{"event_type":"process","pid":1234}'),
    )

    conn = sqlite3.connect(db_path)
    stored = conn.execute(
        "SELECT compressed_event FROM events WHERE id = ?",
        (event_id,),
    ).fetchone()[0]
    conn.close()
    router.conn.close()

    assert stored == '{"event_type": "process", "pid": 1234}'


def test_init_database_normalizes_existing_double_encoded_rows(tmp_path, monkeypatch):
    db_path = tmp_path / "events.db"
    monkeypatch.setattr(guardian, "DB_PATH", db_path)
    guardian.init_database()

    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        INSERT INTO events (timestamp, source, boundary, raw_event, compressed_event)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            "2026-05-29T00:00:00Z",
            "auditd",
            "HOST",
            "{}",
            json.dumps('{"event_type":"process","pid":5678}'),
        ),
    )
    conn.commit()
    conn.close()

    guardian.init_database()

    conn = sqlite3.connect(db_path)
    stored = conn.execute("SELECT compressed_event FROM events").fetchone()[0]
    conn.close()

    assert stored == '{"event_type": "process", "pid": 5678}'
