#!/usr/bin/env python3

import json
import hashlib

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
