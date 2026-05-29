#!/usr/bin/env python3

from bifrost import paths as bifrost_paths


def test_db_path_from_env(monkeypatch, tmp_path):
    db_file = tmp_path / "custom.db"
    monkeypatch.setenv("BIFROST_DB_PATH", str(db_file))

    assert bifrost_paths.db_path() == db_file.resolve()


def test_config_path_from_env_file(monkeypatch, tmp_path):
    config_file = tmp_path / "custom_config.json"
    monkeypatch.setenv("BIFROST_CONFIG_PATH", str(config_file))

    assert bifrost_paths.config_path() == config_file.resolve()


def test_paths_from_config_section(tmp_path):
    config = {
        "paths": {
            "db_path": str(tmp_path / "events.db"),
            "log_path": str(tmp_path / "logs"),
            "config_path": str(tmp_path / "etc"),
        }
    }

    assert bifrost_paths.db_path(config) == (tmp_path / "events.db").resolve()
    assert bifrost_paths.log_path(config) == (tmp_path / "logs" / "guardian.log").resolve()
    assert bifrost_paths.config_path(config) == (
        tmp_path / "etc" / "heimdall_config.json"
    ).resolve()


def test_cowrie_log_from_env(monkeypatch, tmp_path):
    cowrie = tmp_path / "cowrie.json"
    monkeypatch.setenv("BIFROST_COWRIE_LOG_PATH", str(cowrie))

    assert bifrost_paths.cowrie_log_path() == cowrie.resolve()
