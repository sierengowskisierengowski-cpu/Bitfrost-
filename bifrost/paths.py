#!/usr/bin/env python3
"""
Bifrost path resolution.

Paths resolve in priority order:
  1. Environment variables (BIFROST_* / HEIMDALL_*)
  2. heimdall_config.json "paths" section (when config is provided)
  3. BIFROST_HOME / HEIMDALL_HOME (default ~/Projects/bifrost)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping, Optional

_DEFAULT_HOME = "~/Projects/bifrost"
_DEFAULT_HONEYPOT_HOME = "~/Projects/honeypot"


def _first_env(*names: str) -> str:
    for name in names:
        value = os.getenv(name, "").strip()
        if value:
            return value
    return ""


def bifrost_home() -> Path:
    """Base install directory for Bifrost/Heimdall."""
    override = _first_env("BIFROST_HOME", "HEIMDALL_HOME")
    if override:
        return Path(override).expanduser().resolve()
    return Path(_DEFAULT_HOME).expanduser().resolve()


def honeypot_home() -> Path:
    override = _first_env("BIFROST_HONEYPOT_HOME", "HEIMDALL_HONEYPOT_HOME")
    if override:
        return Path(override).expanduser().resolve()
    return Path(_DEFAULT_HONEYPOT_HOME).expanduser().resolve()


def _path_from_config(
    config: Optional[Mapping[str, Any]],
    key: str,
    filename: Optional[str] = None,
) -> Optional[Path]:
    if not config:
        return None
    paths = config.get("paths")
    if not isinstance(paths, dict):
        return None
    raw = paths.get(key)
    if not raw:
        return None
    path = Path(str(raw)).expanduser()
    if filename and (path.is_dir() or not path.suffix):
        return (path / filename).resolve()
    return path.resolve()


def config_path(config: Optional[Mapping[str, Any]] = None) -> Path:
    override = _first_env("BIFROST_CONFIG_PATH", "HEIMDALL_CONFIG_PATH")
    if override:
        path = Path(override).expanduser()
        if path.is_dir():
            return (path / "heimdall_config.json").resolve()
        return path.resolve()

    from_config = _path_from_config(config, "config_path", "heimdall_config.json")
    if from_config:
        return from_config

    return (bifrost_home() / "heimdall_config.json").resolve()


def config_checksum_path(config: Optional[Mapping[str, Any]] = None) -> Path:
    return config_path(config).with_suffix(".sha256")


def db_path(config: Optional[Mapping[str, Any]] = None) -> Path:
    override = _first_env("BIFROST_DB_PATH", "HEIMDALL_DB_PATH")
    if override:
        return Path(override).expanduser().resolve()

    from_config = _path_from_config(config, "db_path")
    if from_config:
        return from_config

    if config:
        fp_db = config.get("false_positive_db")
        if fp_db:
            return Path(str(fp_db)).expanduser().resolve()

    return (bifrost_home() / "db" / "events.db").resolve()


def log_path(config: Optional[Mapping[str, Any]] = None) -> Path:
    override = _first_env("BIFROST_LOG_PATH", "HEIMDALL_LOG_PATH")
    if override:
        path = Path(override).expanduser()
        if path.is_dir():
            return (path / "guardian.log").resolve()
        return path.resolve()

    from_config = _path_from_config(config, "log_path", "guardian.log")
    if from_config:
        return from_config

    return (bifrost_home() / "db" / "guardian.log").resolve()


def cowrie_log_path(config: Optional[Mapping[str, Any]] = None) -> Path:
    override = _first_env("BIFROST_COWRIE_LOG_PATH", "HEIMDALL_COWRIE_LOG_PATH")
    if override:
        return Path(override).expanduser().resolve()

    from_config = _path_from_config(config, "cowrie_log_path")
    if from_config:
        return from_config

    return (honeypot_home() / "logs/cowrie/cowrie.json").resolve()


def gjallarhorn_dir(config: Optional[Mapping[str, Any]] = None) -> Path:
    override = _first_env("BIFROST_GJALLARHORN_PATH", "HEIMDALL_GJALLARHORN_PATH")
    if override:
        return Path(override).expanduser().resolve()

    from_config = _path_from_config(config, "gjallarhorn_path")
    if from_config:
        return from_config

    return (bifrost_home() / "gjallarhorn").resolve()


def alert_sound_path(config: Optional[Mapping[str, Any]] = None) -> Path:
    override = _first_env("BIFROST_ALERT_SOUND", "HEIMDALL_ALERT_SOUND")
    if override:
        return Path(override).expanduser().resolve()
    return (gjallarhorn_dir(config) / "alert.wav").resolve()


def breach_sound_path(config: Optional[Mapping[str, Any]] = None) -> Path:
    override = _first_env("BIFROST_BREACH_SOUND", "HEIMDALL_BREACH_SOUND")
    if override:
        return Path(override).expanduser().resolve()
    return (gjallarhorn_dir(config) / "breach.wav").resolve()

