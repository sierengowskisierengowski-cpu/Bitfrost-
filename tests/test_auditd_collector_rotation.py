#!/usr/bin/env python3

import logging
import time
from pathlib import Path
from queue import Queue

from bifrost.guardian import AuditdCollector, SHUTDOWN


def _append_line(path: Path, line: str):
    with open(path, "a") as f:
        f.write(line + "\n")
        f.flush()


def test_auditd_collector_reopens_after_rotation(tmp_path, monkeypatch):
    audit_log = tmp_path / "audit.log"
    audit_log.write_text("")

    monkeypatch.setattr(AuditdCollector, "AUDIT_LOG", audit_log)
    monkeypatch.setattr(AuditdCollector, "RETRY_INTERVAL", 0.05)

    q = Queue()
    log = logging.getLogger("test.auditd.rotation")
    SHUTDOWN.clear()

    collector = AuditdCollector(q, log)
    collector.start()

    try:
        time.sleep(0.2)
        _append_line(audit_log, 'type=SYSCALL msg=audit(1.1:1): comm="wget"')
        first = q.get(timeout=2)
        assert first["raw"].startswith("type=SYSCALL")

        rotated = tmp_path / "audit.log.1"
        audit_log.rename(rotated)
        audit_log.write_text("")
        time.sleep(0.2)
        second_line = 'type=SYSCALL msg=audit(1.1:2): comm="curl"'
        _append_line(audit_log, second_line)

        second = q.get(timeout=2)
        assert second["raw"] == second_line
        assert q.empty()
    finally:
        SHUTDOWN.set()
        collector.join(timeout=2)
        SHUTDOWN.clear()
