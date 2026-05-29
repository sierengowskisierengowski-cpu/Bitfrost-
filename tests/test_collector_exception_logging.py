#!/usr/bin/env python3

import logging
import threading
from queue import Queue

from bifrost.bpf_collector import BPFCollector
from bifrost.guardian import NetworkWatcher


class _FakeBPFMap:
    def __init__(self, event):
        self._event = event

    def event(self, _data):
        return self._event


class _FakeBPF:
    def __init__(self, event):
        self._events = _FakeBPFMap(event)

    def __getitem__(self, key):
        assert key == "events"
        return self._events


class _FakeEvent:
    pid = 4242
    uid = 0
    comm = b"curl"
    type = b"execve"
    path = b"/tmp/dropper.sh"
    ip = 0
    port = 0


def test_bpf_collector_logs_dropped_queue_full_once(caplog):
    queue = Queue(maxsize=1)
    queue.put_nowait({"existing": True})

    collector = BPFCollector(
        queue, threading.Event(), logging.getLogger("test.collector.bpf")
    )
    collector.LOG_RATE_LIMIT_SECONDS = 3600
    collector.bpf = _FakeBPF(_FakeEvent())

    with caplog.at_level(logging.WARNING):
        collector.handle_event(0, object(), 0)
        collector.handle_event(0, object(), 0)

    messages = [
        record.message
        for record in caplog.records
        if "queue full while enqueueing event" in record.message.lower()
    ]
    assert messages == [
        "BPFCollector queue full while enqueueing event; dropping event source=ebpf"
    ]
    assert queue.qsize() == 1


def test_network_watcher_logs_invalid_hex_ip_once(caplog):
    watcher = NetworkWatcher(Queue(), logging.getLogger("test.collector.network"))
    watcher.LOG_RATE_LIMIT_SECONDS = 3600

    with caplog.at_level(logging.WARNING):
        assert watcher.hex_to_ip("not-hex") == "0.0.0.0"
        assert watcher.hex_to_ip("not-hex") == "0.0.0.0"

    messages = [
        record.message
        for record in caplog.records
        if "invalid hex ip" in record.message.lower()
    ]
    assert len(messages) == 1
    assert "not-hex" in messages[0]
