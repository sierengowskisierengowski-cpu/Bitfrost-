#!/usr/bin/env python3

import logging
import threading
from queue import Queue

from bifrost.bpf_collector import BPFCollector
from bifrost.guardian import NetworkWatcher


class _FakeBPFMap:
    def __init__(self, event_factory):
        self._event_factory = event_factory

    def event(self, data):
        return self._event_factory(data)


class _FakeBPF:
    def __init__(self, event_factory):
        self._events = _FakeBPFMap(event_factory)

    def __getitem__(self, key):
        if key != "events":
            raise KeyError(key)
        return self._events


class _FakeEvent:
    pid = 4242
    uid = 0
    comm = b"python"
    type = b"execve"
    path = b"/tmp/dropper"
    ip = 0
    port = 0


def _raise_bad_event(_data):
    raise ValueError("bad event")


def test_network_watcher_hex_to_ip_logs_invalid_input_once(caplog):
    watcher = NetworkWatcher(Queue(), logging.getLogger("test.network"))

    with caplog.at_level(logging.WARNING):
        assert watcher.hex_to_ip("not-hex") == "0.0.0.0"
        assert watcher.hex_to_ip("not-hex") == "0.0.0.0"

    messages = [
        record.message for record in caplog.records
        if "invalid hex IP" in record.message
    ]
    assert messages == [
        "NetworkWatcher received invalid hex IP 'not-hex': "
        "ValueError: invalid literal for int() with base 16: 'not-hex'"
    ]


def test_bpf_collector_logs_queue_full_once(caplog):
    collector = BPFCollector(
        Queue(maxsize=1),
        threading.Event(),
        logging.getLogger("test.bpf.queue"),
    )
    collector.bpf = _FakeBPF(lambda data: _FakeEvent())
    collector.queue.put_nowait({"existing": True})

    with caplog.at_level(logging.WARNING):
        collector.handle_event(0, object(), 0)
        collector.handle_event(0, object(), 0)

    messages = [
        record.message for record in caplog.records
        if "Dropping eBPF event pid=4242" in record.message
    ]
    assert messages == ["Dropping eBPF event pid=4242: Full: "]


def test_bpf_collector_logs_parse_error_once(caplog):
    collector = BPFCollector(
        Queue(),
        threading.Event(),
        logging.getLogger("test.bpf.parse"),
    )
    collector.bpf = _FakeBPF(_raise_bad_event)

    with caplog.at_level(logging.WARNING):
        collector.handle_event(0, object(), 0)
        collector.handle_event(0, object(), 0)

    messages = [
        record.message for record in caplog.records
        if "Event parsing error in BPFCollector.handle_event" in record.message
    ]
    assert messages == [
        "Event parsing error in BPFCollector.handle_event: ValueError: bad event"
    ]
