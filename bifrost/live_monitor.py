#!/usr/bin/env python3
"""Built-in human-readable live monitoring for Bifrost."""

from __future__ import annotations

import hashlib
import json
import logging
import math
from collections import Counter, OrderedDict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Mapping

from bifrost import paths as bifrost_paths
from bifrost.event_queue import METRICS, METRICS_LOCK

DEFAULT_MONITORING_CONFIG = {
    "live_monitor_enabled": True,
    "human_live_enabled": True,
    "test_mode_enabled": False,
    "test_mode_summary_interval_seconds": 60,
    "correlation_window_seconds": 300,
    "recent_window_seconds": 3600,
    "repeat_window_seconds": 86400,
    "live_confidence_threshold": 0.35,
    "possible_false_positive_confidence_threshold": 0.55,
    "dedup_cooldown_seconds": 30,
    "noisy_rule_threshold": 25,
    "noisy_rule_window_seconds": 300,
    "monitor_safelist": [],
    "monitor_max_tracked_entities": 4096,
    "live_monitor_jsonl_path": None,
}

SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
    "UNKNOWN": 0,
}


def apply_monitoring_defaults(config: Mapping[str, Any] | None) -> dict[str, Any]:
    merged = dict(config or {})
    for key, value in DEFAULT_MONITORING_CONFIG.items():
        merged.setdefault(key, value)
    return merged


def _coerce_float(*values: Any, default: float = 0.0) -> float:
    for value in values:
        try:
            if value is None or value == "":
                continue
            return float(value)
        except (TypeError, ValueError):
            continue
    return default


def _coerce_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value or "").strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _iso_zulu(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _stable_hash(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:16]


def _severity_from_confidence(confidence: float) -> str:
    if confidence >= 0.90:
        return "CRITICAL"
    if confidence >= 0.75:
        return "HIGH"
    if confidence >= 0.50:
        return "MEDIUM"
    if confidence >= 0.25:
        return "LOW"
    return "INFO"


def _truncate_summary(*parts: str, max_len: int = 220) -> str:
    text = " ".join(part.strip() for part in parts if part and part.strip())
    text = " ".join(text.split())
    if not text:
        return "Security telemetry observed."
    if len(text) <= max_len:
        return text
    return text[: max_len - 3].rstrip() + "..."


def _first_present(raw: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        value = raw.get(key)
        if value not in (None, ""):
            return value
    return None


def normalize_monitor_event(
    event: Mapping[str, Any] | None,
    decision: Mapping[str, Any] | None = None,
    *,
    sequence: int = 0,
    correlation_window_seconds: int = 300,
) -> dict[str, Any]:
    event = dict(event or {})
    decision = dict(decision or {})
    raw = event.get("raw")
    raw = raw if isinstance(raw, dict) else {}

    timestamp_dt = _parse_timestamp(event.get("timestamp") or raw.get("timestamp"))
    boundary = str(event.get("boundary") or decision.get("boundary") or "UNKNOWN").upper()
    source = str(event.get("source") or raw.get("collector") or "unknown")
    host = str(
        event.get("host")
        or _first_present(raw, "host", "hostname", "dest_host", "sensor_host")
        or source
    )

    event_type = str(
        _first_present(raw, "type", "event_type", "alert")
        or decision.get("threat_class")
        or "unknown"
    )
    threat_class = str(decision.get("threat_class") or event_type or "unknown")

    process_name = str(
        _first_present(raw, "process_name", "process", "exe", "comm")
        or "unknown"
    )
    pid = _first_present(raw, "pid", "process_id")

    attacker_identity = _first_present(
        raw,
        "src_ip",
        "source_ip",
        "remote_ip",
        "attacker_ip",
        "remote_user",
        "user",
        "username",
    )
    if attacker_identity in (None, ""):
        if pid not in (None, ""):
            attacker_identity = f"{process_name}:{pid}"
        else:
            attacker_identity = source
    attacker_identity = str(attacker_identity)

    target_identity = _first_present(
        raw,
        "dest_ip",
        "destination_ip",
        "target_file",
        "target_path",
        "dest_port",
    )
    if target_identity in (None, ""):
        target_identity = str(event.get("target") or decision.get("target") or "n/a")
    else:
        target_identity = str(target_identity)

    confidence = _coerce_float(
        decision.get("confidence"),
        raw.get("confidence"),
        raw.get("severity"),
        default=0.0,
    )
    severity = str(decision.get("severity") or _severity_from_confidence(confidence)).upper()
    requested_action = str(
        decision.get("action_requested") or decision.get("action_required") or "LOG"
    ).upper()
    action_taken = str(
        decision.get("action_effective") or requested_action or "LOG"
    ).upper()

    summary = _truncate_summary(
        str(decision.get("reasoning") or ""),
        str(_first_present(raw, "note", "summary", "message") or ""),
        max_len=220,
    )

    attacker_fingerprint = _stable_hash({"attacker_identity": attacker_identity})
    pattern_fingerprint = _stable_hash(
        {
            "boundary": boundary,
            "threat_class": threat_class,
            "event_type": event_type,
            "process_name": process_name,
            "target_identity": target_identity,
            "action_taken": action_taken,
        }
    )
    fingerprint = _stable_hash(
        {
            "attacker_fingerprint": attacker_fingerprint,
            "pattern_fingerprint": pattern_fingerprint,
            "host": host,
        }
    )

    correlation_window_seconds = max(int(correlation_window_seconds), 1)
    bucket = int(math.floor(timestamp_dt.timestamp() / correlation_window_seconds))
    incident_id = _stable_hash(
        {
            "bucket": bucket,
            "host": host,
            "boundary": boundary,
            "attacker_fingerprint": attacker_fingerprint,
            "pattern_fingerprint": pattern_fingerprint,
        }
    )

    incident_detected = bool(decision.get("incident_detected"))

    return {
        "sequence": sequence,
        "timestamp": _iso_zulu(timestamp_dt),
        "timestamp_epoch": timestamp_dt.timestamp(),
        "host": host,
        "boundary": boundary,
        "source": source,
        "event_type": event_type,
        "threat_class": threat_class,
        "summary": summary,
        "attacker_identity": attacker_identity,
        "target_identity": target_identity,
        "process_name": process_name,
        "pid": pid,
        "confidence": confidence,
        "severity": severity,
        "action_requested": requested_action,
        "action_taken": action_taken,
        "incident_detected": incident_detected,
        "policy_allowed": decision.get("policy_allowed"),
        "policy_rationale": decision.get("policy_rationale"),
        "decision_reasoning": decision.get("reasoning"),
        "event_id": str(event.get("event_id") or raw.get("event_id") or incident_id),
        "fingerprint": fingerprint,
        "attacker_fingerprint": attacker_fingerprint,
        "pattern_fingerprint": pattern_fingerprint,
        "incident_id": incident_id,
    }


def format_human_incident(record: Mapping[str, Any]) -> str:
    severity = str(record.get("severity", "UNKNOWN")).upper()
    severity_marker = {
        "CRITICAL": "[!!!]",
        "HIGH": "[!!]",
        "MEDIUM": "[!]",
        "LOW": "[-]",
        "INFO": "[i]",
    }.get(severity, "[?]")
    prefix = "[TEST MODE] " if record.get("test_mode") else ""
    outcome = record.get("outcome", "n/a")
    return (
        f"{severity_marker} {prefix}{record['timestamp']} "
        f"{record['boundary']}/{record['source']} {record['threat_class']} "
        f"conf={record['confidence']:.2f} action={record['action_taken']} outcome={outcome}. "
        f"Host {record['host']} {record['severity']}: "
        f"{record['summary']} Source {record['attacker_identity']} is "
        f"{record['attacker_status']} / pattern {record['pattern_status']} "
        f"({record['recent_count']} in last {record['recent_window_seconds']}s, "
        f"{record['repeat_count']} in last {record['repeat_window_seconds']}s). "
        f"Action taken: {record['action_taken']}."
    )


def format_test_mode_summary(summary: Mapping[str, Any]) -> str:
    strengths = ", ".join(summary.get("strongest_areas", [])[:2]) or "n/a"
    weaknesses = ", ".join(summary.get("weakest_areas", [])[:2]) or "n/a"
    return (
        "[TEST MODE SUMMARY] "
        f"{summary['timestamp']} events={summary['total_events']} "
        f"incidents={summary['incidents']} blocked={summary['blocked_actions']} "
        f"pass={summary.get('test_passed', 0)} fail={summary.get('test_failed', 0)} "
        f"pass_rate={summary.get('test_pass_rate', 0.0):.2f} "
        f"unique_attackers={summary['unique_attackers']} repeats={summary['repeat_attackers']} "
        f"new={summary['new_attackers']} suppressed={summary['suppressed']} "
        f"possible_fp={summary['possible_false_positive_queue']} "
        f"dropped={summary['dropped_events']} queue={summary['queue_size']}/{summary['queue_capacity']} "
        f"strengths={strengths} weaknesses={weaknesses}"
    )


class LiveMonitor:
    def __init__(self, config: Mapping[str, Any], log: logging.Logger, *, queue=None):
        self.config = apply_monitoring_defaults(config)
        self.log = log
        self.queue = queue
        self.enabled = bool(self.config.get("live_monitor_enabled", True))
        self.human_live_enabled = bool(self.config.get("human_live_enabled", True))
        self.test_mode_enabled = bool(self.config.get("test_mode_enabled", False))
        self.summary_interval_seconds = max(
            _coerce_int(self.config.get("test_mode_summary_interval_seconds"), 60),
            1,
        )
        self.correlation_window_seconds = max(
            _coerce_int(self.config.get("correlation_window_seconds"), 300),
            1,
        )
        self.recent_window_seconds = max(
            _coerce_int(self.config.get("recent_window_seconds"), 3600),
            1,
        )
        self.repeat_window_seconds = max(
            _coerce_int(self.config.get("repeat_window_seconds"), 86400),
            self.recent_window_seconds,
        )
        self.live_confidence_threshold = _coerce_float(
            self.config.get("live_confidence_threshold"), default=0.35
        )
        self.possible_false_positive_confidence_threshold = _coerce_float(
            self.config.get("possible_false_positive_confidence_threshold"),
            default=0.55,
        )
        self.dedup_cooldown_seconds = max(
            _coerce_int(self.config.get("dedup_cooldown_seconds"), 30),
            0,
        )
        self.noisy_rule_threshold = max(
            _coerce_int(self.config.get("noisy_rule_threshold"), 25),
            1,
        )
        self.noisy_rule_window_seconds = max(
            _coerce_int(self.config.get("noisy_rule_window_seconds"), 300),
            1,
        )
        self.monitor_max_tracked_entities = max(
            _coerce_int(self.config.get("monitor_max_tracked_entities"), 4096),
            64,
        )
        self.safelist = {
            str(item).strip().lower()
            for item in self.config.get("monitor_safelist", [])
            if str(item).strip()
        }

        self.sequence = 0
        self.total_events = 0
        self.incidents = 0
        self.blocked_actions = 0
        self.repeat_attackers = 0
        self.new_attackers = 0
        self.repeat_patterns = 0
        self.new_patterns = 0
        self.suppressed = 0
        self.possible_false_positives = 0
        self._last_summary_ts = 0.0

        self._known_attackers: OrderedDict[str, float] = OrderedDict()
        self._known_patterns: OrderedDict[str, float] = OrderedDict()
        self._attacker_windows: OrderedDict[str, Deque[float]] = OrderedDict()
        self._pattern_windows: OrderedDict[str, Deque[float]] = OrderedDict()
        self._rule_windows: OrderedDict[str, Deque[float]] = OrderedDict()
        self._emit_history: OrderedDict[str, float] = OrderedDict()
        self._possible_false_positive_queue: OrderedDict[str, float] = OrderedDict()
        self.test_passed = 0
        self.test_failed = 0
        self._failure_reasons: Counter[str] = Counter()
        self._threat_totals: Counter[str] = Counter()
        self._threat_failures: Counter[str] = Counter()
        self._source_totals: Counter[str] = Counter()
        self._source_failures: Counter[str] = Counter()

        self.structured_log_path = Path(
            self.config.get("live_monitor_jsonl_path")
            or bifrost_paths.log_path(self.config).with_name("live_monitor.jsonl")
        )
        self.structured_log_path.parent.mkdir(parents=True, exist_ok=True)
        self._structured_stream = None
        if self.enabled:
            self._structured_stream = self.structured_log_path.open(
                "a",
                encoding="utf-8",
                buffering=1,
            )

        for metric_name in (
            "live_monitor_events",
            "live_monitor_incidents",
            "live_monitor_suppressed",
            "live_monitor_possible_false_positives",
            "live_monitor_summaries",
        ):
            METRICS.setdefault(metric_name, 0)

    def close(self) -> None:
        if self._structured_stream:
            self._structured_stream.close()
            self._structured_stream = None

    def _cap_store(self, store: OrderedDict[str, Any]) -> None:
        while len(store) > self.monitor_max_tracked_entities:
            store.popitem(last=False)

    def _touch_window(
        self,
        store: OrderedDict[str, Deque[float]],
        key: str,
        timestamp_epoch: float,
        max_window: int,
    ) -> Deque[float]:
        values = store.pop(key, deque())
        cutoff = timestamp_epoch - max_window
        while values and values[0] < cutoff:
            values.popleft()
        values.append(timestamp_epoch)
        store[key] = values
        self._cap_store(store)
        return values

    @staticmethod
    def _count_since(values: Deque[float], cutoff: float) -> int:
        return sum(1 for value in values if value >= cutoff)

    def _queue_snapshot(self) -> dict[str, int]:
        queue_size = self.queue.qsize() if self.queue else 0
        queue_capacity = getattr(self.queue, "maxsize", 0) or 0
        return {
            "queue_size": queue_size,
            "queue_capacity": queue_capacity,
        }

    def _write_structured(self, payload: Mapping[str, Any]) -> None:
        if not self._structured_stream:
            return
        self._structured_stream.write(json.dumps(payload, sort_keys=True) + "\n")
        self._structured_stream.flush()

    def record_pipeline_step(
        self,
        event: Mapping[str, Any] | None,
        *,
        step: str,
        status: str,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        """Persist a structured pipeline-step record into live_monitor.jsonl.

        `step` should be a stable phase name (for example: route_start,
        compress_event, policy_gate). `status` should be a concise state such
        as "ok" or "error".
        """
        if not self.enabled:
            return
        event = dict(event or {})
        raw = event.get("raw")
        raw = raw if isinstance(raw, dict) else {}
        payload = {
            "record_type": "pipeline_step",
            "timestamp": _iso_zulu(datetime.now(timezone.utc)),
            "event_id": str(event.get("event_id") or raw.get("event_id") or "unknown"),
            "source": str(event.get("source") or "unknown"),
            "boundary": str(event.get("boundary") or "UNKNOWN"),
            "step": step,
            "status": status,
            "details": dict(details or {}),
        }
        self._write_structured(payload)

    def _evaluate_suppression(
        self,
        record: Mapping[str, Any],
        *,
        recent_rule_hits: int,
        timestamp_epoch: float,
    ) -> dict[str, Any]:
        reasons: list[str] = []
        matches = {
            record["attacker_identity"].lower(),
            record["host"].lower(),
            record["process_name"].lower(),
            record["threat_class"].lower(),
            record["fingerprint"].lower(),
            record["attacker_fingerprint"].lower(),
            record["pattern_fingerprint"].lower(),
        }
        if self.safelist.intersection(matches):
            reasons.append("allowlisted")
        if record["confidence"] < self.live_confidence_threshold:
            reasons.append("below_confidence_threshold")
        last_emit = self._emit_history.get(record["fingerprint"])
        if (
            last_emit is not None
            and self.dedup_cooldown_seconds > 0
            and (timestamp_epoch - last_emit) < self.dedup_cooldown_seconds
        ):
            reasons.append("dedup_cooldown")
        if (
            recent_rule_hits >= self.noisy_rule_threshold
            and record["confidence"] <= self.possible_false_positive_confidence_threshold
        ):
            reasons.append("noisy_rule_dampening")

        possible_fp = any(
            reason in {"below_confidence_threshold", "noisy_rule_dampening"}
            for reason in reasons
        )
        if possible_fp:
            self._possible_false_positive_queue[record["incident_id"]] = timestamp_epoch
            self._cap_store(self._possible_false_positive_queue)
        else:
            self._possible_false_positive_queue.pop(record["incident_id"], None)

        return {
            "suppressed": bool(reasons),
            "reasons": reasons,
            "possible_false_positive": possible_fp,
        }

    def record_event(
        self,
        event: Mapping[str, Any],
        decision: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.sequence += 1
        base = normalize_monitor_event(
            event,
            decision,
            sequence=self.sequence,
            correlation_window_seconds=self.correlation_window_seconds,
        )
        timestamp_epoch = base["timestamp_epoch"]
        self.total_events += 1

        attacker_key = base["attacker_fingerprint"]
        pattern_key = base["pattern_fingerprint"]

        attacker_seen_before = attacker_key in self._known_attackers
        pattern_seen_before = pattern_key in self._known_patterns
        self._known_attackers[attacker_key] = timestamp_epoch
        self._known_patterns[pattern_key] = timestamp_epoch
        self._cap_store(self._known_attackers)
        self._cap_store(self._known_patterns)

        attacker_window = self._touch_window(
            self._attacker_windows,
            attacker_key,
            timestamp_epoch,
            self.repeat_window_seconds,
        )
        pattern_window = self._touch_window(
            self._pattern_windows,
            pattern_key,
            timestamp_epoch,
            self.repeat_window_seconds,
        )
        rule_window = self._touch_window(
            self._rule_windows,
            base["threat_class"],
            timestamp_epoch,
            max(self.repeat_window_seconds, self.noisy_rule_window_seconds),
        )

        recent_cutoff = timestamp_epoch - self.recent_window_seconds
        repeat_cutoff = timestamp_epoch - self.repeat_window_seconds
        recent_count = self._count_since(attacker_window, recent_cutoff)
        repeat_count = self._count_since(attacker_window, repeat_cutoff)
        recent_pattern_count = self._count_since(pattern_window, recent_cutoff)
        recent_rule_hits = self._count_since(
            rule_window,
            timestamp_epoch - self.noisy_rule_window_seconds,
        )

        attacker_status = "repeat" if attacker_seen_before else "new"
        pattern_status = "repeat" if pattern_seen_before else "new"
        if attacker_seen_before:
            self.repeat_attackers += 1
        else:
            self.new_attackers += 1
        if pattern_seen_before:
            self.repeat_patterns += 1
        else:
            self.new_patterns += 1

        if base["incident_detected"]:
            self.incidents += 1
        if base["policy_allowed"] is False:
            self.blocked_actions += 1

        suppression = self._evaluate_suppression(
            base,
            recent_rule_hits=recent_rule_hits,
            timestamp_epoch=timestamp_epoch,
        )
        if suppression["suppressed"]:
            self.suppressed += 1
        if suppression["possible_false_positive"]:
            self.possible_false_positives += 1

        record = {
            "record_type": "incident",
            "test_mode": self.test_mode_enabled,
            "recent_window_seconds": self.recent_window_seconds,
            "repeat_window_seconds": self.repeat_window_seconds,
            "recent_count": recent_count,
            "repeat_count": repeat_count,
            "recent_pattern_count": recent_pattern_count,
            "recent_rule_hits": recent_rule_hits,
            "attacker_status": attacker_status,
            "pattern_status": pattern_status,
            "unique_attackers": len(self._known_attackers),
            "unique_patterns": len(self._known_patterns),
            "suppression": suppression,
            "model_calls": list(decision.get("model_calls", []))
            if isinstance(decision, Mapping)
            else [],
            "outcome": str(
                (decision or {}).get("execution_result")
                or (decision or {}).get("policy_rationale")
                or "n/a"
            ),
            **self._queue_snapshot(),
            **base,
        }

        test_fail_reasons: list[str] = []
        if self.test_mode_enabled:
            reasoning = str(record.get("decision_reasoning") or "").lower()
            if reasoning.startswith("safe fallback:"):
                test_fail_reasons.append("reasoner_fallback")
            if record.get("outcome") == "dispatch_failed":
                test_fail_reasons.append("executor_dispatch_failed")
            for call in record["model_calls"]:
                if not isinstance(call, Mapping):
                    continue
                if call.get("success") is False:
                    test_fail_reasons.append(
                        str(call.get("failure_reason") or "model_call_failed")
                    )
            if suppression["possible_false_positive"]:
                test_fail_reasons.append("possible_false_positive")

        test_pass = self.test_mode_enabled and not test_fail_reasons
        test_fail = self.test_mode_enabled and not test_pass
        record["test_pass"] = test_pass
        record["test_fail"] = test_fail
        record["test_fail_reasons"] = test_fail_reasons

        with METRICS_LOCK:
            METRICS["live_monitor_events"] += 1
            if base["incident_detected"]:
                METRICS["live_monitor_incidents"] += 1
            if suppression["suppressed"]:
                METRICS["live_monitor_suppressed"] += 1
            if suppression["possible_false_positive"]:
                METRICS["live_monitor_possible_false_positives"] += 1
            METRICS.setdefault("live_monitor_test_passed", 0)
            METRICS.setdefault("live_monitor_test_failed", 0)
            if test_pass:
                METRICS["live_monitor_test_passed"] += 1
            if test_fail:
                METRICS["live_monitor_test_failed"] += 1

        if self.test_mode_enabled:
            self._threat_totals[record["threat_class"]] += 1
            self._source_totals[record["source"]] += 1
            if test_fail:
                self.test_failed += 1
                self._threat_failures[record["threat_class"]] += 1
                self._source_failures[record["source"]] += 1
                for reason in test_fail_reasons:
                    self._failure_reasons[reason] += 1
            else:
                self.test_passed += 1

        self._write_structured(record)
        if self.enabled and self.human_live_enabled and not suppression["suppressed"]:
            self.log.warning(format_human_incident(record))
            self._emit_history[record["fingerprint"]] = timestamp_epoch
            self._cap_store(self._emit_history)
        return record

    def build_summary(self, *, now: datetime | None = None) -> dict[str, Any]:
        now = now or datetime.now(timezone.utc)
        strongest_areas = [
            f"{threat_class}:{count}"
            for threat_class, count in self._threat_totals.most_common(3)
            if self._threat_failures.get(threat_class, 0) == 0
        ]
        weakest_areas = [
            f"{failure_reason}:{count}"
            for failure_reason, count in self._failure_reasons.most_common(3)
        ]
        total_test = self.test_passed + self.test_failed
        pass_rate = (self.test_passed / total_test) if total_test else 0.0
        summary = {
            "record_type": "summary",
            "test_mode": True,
            "timestamp": _iso_zulu(now),
            "total_events": self.total_events,
            "incidents": self.incidents,
            "blocked_actions": self.blocked_actions,
            "unique_attackers": len(self._known_attackers),
            "repeat_attackers": self.repeat_attackers,
            "new_attackers": self.new_attackers,
            "repeat_patterns": self.repeat_patterns,
            "new_patterns": self.new_patterns,
            "suppressed": self.suppressed,
            "possible_false_positive_queue": len(self._possible_false_positive_queue),
            "test_passed": self.test_passed,
            "test_failed": self.test_failed,
            "test_pass_rate": pass_rate,
            "strongest_areas": strongest_areas,
            "weakest_areas": weakest_areas,
            "dropped_events": METRICS.get("events_dropped", 0),
            **self._queue_snapshot(),
        }
        return summary

    def emit_due_summary(self, *, force: bool = False) -> dict[str, Any] | None:
        if not self.enabled or not self.test_mode_enabled:
            return None
        now = datetime.now(timezone.utc)
        now_ts = now.timestamp()
        if not force and self._last_summary_ts:
            if (now_ts - self._last_summary_ts) < self.summary_interval_seconds:
                return None
        summary = self.build_summary(now=now)
        self._last_summary_ts = now_ts
        with METRICS_LOCK:
            METRICS["live_monitor_summaries"] += 1
        self._write_structured(summary)
        if self.human_live_enabled:
            self.log.info(format_test_mode_summary(summary))
        return summary
