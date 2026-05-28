#!/usr/bin/env python3
"""
Bifrost Schema v0.1.0

Strict data contracts for pipeline internals.
- RawEvent: event envelope entering pipeline
- Decision: reasoner output entering policy gate

Rule: Convert dict <-> model only at IO boundaries.
"""

from __future__ import annotations
from enum import Enum
from typing import Optional, Any
from datetime import datetime, timezone

SCHEMA_VERSION = "0.1.0"

try:
    from pydantic import BaseModel, ConfigDict, field_validator
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class Boundary(str, Enum):
    HOST      = "HOST"
    HONEYPOT  = "HONEYPOT"
    NETWORK   = "NETWORK"
    UNKNOWN   = "UNKNOWN"


class ActionType(str, Enum):
    KILL       = "KILL"
    BLOCK      = "BLOCK"
    QUARANTINE = "QUARANTINE"
    ALERT      = "ALERT"
    LOG        = "LOG"
    NONE       = "NONE"


DESTRUCTIVE_ACTIONS = {ActionType.KILL, ActionType.BLOCK, ActionType.QUARANTINE}
SAFE_ACTIONS        = {ActionType.ALERT, ActionType.LOG, ActionType.NONE}


def _normalize_iso8601(ts: str) -> str:
    if not ts:
        return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    t = ts.strip()
    if t.endswith("Z"):
        t = t[:-1] + "+00:00"
    parsed = datetime.fromisoformat(t)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


if PYDANTIC_AVAILABLE:

    class RawEvent(BaseModel):
        model_config = ConfigDict(extra="forbid", validate_assignment=True)

        source:    str
        timestamp: str
        boundary:  Boundary
        raw:       Any

        @field_validator("timestamp", mode="before")
        @classmethod
        def validate_timestamp(cls, v):
            return _normalize_iso8601("" if v is None else str(v))

        @field_validator("source")
        @classmethod
        def validate_source(cls, v: str):
            if not v or not v.strip():
                raise ValueError("source cannot be empty")
            return v.strip()

        def to_dict(self) -> dict:
            return {
                "source":    self.source,
                "timestamp": self.timestamp,
                "boundary":  self.boundary.value,
                "raw":       self.raw,
            }

        @classmethod
        def from_dict(cls, d: dict) -> "RawEvent":
            return cls.model_validate(d)


    class Decision(BaseModel):
        model_config = ConfigDict(extra="forbid", validate_assignment=True)

        schema_version:    str            = SCHEMA_VERSION
        incident_detected: bool           = False
        severity:          Severity       = Severity.INFO
        boundary:          Boundary       = Boundary.UNKNOWN
        threat_class:      str            = "unknown"
        confidence:        float          = 0.0
        action_required:   ActionType     = ActionType.NONE
        target:            Optional[str]  = None
        gjallarhorn_tier:  int            = 1
        reasoning:         str            = ""
        extractor_model:   str            = "unknown"
        reasoner_model:    str            = "unknown"
        hardware_tier:     str            = "TIER_4"
        action_effective:  Optional[ActionType] = None
        policy_rationale:  Optional[str]  = None
        rollback_id:       Optional[str]  = None
        event_id:          Optional[str]  = None

        @field_validator("schema_version", mode="before")
        @classmethod
        def normalize_schema_version(cls, v):
            if v and str(v) != SCHEMA_VERSION:
                import logging
                logging.getLogger("heimdall.schema").warning(
                    f"schema_version mismatch: got {v}, locking to {SCHEMA_VERSION}"
                )
            return SCHEMA_VERSION

        @field_validator("confidence", mode="before")
        @classmethod
        def clamp_confidence(cls, v):
            try:
                f = float(v)
            except Exception:
                f = 0.0
            return max(0.0, min(1.0, f))

        @field_validator("reasoning", mode="before")
        @classmethod
        def truncate_reasoning(cls, v):
            return ("" if v is None else str(v))[:200]

        @field_validator("gjallarhorn_tier", mode="before")
        @classmethod
        def validate_tier(cls, v):
            try:
                i = int(v)
            except Exception:
                i = 1
            return i if i in (1, 2) else 2

        def is_destructive(self) -> bool:
            return self.action_required in DESTRUCTIVE_ACTIONS

        def is_safe(self) -> bool:
            return self.action_required in SAFE_ACTIONS

        def to_dict(self) -> dict:
            return {
                "schema_version":    self.schema_version,
                "incident_detected": self.incident_detected,
                "severity":          self.severity.value,
                "boundary":          self.boundary.value,
                "threat_class":      self.threat_class,
                "confidence":        round(self.confidence, 3),
                "action_required":   self.action_required.value,
                "target":            self.target,
                "gjallarhorn_tier":  self.gjallarhorn_tier,
                "reasoning":         self.reasoning,
                "extractor_model":   self.extractor_model,
                "reasoner_model":    self.reasoner_model,
                "hardware_tier":     self.hardware_tier,
                "action_effective":  self.action_effective.value
                                     if self.action_effective else None,
                "policy_rationale":  self.policy_rationale,
                "rollback_id":       self.rollback_id,
                "event_id":          self.event_id,
            }

        @classmethod
        def from_dict(cls, d: dict) -> "Decision":
            import logging
            log = logging.getLogger("heimdall.schema")
            decision = cls.model_validate(d)
            if not decision.incident_detected and decision.is_destructive():
                log.warning(
                    f"Contradictory payload: incident_detected=False "
                    f"but action={decision.action_required.value}. "
                    f"Downgrading to ALERT."
                )
                decision.action_required = ActionType.ALERT
            return decision

        @classmethod
        def safe_fallback(cls, reason: str = "parser_error") -> "Decision":
            return cls(
                schema_version=SCHEMA_VERSION,
                incident_detected=True,
                severity=Severity.LOW,
                boundary=Boundary.UNKNOWN,
                threat_class="parser_error",
                confidence=0.5,
                action_required=ActionType.ALERT,
                reasoning=f"Safe fallback: {reason}"[:200],
                reasoner_model="safe_fallback",
            )

else:
    import logging as _logging
    _logging.getLogger("heimdall.schema").warning(
        "Pydantic not available. Running in degraded mode. "
        "Destructive actions will be disabled."
    )
    import dataclasses

    @dataclasses.dataclass
    class RawEvent:
        source:    str
        timestamp: str
        boundary:  str
        raw:       Any

        def to_dict(self) -> dict:
            return dataclasses.asdict(self)

        @classmethod
        def from_dict(cls, d: dict):
            src = str(d.get("source", "")).strip()
            if not src:
                raise ValueError("source cannot be empty")
            ts = _normalize_iso8601(str(d.get("timestamp", "")))
            b = str(d.get("boundary", "UNKNOWN"))
            if b not in {"HOST", "HONEYPOT", "NETWORK", "UNKNOWN"}:
                b = "UNKNOWN"
            return cls(
                source=src, timestamp=ts,
                boundary=b, raw=d.get("raw", {})
            )

    @dataclasses.dataclass
    class Decision:
        schema_version:    str   = SCHEMA_VERSION
        incident_detected: bool  = False
        severity:          str   = "INFO"
        boundary:          str   = "UNKNOWN"
        threat_class:      str   = "unknown"
        confidence:        float = 0.0
        action_required:   str   = "NONE"
        target:            Any   = None
        gjallarhorn_tier:  int   = 1
        reasoning:         str   = ""
        extractor_model:   str   = "unknown"
        reasoner_model:    str   = "unknown"
        hardware_tier:     str   = "TIER_4"
        action_effective:  Any   = None
        policy_rationale:  Any   = None
        rollback_id:       Any   = None
        event_id:          Any   = None

        def __post_init__(self):
            self.confidence = max(0.0, min(1.0, float(self.confidence)))
            self.reasoning = str(self.reasoning)[:200]
            self.gjallarhorn_tier = (
                self.gjallarhorn_tier
                if self.gjallarhorn_tier in (1, 2) else 2
            )
            # Degraded mode — force safe actions only
            if self.action_required in ("KILL", "BLOCK", "QUARANTINE"):
                import logging
                logging.getLogger("heimdall.schema").warning(
                    f"Degraded mode: downgrading {self.action_required} "
                    f"to ALERT — Pydantic not available."
                )
                self.action_required = "ALERT"

        def is_destructive(self):
            return self.action_required in ("KILL", "BLOCK", "QUARANTINE")

        def is_safe(self):
            return self.action_required in ("ALERT", "LOG", "NONE")

        def to_dict(self):
            return dataclasses.asdict(self)

        @classmethod
        def from_dict(cls, d):
            allowed = {f.name for f in dataclasses.fields(cls)}
            data = {k: v for k, v in d.items() if k in allowed}
            return cls(**data)

        @classmethod
        def safe_fallback(cls, reason="parser_error"):
            return cls(
                schema_version=SCHEMA_VERSION,
                incident_detected=True,
                severity="LOW",
                boundary="UNKNOWN",
                threat_class="parser_error",
                confidence=0.5,
                action_required="ALERT",
                reasoning=f"Safe fallback: {reason}"[:200],
                reasoner_model="safe_fallback",
            )


def validate_decision_dict(d: dict) -> "Decision":
    import logging
    log = logging.getLogger("heimdall.schema")
    try:
        return Decision.from_dict(d)
    except Exception as e:
        log.warning(f"Decision validation failed: {e}. Using safe fallback.")
        return Decision.safe_fallback(str(e))


def validate_raw_event(d: dict) -> "RawEvent":
    try:
        return RawEvent.from_dict(d)
    except Exception as e:
        raise ValueError(f"Invalid event envelope: {e}")
