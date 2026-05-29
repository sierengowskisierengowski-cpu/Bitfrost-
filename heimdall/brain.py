#!/usr/bin/env python3
"""
Heimdall Brain v0.1.0

The single interface guardian.py calls.
Coordinates the full pipeline in order:
  extractor -> anonymizer -> memory -> reasoner -> policy gate

Every decision goes through here.
Nothing reaches the executor without passing brain first.
"""

from __future__ import annotations
import ipaddress
import logging
import json
from datetime import datetime, timezone
from typing import Optional

from heimdall.schema import (
    Decision, RawEvent, ActionType, Severity,
    validate_decision_dict, SCHEMA_VERSION
)
from bifrost.policy import (
    evaluate_policy, Decision as PolicyDecision,
    ActionType as PolicyActionType, SAFE_DEFAULTS
)

log = logging.getLogger("heimdall.brain")


class BifrostBrain:
    def __init__(self, config: dict):
        self.config = config
        self.tier = config.get("hardware_tier", "TIER_4")
        self.learning_mode = config.get("learning_mode", True)
        self.dry_run = config.get("dry_run", True)
        self.autonomous_enabled = config.get("autonomous_actions_enabled", False)
        self.confidence_threshold = config.get(
            "confidence_threshold", SAFE_DEFAULTS["confidence_threshold"]
        )
        self.min_evidence = config.get(
            "min_evidence_count",
            SAFE_DEFAULTS["min_repeated_evidence_for_destructive"]
        )
        self.event_count = 0
        self.decision_count = 0
        self.fallback_count = 0
        self.policy_block_count = 0

        log.info(
            f"BifrostBrain initialized: tier={self.tier} "
            f"learning={self.learning_mode} "
            f"dry_run={self.dry_run} "
            f"autonomous={self.autonomous_enabled}"
        )

    def process_event(self, raw_event: dict) -> Optional[dict]:
        self.event_count += 1

        try:
            from heimdall.schema import validate_raw_event
            event = validate_raw_event(raw_event)
        except Exception as ex:
            log.warning(f"Brain: invalid event envelope: {ex}")
            return None

        boundary = event.boundary.value
        source = event.source

        raw_data = event.raw if isinstance(event.raw, dict) else {}
        is_breakout = raw_data.get("alert") in [
            "honeypot_to_host_connection",
            "container_escape_detected"
        ]

        if boundary == "HONEYPOT" and not is_breakout:
            log.debug(f"Brain: honeypot noise from {source} — skip reasoning.")
            return None

        compressed = self._extract(event)
        anonymized, anon_instance = self._anonymize(compressed)
        self._update_memory(anonymized)
        raw_decision = self._reason(anonymized)
        decision = validate_decision_dict(raw_decision)

        if anon_instance:
            decision = self._deanonymize(decision, anon_instance)

        decision = self._apply_policy(decision)
        audit = self._build_audit_record(event, decision)
        self.decision_count += 1

        log.info(
            f"Brain: decision={decision.action_required.value} "
            f"effective={decision.action_effective} "
            f"severity={decision.severity.value} "
            f"confidence={decision.confidence:.2f} "
            f"boundary={boundary}"
        )

        return audit

    def _extract(self, event: RawEvent) -> dict:
        try:
            from bifrost.extractor import compress_event
            return compress_event(event.to_dict(), self.config)
        except Exception as ex:
            log.warning(f"Brain: extractor failed: {ex}. Using raw.")
            raw = event.raw if isinstance(event.raw, dict) else {}
            return {
                "event_type": event.source,
                "boundary": event.boundary.value,
                "timestamp": event.timestamp,
                "raw_snippet": str(raw)[:200],
                "extraction_method": "fallback"
            }

    def _anonymize(self, compressed: dict) -> tuple:
        try:
            from bifrost.anonymizer import anonymize_for_external_api
            anonymized, anon = anonymize_for_external_api(compressed, self.config)
            return anonymized, anon
        except Exception as ex:
            log.warning(f"Brain: anonymizer failed: {ex}.")
            return compressed, None

    def _update_memory(self, compressed: dict):
        try:
            from heimdall.memory import update_buffer
            update_buffer(compressed)
        except Exception as ex:
            log.debug(f"Brain: memory update failed: {ex}")

    def _reason(self, compressed: dict) -> dict:
        try:
            from bifrost.reasoner import route_to_heimdall
            decision = route_to_heimdall(compressed, self.config)
            if decision:
                return decision
        except Exception as ex:
            log.warning(f"Brain: reasoner failed: {ex}")
            self.fallback_count += 1

        try:
            from bifrost.reasoner import apply_deterministic_rules
            decision = apply_deterministic_rules(compressed, self.config)
            if decision:
                self.fallback_count += 1
                return decision
        except Exception as ex:
            log.warning(f"Brain: deterministic rules failed: {ex}")

        self.fallback_count += 1
        return Decision.safe_fallback("all_reasoners_failed").to_dict()

    def _deanonymize(self, decision: Decision, anon) -> Decision:
        try:
            d = decision.to_dict()
            restored = anon.deanonymize_decision(d)
            return validate_decision_dict(restored)
        except Exception as ex:
            log.warning(f"Brain: deanonymize failed: {ex}")
            return decision

    def _apply_policy(self, decision: Decision) -> Decision:
        try:
            pid = None
            dest_ip = None
            process_name = None
            target = decision.target or ""

            if target.startswith("pid:"):
                try:
                    pid = int(target.split(":")[1])
                except Exception:
                    pass
            elif target:
                try:
                    ipaddress.ip_address(target)
                    dest_ip = target
                except ValueError:
                    pass

            policy_decision = PolicyDecision(
                action=PolicyActionType(decision.action_required.value),
                confidence=decision.confidence,
                reason=decision.reasoning,
                pid=pid,
                process_name=process_name,
                destination_ip=dest_ip,
                is_system_process=False,
                evidence_count=2,
                event_window_seconds=60,
            )

            result = evaluate_policy(
                policy_decision,
                learning_mode=self.learning_mode,
                dry_run=self.dry_run,
                autonomous_enabled=self.autonomous_enabled,
                confidence_threshold=self.confidence_threshold,
                min_repeated_evidence_for_destructive=self.min_evidence,
            )

            decision.action_effective = ActionType(result.downgraded_action.value)
            decision.policy_rationale = result.rationale

            if not result.allowed:
                self.policy_block_count += 1
                log.info(
                    f"Brain: policy blocked {decision.action_required.value} "
                    f"-> {decision.action_effective.value}: {result.rationale}"
                )

            return decision

        except Exception as ex:
            log.error(f"Brain: policy gate error: {ex}. Defaulting to ALERT.")
            decision.action_effective = ActionType.ALERT
            decision.policy_rationale = f"Policy gate error: {ex}"
            return decision

    def _build_audit_record(self, event: RawEvent, decision: Decision) -> dict:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "event_id": decision.event_id,
            "source": event.source,
            "boundary": event.boundary.value,
            "schema_version": SCHEMA_VERSION,
            "incident_detected": decision.incident_detected,
            "severity": decision.severity.value,
            "threat_class": decision.threat_class,
            "confidence": decision.confidence,
            "action_requested": decision.action_required.value,
            "action_effective": (
                decision.action_effective.value
                if decision.action_effective else "NONE"
            ),
            "policy_rationale": decision.policy_rationale,
            "reasoning": decision.reasoning,
            "extractor_model": decision.extractor_model,
            "reasoner_model": decision.reasoner_model,
            "hardware_tier": self.tier,
            "rollback_id": decision.rollback_id,
            "learning_mode": self.learning_mode,
            "dry_run": self.dry_run,
        }

    def get_status(self) -> dict:
        return {
            "tier": self.tier,
            "learning_mode": self.learning_mode,
            "dry_run": self.dry_run,
            "autonomous_enabled": self.autonomous_enabled,
            "events_processed": self.event_count,
            "decisions_made": self.decision_count,
            "fallbacks_triggered": self.fallback_count,
            "policy_blocks": self.policy_block_count,
            "fallback_rate": round(
                self.fallback_count / max(self.decision_count, 1), 3
            ),
        }

    def update_baseline(self, baseline: dict):
        self.config["baseline_context"] = baseline
        log.info("Brain: baseline context updated.")
