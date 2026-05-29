#!/usr/bin/env python3
"""
Bifrost Reasoner v0.1.0

The Heimdall intelligence layer. Takes compressed events
from the extractor, builds attack chain context from the
rolling event buffer, routes to the correct AI model
based on hardware tier, enforces deterministic JSON schema,
and returns Heimdall's decision.

Routing priority:
1. Local Ollama model (Qwen 3 27B on TIER_1)
2. Groq API (fast cloud fallback)
3. Claude API (deep reasoning for complex events)
4. Deterministic rule engine (never goes blind)
"""

import os
import json
import logging
import sqlite3
from datetime import datetime, timezone

def _parse_ts(ts: str):
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def detect_cowrie_dns_pivot_chain(events: list) -> list:
    """
    Detect chain:
      - cowrie.login.success
      - cowrie.direct-tcpip.request (dst_port=53)
      - same session + src_ip
      - within <= 5 seconds

    This is a confirmed automated C2 callback pattern.
    Captured live from GowskiNet 2026-05-29: 87.251.64.176
    """
    by_session = {}
    for e in events:
        sid = e.get("session")
        if not sid:
            continue
        by_session.setdefault(sid, []).append(e)

    detections = []
    for sid, sess_events in by_session.items():
        sess_events.sort(key=lambda x: x.get("timestamp", ""))

        login_evt = None
        for e in sess_events:
            if e.get("eventid") == "cowrie.login.success":
                login_evt = e
                break

        if not login_evt:
            continue

        t_login = _parse_ts(login_evt.get("timestamp", ""))
        src_ip = login_evt.get("src_ip")

        for e in sess_events:
            if e.get("eventid") != "cowrie.direct-tcpip.request":
                continue
            if e.get("src_ip") != src_ip:
                continue
            if int(e.get("dst_port", -1)) != 53:
                continue
            t_req = _parse_ts(e.get("timestamp", ""))
            if not t_login or not t_req:
                continue
            delta = (t_req - t_login).total_seconds()
            if 0 <= delta <= 5:
                detections.append({
                    "rule_id": "COWRIE_DNS_PIVOT_AFTER_LOGIN",
                    "schema_version": "0.1.0",
                    "incident_detected": True,
                    "severity": "HIGH",
                    "boundary": "HONEYPOT",
                    "threat_class": "dns_tunnel_pivot",
                    "confidence": 0.97,
                    "action_required": "BLOCK",
                    "target": src_ip,
                    "gjallarhorn_tier": 2,
                    "reasoning": (
                        "SSH login success followed by direct-tcpip DNS "
                        "forward within 5s. Confirmed automated C2 callback."
                    ),
                    "session": sid,
                    "src_ip": src_ip,
                    "dst_ip": e.get("dst_ip"),
                    "dst_port": e.get("dst_port"),
                    "evidence_count": 2,
                    "extractor_model": "deterministic",
                    "reasoner_model": "deterministic_rule",
                    "hardware_tier": "TIER_4",
                })
                break

    return detections

from collections import deque
from pathlib import Path
from typing import Optional

from bifrost.extractor import format_for_heimdall
from bifrost.inference import (
    CircuitBreaker,
    execute_with_retry,
    get_request_timeout,
)

log = logging.getLogger("heimdall.reasoner")

DB_PATH = Path("~/Projects/bifrost/db/events.db").expanduser()
INFERENCE_CIRCUIT_BREAKERS = {
    "ollama": CircuitBreaker(),
    "groq": CircuitBreaker(),
    "claude": CircuitBreaker(),
}

# Rolling event buffer per source IP and per process
# Heimdall sees attack chains not just individual events
IP_BUFFER: dict[str, deque] = {}
PROCESS_BUFFER: dict[str, deque] = {}
BUFFER_SIZE = 10

# Deterministic rule engine — the floor
# Used when all AI options are unavailable
# Never returns blind — always makes a decision
DETERMINISTIC_RULES = [
    {
        "name": "execve_from_tmp",
        "condition": lambda e: (
            e.get("path") and "/tmp/" in e.get("path", "")
        ),
        "severity": "HIGH",
        "action": "ALERT",
        "threat_class": "suspicious_execution",
        "confidence": 0.85
    },
    {
        "name": "execve_from_shm",
        "condition": lambda e: (
            e.get("path") and "/dev/shm/" in e.get("path", "")
        ),
        "severity": "CRITICAL",
        "action": "KILL",
        "threat_class": "fileless_execution",
        "confidence": 0.95
    },
    {
        "name": "kernel_masquerade",
        "condition": lambda e: (
            e.get("alert_signal") == "True" and
            e.get("event_type") == "process.watcher"
        ),
        "severity": "HIGH",
        "action": "ALERT",
        "threat_class": "process_masquerade",
        "confidence": 0.80
    },
    {
        "name": "honeypot_breakout",
        "condition": lambda e: (
            e.get("alert_signal") == "honeypot_to_host_connection"
        ),
        "severity": "CRITICAL",
        "action": "BLOCK",
        "threat_class": "container_escape",
        "confidence": 0.99
    },
    {
        "name": "shadow_write",
        "condition": lambda e: (
            e.get("path") and
            any(p in e.get("path", "") for p in [
                "/etc/passwd", "/etc/shadow", "/etc/sudoers"
            ])
        ),
        "severity": "CRITICAL",
        "action": "ALERT",
        "threat_class": "credential_tampering",
        "confidence": 0.98
    },
    {
        "name": "wget_curl_from_honeypot_user",
        "condition": lambda e: (
            e.get("command") and
            any(c in e.get("command", "") for c in ["wget", "curl"]) and
            e.get("boundary") == "HOST"
        ),
        "severity": "MEDIUM",
        "action": "ALERT",
        "threat_class": "suspicious_download",
        "confidence": 0.70
    },
]


def build_schema(
    incident: bool,
    severity: str,
    boundary: str,
    threat_class: str,
    confidence: float,
    action: str,
    target: Optional[str],
    gjallarhorn_tier: int,
    reasoning: str,
    extractor_model: str,
    reasoner_model: str,
    hardware_tier: str,
    schema_version: str = "0.1.0"
) -> dict:
    """
    Builds a validated Heimdall decision that conforms
    exactly to the output schema defined in setup.py.
    Every response from Heimdall must pass through this.
    """
    return {
        "schema_version": schema_version,
        "incident_detected": incident,
        "severity": severity,
        "boundary": boundary,
        "threat_class": threat_class,
        "confidence": round(float(confidence), 2),
        "action_required": action,
        "target": target,
        "gjallarhorn_tier": gjallarhorn_tier,
        "reasoning": reasoning[:200],
        "extractor_model": extractor_model,
        "reasoner_model": reasoner_model,
        "hardware_tier": hardware_tier
    }


def apply_deterministic_rules(compressed: dict, config: dict) -> Optional[dict]:
    """
    Runs the deterministic rule engine against the compressed event.
    Returns a decision if any rule matches, None if no rule applies.
    This is the fallback floor — always available, zero latency.
    """
    tier = config.get("hardware_tier", "TIER_4")
    extractor_model = compressed.get("extractor_model", "deterministic")

    for rule in DETERMINISTIC_RULES:
        try:
            if rule["condition"](compressed):
                log.info(f"Deterministic rule matched: {rule['name']}")
                action = rule["action"]
                severity = rule["severity"]
                gjallarhorn_tier = 2 if severity == "CRITICAL" else 1

                return build_schema(
                    incident=True,
                    severity=severity,
                    boundary=compressed.get("boundary", "UNKNOWN"),
                    threat_class=rule["threat_class"],
                    confidence=rule["confidence"],
                    action=action,
                    target=compressed.get("ip") or compressed.get("path"),
                    gjallarhorn_tier=gjallarhorn_tier,
                    reasoning=f"Deterministic rule: {rule['name']}",
                    extractor_model=extractor_model,
                    reasoner_model="deterministic_rules",
                    hardware_tier=tier
                )
        except Exception as e:
            log.warning(f"Rule {rule['name']} evaluation error: {e}")
            continue

    return None


def update_event_buffer(compressed: dict) -> list:
    """
    Maintains rolling buffers of the last 10 events
    per source IP and per process. Returns the current
    buffer context for Heimdall to reason over as a chain.
    """
    ip = compressed.get("ip")
    process = compressed.get("process")

    if ip:
        if ip not in IP_BUFFER:
            IP_BUFFER[ip] = deque(maxlen=BUFFER_SIZE)
        IP_BUFFER[ip].append(compressed)
        return list(IP_BUFFER[ip])

    if process:
        if process not in PROCESS_BUFFER:
            PROCESS_BUFFER[process] = deque(maxlen=BUFFER_SIZE)
        PROCESS_BUFFER[process].append(compressed)
        return list(PROCESS_BUFFER[process])

    return [compressed]


def load_false_positives() -> list:
    """
    Loads known false positive patterns from the database.
    Included in the Heimdall prompt so it learns from corrections.
    """
    if not DB_PATH.exists():
        return []
    try:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        cursor.execute(
            "SELECT threat_class, pattern FROM false_positives "
            "ORDER BY marked_at DESC LIMIT 20"
        )
        rows = cursor.fetchall()
        conn.close()
        return [
            {"threat_class": r[0], "pattern": r[1]}
            for r in rows
        ]
    except Exception as e:
        log.warning(f"False positive load failed: {e}")
        return []


def build_heimdall_prompt(
    event_chain: list,
    false_positives: list,
    config: dict
) -> str:
    """
    Builds the full reasoning prompt for Heimdall.
    Includes the attack chain context and any known
    false positive patterns to reduce noise over time.
    """
    chain_text = format_for_heimdall(event_chain)

    fp_text = ""
    if false_positives:
        fp_lines = [
            f"- {fp['threat_class']}: {fp['pattern']}"
            for fp in false_positives
        ]
        fp_text = (
            "\n\nKnown false positive patterns — do not flag these:\n" +
            "\n".join(fp_lines)
        )

    prompt = (
        f"{chain_text}"
        f"{fp_text}"
        f"\n\nAnalyze the above event sequence and return your "
        f"decision as a single JSON object matching the output schema. "
        f"Consider the full sequence as an attack chain, not just "
        f"individual events. Return ONLY the JSON object."
    )

    return prompt


def route_to_ollama(
    prompt: str,
    system_baseline: str,
    config: dict
) -> Optional[dict]:
    """
    Routes to local Ollama model (Qwen 3 27B on TIER_1).
    Fastest for high-end hardware. Fully air gapped.
    """
    try:
        from openai import OpenAI
        client = OpenAI(
            base_url=config.get("local_url", "http://localhost:11434/v1"),
            api_key="ollama",
            timeout=get_request_timeout(config)
        )
        model = config.get("analyst_model")
        if not model:
            return None

        response, _ = execute_with_retry(
            lambda: client.chat.completions.create(
                model=model,
                temperature=0.0,
                messages=[
                    {"role": "system", "content": system_baseline},
                    {"role": "user", "content": prompt}
                ]
            ),
            provider="ollama",
            config=config,
            logger=log,
            circuit_breaker=INFERENCE_CIRCUIT_BREAKERS["ollama"],
        )
        if not response:
            return None

        content = response.choices[0].message.content.strip()
        return json.loads(content)

    except Exception as e:
        log.warning(f"Ollama routing failed: {e}")
        return None


def route_to_groq(
    prompt: str,
    system_baseline: str,
    config: dict
) -> Optional[dict]:
    """
    Routes to Groq API. Fast cloud fallback.
    Direct — no middleman aggregator.
    """
    try:
        api_key = os.getenv("HEIMDALL_API_KEY", "")
        if not api_key:
            log.warning("HEIMDALL_API_KEY not set. Groq unavailable.")
            return None

        from openai import OpenAI
        client = OpenAI(
            base_url=config.get(
                "groq_url", "https://api.groq.com/openai/v1"
            ),
            api_key=api_key,
            timeout=get_request_timeout(config)
        )
        model = config.get("groq_model", "llama-3.3-70b-versatile")

        response, _ = execute_with_retry(
            lambda: client.chat.completions.create(
                model=model,
                temperature=0.0,
                messages=[
                    {"role": "system", "content": system_baseline},
                    {"role": "user", "content": prompt}
                ]
            ),
            provider="groq",
            config=config,
            logger=log,
            circuit_breaker=INFERENCE_CIRCUIT_BREAKERS["groq"],
        )
        if not response:
            return None

        content = response.choices[0].message.content.strip()
        return json.loads(content)

    except Exception as e:
        log.warning(f"Groq routing failed: {e}")
        return None


def route_to_claude(
    prompt: str,
    system_baseline: str,
    config: dict
) -> Optional[dict]:
    """
    Routes to Claude API. Deep reasoning for complex events.
    Used when local model and Groq are both unavailable.
    """
    try:
        import anthropic
        api_key = os.getenv("HEIMDALL_CLAUDE_KEY", "")
        if not api_key:
            log.warning("HEIMDALL_CLAUDE_KEY not set. Claude unavailable.")
            return None

        client = anthropic.Anthropic(
            api_key=api_key,
            timeout=get_request_timeout(config)
        )
        model = config.get("claude_model", "claude-sonnet-4-20250514")

        message, _ = execute_with_retry(
            lambda: client.messages.create(
                model=model,
                max_tokens=1024,
                system=system_baseline,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            ),
            provider="claude",
            config=config,
            logger=log,
            circuit_breaker=INFERENCE_CIRCUIT_BREAKERS["claude"],
        )
        if not message:
            return None

        content = message.content[0].text.strip()
        return json.loads(content)

    except Exception as e:
        log.warning(f"Claude routing failed: {e}")
        return None


def validate_and_normalize(
    decision: dict,
    compressed: dict,
    reasoner_model: str,
    config: dict
) -> dict:
    """
    Validates the AI decision against our schema.
    Fills in any missing fields with safe defaults.
    Ensures Heimdall always returns a valid decision.
    """
    tier = config.get("hardware_tier", "TIER_4")
    extractor_model = compressed.get("extractor_model", "deterministic")

    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    valid_actions = {"KILL", "BLOCK", "QUARANTINE", "ALERT", "LOG", "NONE"}
    valid_boundaries = {"HOST", "HONEYPOT", "NETWORK", "UNKNOWN"}

    severity = decision.get("severity", "LOW")
    if severity not in valid_severities:
        severity = "LOW"

    action = decision.get("action_required", "LOG")
    if action not in valid_actions:
        action = "LOG"

    boundary = decision.get("boundary", compressed.get("boundary", "UNKNOWN"))
    if boundary not in valid_boundaries:
        boundary = "UNKNOWN"

    confidence = float(decision.get("confidence", 0.5))
    confidence = max(0.0, min(1.0, confidence))

    gjallarhorn_tier = 2 if severity in {"CRITICAL", "HIGH"} else 1

    return build_schema(
        incident=decision.get("incident_detected", False),
        severity=severity,
        boundary=boundary,
        threat_class=decision.get("threat_class", "unknown"),
        confidence=confidence,
        action=action,
        target=decision.get("target"),
        gjallarhorn_tier=gjallarhorn_tier,
        reasoning=decision.get("reasoning", "AI decision")[:200],
        extractor_model=extractor_model,
        reasoner_model=reasoner_model,
        hardware_tier=tier,
        schema_version=decision.get("schema_version", "0.1.0")
    )


def route_to_heimdall(compressed: dict, config: dict) -> Optional[dict]:
    """
    Main entry point for Heimdall reasoning.

    Full routing chain:
    1. Update rolling event buffer — build attack chain context
    2. Try Ollama local model (TIER_1 / TIER_2)
    3. Try Groq API (TIER_3 / TIER_4 fallback)
    4. Try Claude API (deep reasoning fallback)
    5. Apply deterministic rules (always available floor)

    Returns a validated Heimdall decision dict or None.
    """
    tier = config.get("hardware_tier", "TIER_4")
    system_baseline = config.get("system_baseline", "")

    # Build attack chain context
    event_chain = update_event_buffer(compressed)
    false_positives = load_false_positives()
    prompt = build_heimdall_prompt(event_chain, false_positives, config)

    decision = None
    reasoner_model = "unknown"

    # TIER_1 and TIER_2 — try local Ollama first
    if config.get("use_local_llm") and tier in ["TIER_1", "TIER_2"]:
        log.debug(f"Routing to Ollama: {config.get('analyst_model')}")
        raw = route_to_ollama(prompt, system_baseline, config)
        if raw:
            decision = raw
            reasoner_model = config.get("analyst_model", "ollama")

    # Groq fallback
    if not decision:
        log.debug("Routing to Groq.")
        raw = route_to_groq(prompt, system_baseline, config)
        if raw:
            decision = raw
            reasoner_model = config.get("groq_model", "groq")

    # Claude fallback
    if not decision:
        log.debug("Routing to Claude.")
        raw = route_to_claude(prompt, system_baseline, config)
        if raw:
            decision = raw
            reasoner_model = config.get("claude_model", "claude")

    # Deterministic rule engine — always available
    if not decision:
        log.info("All AI routes failed. Applying deterministic rules.")
        return apply_deterministic_rules(compressed, config)

    # Validate and normalize the AI decision
    try:
        return validate_and_normalize(
            decision, compressed, reasoner_model, config
        )
    except Exception as e:
        log.error(f"Decision validation failed: {e}")
        return apply_deterministic_rules(compressed, config)


if __name__ == "__main__":
    test_compressed = {
        "event_type": "process.watcher",
        "boundary": "HOST",
        "timestamp": "2026-05-28T03:00:00Z",
        "process": "wget",
        "path": "/tmp/malware.sh",
        "ip": None,
        "port": None,
        "user": "0",
        "command": "/tmp/malware.sh -c install",
        "syscall": "execve",
        "alert_signal": "scratch_space_exec",
        "raw_snippet": "pid=5678 exe=/tmp/malware.sh",
        "extraction_method": "deterministic",
        "extractor_model": "deterministic"
    }

    test_config = {
        "hardware_tier": "TIER_4",
        "use_local_llm": False,
        "analyst_model": None,
        "groq_model": "llama-3.3-70b-versatile",
        "groq_url": "https://api.groq.com/openai/v1",
        "claude_model": "claude-sonnet-4-20250514",
        "system_baseline": "You are Heimdall-Core. Analyze threats.",
    }

    print("Testing deterministic rule engine...")
    result = route_to_heimdall(test_compressed, test_config)
    print(json.dumps(result, indent=2))
