#!/usr/bin/env python3
"""
Bifrost Router v0.1.0

Fallback chain logic and decision execution routing.
Reads Heimdall decisions and dispatches to the Go executor.
Manages the full fallback chain:
  Local Ollama -> Groq -> Claude -> Deterministic rules
"""

import json
import logging
import urllib.request
import urllib.error
from typing import Optional

log = logging.getLogger("heimdall.router")

EXECUTOR_URL = "http://127.0.0.1:8766/execute"
EXECUTOR_HEALTH = "http://127.0.0.1:8766/health"


def executor_available() -> bool:
    """Check if the Go executor is running and reachable."""
    try:
        with urllib.request.urlopen(EXECUTOR_HEALTH, timeout=2) as resp:
            return resp.status == 200
    except Exception:
        return False


def execute_decision(
    decision: dict,
    event_id: int,
    db_path: str,
    log_ref
) -> bool:
    """
    Sends a Heimdall decision to the Go executor.
    The executor handles the actual system action —
    UFW block, process kill, or file quarantine.
    Returns True if executor accepted the decision.
    """
    action = decision.get("action_required", "NONE")

    if action in ["LOG", "NONE", "ALERT"]:
        log_ref.info(f"Router: non-disruptive action {action} — no executor call.")
        return True

    if not executor_available():
        log_ref.warning(
            f"Router: Go executor not available. "
            f"Action {action} could not be executed. "
            f"Start bifrost-agent service."
        )
        return False

    payload = {
        "action_required": action,
        "target": str(decision.get("target", "")),
        "threat_class": decision.get("threat_class", "unknown"),
        "reasoning": decision.get("reasoning", "")[:200],
        "event_id": event_id,
        "schema_version": decision.get("schema_version", "1.0.0")
    }

    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            EXECUTOR_URL,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            result = json.loads(resp.read())
            log_ref.info(
                f"Router: executor accepted action={action} "
                f"target={payload['target']} result={result}"
            )
            return True

    except urllib.error.URLError as e:
        log_ref.error(f"Router: executor unreachable: {e}")
        return False
    except Exception as e:
        log_ref.error(f"Router: dispatch error: {e}")
        return False


def rollback_last_action(action_id: int, log_ref) -> bool:
    """
    Rolls back an action by ID via the Go executor rollback endpoint.
    Called from the feedback loop when a false positive is marked.
    """
    rollback_url = "http://127.0.0.1:8766/rollback"

    if not executor_available():
        log_ref.warning("Router: executor not available for rollback.")
        return False

    try:
        payload = json.dumps({"action_id": action_id}).encode()
        req = urllib.request.Request(
            rollback_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            result = json.loads(resp.read())
            log_ref.info(f"Router: rollback executed action_id={action_id} result={result}")
            return True

    except Exception as e:
        log_ref.error(f"Router: rollback failed: {e}")
        return False


def select_model_route(config: dict) -> str:
    """
    Determines which AI backend to use based on
    hardware tier and availability.
    Returns a string identifying the route selected.
    """
    tier = config.get("hardware_tier", "TIER_4")
    use_local = config.get("use_local_llm", False)

    if use_local and tier in ["TIER_1", "TIER_2"]:
        return "ollama"

    import os
    if os.getenv("HEIMDALL_API_KEY"):
        return "groq"

    if os.getenv("HEIMDALL_CLAUDE_KEY"):
        return "claude"

    return "rules"


def get_fallback_chain(config: dict) -> list:
    """
    Returns the ordered fallback chain for this deployment.
    Heimdall tries each in order until one succeeds.
    """
    tier = config.get("hardware_tier", "TIER_4")
    use_local = config.get("use_local_llm", False)
    chain = []

    if use_local and tier in ["TIER_1", "TIER_2"]:
        chain.append("ollama")

    chain.append("groq")
    chain.append("claude")
    chain.append("rules")

    return chain
