#!/usr/bin/env python3
"""
Bifrost Extractor v0.1.0

The noise stripping layer. Takes raw system telemetry —
kernel dumps, auditd lines, process info, network events —
and compresses them into clean dense JSON summaries.

The extractor runs on the smallest model (Qwen 2.5 1.5B)
and its only job is structural filtering not reasoning.
Reasoning happens in the Heimdall layer after extraction.

This is what makes Bifrost portable across any hardware.
A clean 3-line JSON summary costs the same tokens on a Pi
as it does on an RTX 3060.
"""

import re
import json
import logging
from datetime import datetime, timezone

from bifrost.inference import CircuitBreaker, execute_with_retry, get_request_timeout

log = logging.getLogger("heimdall.extractor")

HEX_ADDRESS_PATTERN = re.compile(r'\b0x[0-9a-fA-F]+\b')
MEMORY_OFFSET_PATTERN = re.compile(r'\b[0-9a-fA-F]{8,16}\b')
REGISTER_PATTERN = re.compile(
    r'\b(rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp|rip|eax|ebx|ecx|edx|'
    r'esi|edi|esp|ebp|eip|r8|r9|r10|r11|r12|r13|r14|r15)='
    r'[0-9a-fA-F]+\b'
)
KERNEL_NOISE_PATTERN = re.compile(
    r'\[\s*\d+\.\d+\]|\bSMP\b|\bPREEMPT\b|'
    r'Call Trace:|<IRQ>|</IRQ>|Hardware name:'
)

EXTRACTOR_SYSTEM_PROMPT = """
You are a security telemetry compressor.
Your only job is to extract the security-relevant tokens
from raw system events and return them as compact JSON.

Rules you must follow without exception:
1. Strip all hex memory addresses (0x...)
2. Strip all CPU register states
3. Strip all memory offset dumps
4. Strip all kernel stack trace noise
5. Keep process names, file paths, IPs, ports, usernames
6. Keep command strings and arguments
7. Keep error codes and syscall names
8. Keep timestamps in ISO format only
9. Return ONLY raw JSON — no explanation, no preamble
10. Maximum output: 200 tokens

Output schema:
{
  "event_type": "string",
  "process": "string or null",
  "path": "string or null",
  "ip": "string or null",
  "port": "integer or null",
  "user": "string or null",
  "command": "string or null",
  "syscall": "string or null",
  "alert_signal": "string or null",
  "raw_snippet": "string max 100 chars"
}
""".strip()

EXTRACTOR_CIRCUIT_BREAKER = CircuitBreaker()


def strip_noise_deterministic(raw_text: str) -> str:
    """
    Fast deterministic noise stripping using regex.
    No model needed — runs instantly on any hardware.
    Used as pre-processing before model extraction
    and as fallback when model is unavailable.
    """
    text = str(raw_text)
    text = HEX_ADDRESS_PATTERN.sub("[addr]", text)
    text = MEMORY_OFFSET_PATTERN.sub("[offset]", text)
    text = REGISTER_PATTERN.sub("[reg]", text)
    text = KERNEL_NOISE_PATTERN.sub("", text)
    text = " ".join(text.split())
    return text[:500]


def extract_key_fields(event: dict) -> dict:
    """
    Deterministic field extraction from known event structures.
    Pulls the most important fields without needing a model.
    Works for auditd, cowrie, process watcher, and network events.
    """
    raw = event.get("raw", {})
    source = event.get("source", "unknown")
    boundary = event.get("boundary", "UNKNOWN")

    extracted = {
        "event_type": source,
        "boundary": boundary,
        "timestamp": event.get(
            "timestamp", datetime.now(timezone.utc).isoformat()
        ),
        "process": None,
        "path": None,
        "ip": None,
        "port": None,
        "user": None,
        "command": None,
        "syscall": None,
        "alert_signal": None,
        "raw_snippet": None
    }

    if isinstance(raw, str):
        pairs = dict(
            item.split("=", 1)
            for item in raw.split()
            if "=" in item
        )
        extracted["process"] = pairs.get("comm", "").strip('"')
        extracted["path"] = pairs.get("exe", "").strip('"')
        extracted["user"] = pairs.get("uid", pairs.get("auid"))
        extracted["syscall"] = pairs.get("syscall")
        extracted["command"] = pairs.get("proctitle", "").strip('"')
        extracted["raw_snippet"] = raw[:100]

    elif isinstance(raw, dict):
        if source == "cowrie":
            extracted["ip"] = raw.get("src_ip")
            extracted["port"] = raw.get("src_port")
            extracted["user"] = raw.get("username")
            extracted["command"] = raw.get("input", raw.get("message"))
            extracted["event_type"] = raw.get("eventid", source)
            extracted["raw_snippet"] = str(raw)[:100]

        elif source == "process.watcher":
            extracted["process"] = raw.get(
                "comm", raw.get("cmdline", "")[:40]
            )
            extracted["path"] = raw.get("exe")
            extracted["command"] = raw.get("cmdline", "")[:100]
            extracted["alert_signal"] = (
                raw.get("alert") or
                str(raw.get("indicators", {}).get("scratch_space_exec") or
                    raw.get("indicators", {}).get("kernel_masquerade"))
            )
            extracted["raw_snippet"] = str(raw)[:100]

        elif source == "network_watcher":
            extracted["ip"] = raw.get("remote_ip")
            extracted["port"] = raw.get("local_port")
            extracted["alert_signal"] = raw.get("alert")
            extracted["raw_snippet"] = str(raw)[:100]

        else:
            extracted["alert_signal"] = raw.get("alert")
            extracted["raw_snippet"] = str(raw)[:100]

    return extracted


def compress_event_with_model(event: dict, client, model: str, config: dict) -> dict:
    """
    Uses the 1.5B extractor model to compress the event.
    Falls back to deterministic extraction if model fails.
    """
    try:
        raw_text = json.dumps(event.get("raw", {}))
        pre_stripped = strip_noise_deterministic(raw_text)

        response, _ = execute_with_retry(
            lambda: client.chat.completions.create(
                model=model,
                temperature=0.0,
                messages=[
                    {"role": "system", "content": EXTRACTOR_SYSTEM_PROMPT},
                    {"role": "user", "content": pre_stripped}
                ]
            ),
            provider="extractor",
            config=config,
            logger=log,
            circuit_breaker=EXTRACTOR_CIRCUIT_BREAKER,
        )
        if not response:
            return compress_event_deterministic(event, model)

        content = response.choices[0].message.content.strip()

        try:
            parsed = json.loads(content)
            deterministic = extract_key_fields(event)
            for key, val in deterministic.items():
                if key not in parsed or parsed[key] is None:
                    parsed[key] = val
            parsed["extraction_method"] = "model"
            parsed["extractor_model"] = model
            return parsed
        except json.JSONDecodeError:
            log.warning(
                f"Extractor model returned non-JSON. "
                f"Falling back. Content: {content[:80]}"
            )
            return compress_event_deterministic(event, model)

    except Exception as e:
        log.warning(f"Extractor model error: {e}. Using deterministic fallback.")
        return compress_event_deterministic(event, model)


def compress_event_deterministic(
    event: dict, model: str = "deterministic"
) -> dict:
    """
    Pure deterministic extraction — no model required.
    Always available regardless of hardware or API status.
    This is the floor — Bifrost never goes below this.
    """
    extracted = extract_key_fields(event)
    raw_text = json.dumps(event.get("raw", {}))
    extracted["raw_snippet"] = strip_noise_deterministic(raw_text)[:100]
    extracted["extraction_method"] = "deterministic"
    extracted["extractor_model"] = model
    return extracted


def compress_event(event: dict, config: dict) -> dict:
    """
    Main entry point for event compression.
    Selects extraction method based on config and hardware tier.

    Priority:
    1. Model extraction (Qwen 2.5 1.5B via Ollama)
    2. Deterministic extraction (regex + field parsing)

    Deterministic fallback guarantees Bifrost never goes
    blind even if Ollama is down or hardware is minimal.
    """
    tier = config.get("hardware_tier", "TIER_4")
    use_extractor = config.get("use_extractor", False)
    extractor_model = config.get("extractor_model")

    if not use_extractor or not extractor_model or tier == "TIER_4":
        log.debug(
            f"Deterministic extraction: tier={tier}"
        )
        return compress_event_deterministic(event)

    try:
        from openai import OpenAI
        client = OpenAI(
            base_url=config.get(
                "local_url", "http://localhost:11434/v1"
            ),
            api_key="ollama",
            timeout=get_request_timeout(config)
        )
        log.debug(f"Model extraction: model={extractor_model}")
        return compress_event_with_model(event, client, extractor_model, config)

    except Exception as e:
        log.warning(f"Model client init failed: {e}. Deterministic fallback.")
        return compress_event_deterministic(event)


def batch_compress(events: list, config: dict) -> list:
    """
    Compress a list of events. Used for processing the
    rolling 10-event attack chain context buffer.
    """
    return [compress_event(event, config) for event in events]


def format_for_heimdall(compressed_events: list) -> str:
    """
    Formats compressed events as a single string for the
    Heimdall reasoning prompt. Presents the attack chain
    chronologically so Heimdall sees sequence not just
    individual events.
    """
    if not compressed_events:
        return "No events in buffer."

    lines = ["Security event sequence for analysis:"]
    for i, event in enumerate(compressed_events, 1):
        event_type = event.get("event_type", "unknown")
        boundary = event.get("boundary", "UNKNOWN")
        alert = event.get("alert_signal", "none")
        ip = event.get("ip", "none")
        path = event.get("path", "none")
        command = event.get("command", "none")
        lines.append(
            f"{i}. [{boundary}] type={event_type} "
            f"ip={ip} path={path} "
            f"command={command} alert={alert}"
        )

    return "\n".join(lines)


if __name__ == "__main__":
    test_event = {
        "source": "auditd",
        "timestamp": "2026-05-28T03:00:00Z",
        "boundary": "HOST",
        "raw": (
            'type=SYSCALL msg=audit(1716861600.123:4521): arch=c000003e '
            'syscall=59 success=yes exit=0 a0=0x7f8b2c0d1234 '
            'ppid=1234 pid=5678 auid=1000 uid=0 gid=0 euid=0 '
            'comm="wget" exe="/usr/bin/wget" key="exec_commands"'
        )
    }

    test_config = {
        "hardware_tier": "TIER_4",
        "use_extractor": False,
        "extractor_model": None
    }

    print("Testing deterministic extraction...")
    result = compress_event(test_event, test_config)
    print(json.dumps(result, indent=2))

    print("\nTesting format_for_heimdall...")
    formatted = format_for_heimdall([result])
    print(formatted)
