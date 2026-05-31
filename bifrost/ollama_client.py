#!/usr/bin/env python3

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Optional

from bifrost.inference import get_request_timeout
from bifrost.security import sanitize_telemetry_for_llm

DEFAULT_NUM_CTX = 1024
DEFAULT_NUM_PREDICT = 64
DEFAULT_NUM_GPU = 0
DEFAULT_TEMPERATURE = 0.0
MAX_LOG_BODY = 600


def truncate_for_log(value: object, max_len: int = MAX_LOG_BODY) -> str:
    text = sanitize_telemetry_for_llm(str(value or ""))
    if len(text) <= max_len:
        return text
    return f"{text[:max_len]}...(truncated)"


def _as_int(value: object, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _as_float(value: object, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def resolve_ollama_chat_url(local_url: str) -> str:
    base = str(local_url or "http://127.0.0.1:11434/v1").strip()
    if not base:
        base = "http://127.0.0.1:11434/v1"
    base = base.rstrip("/")
    if base.endswith("/v1"):
        base = base[:-3]
    return f"{base}/api/chat"


def parse_json_object(text: str) -> Optional[dict]:
    if not text:
        return None

    candidate = text.strip()
    if candidate.startswith("```"):
        parts = candidate.split("```")
        if len(parts) >= 3:
            candidate = parts[1]
            if candidate.lstrip().startswith("json"):
                candidate = candidate.lstrip()[4:].strip()

    decoder = json.JSONDecoder()
    try:
        parsed = json.loads(candidate)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    idx = candidate.find("{")
    while idx != -1:
        try:
            parsed, _ = decoder.raw_decode(candidate[idx:])
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
        idx = candidate.find("{", idx + 1)
    return None


def ollama_chat(
    *,
    config: dict,
    model: str,
    messages: list[dict],
    logger,
    temperature: Optional[float] = None,
    response_format: Optional[object] = None,
) -> dict:
    url = resolve_ollama_chat_url(config.get("local_url", "http://127.0.0.1:11434/v1"))
    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "format": response_format if response_format is not None else "json",
        "options": {
            "num_ctx": _as_int(config.get("llm_num_ctx", DEFAULT_NUM_CTX), DEFAULT_NUM_CTX),
            "num_predict": _as_int(
                config.get("llm_num_predict", DEFAULT_NUM_PREDICT),
                DEFAULT_NUM_PREDICT,
            ),
            "num_gpu": _as_int(config.get("llm_num_gpu", DEFAULT_NUM_GPU), DEFAULT_NUM_GPU),
        },
    }
    if temperature is None:
        temperature = _as_float(
            config.get("llm_temperature", DEFAULT_TEMPERATURE), DEFAULT_TEMPERATURE
        )
    payload["options"]["temperature"] = _as_float(temperature, DEFAULT_TEMPERATURE)

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    timeout = float(get_request_timeout(config))
    start = time.monotonic()

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            status = getattr(response, "status", 200)
            body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        logger.error(
            "Ollama non-200 response status=%s url=%s model=%s body=%s",
            exc.code,
            url,
            model,
            truncate_for_log(body),
        )
        raise RuntimeError(f"ollama_http_{exc.code}") from exc
    except Exception as exc:
        logger.warning(
            "Ollama request failed url=%s model=%s error=%s",
            url,
            model,
            exc,
        )
        raise

    if status != 200:
        logger.error(
            "Ollama non-200 response status=%s url=%s model=%s body=%s",
            status,
            url,
            model,
            truncate_for_log(body),
        )
        raise RuntimeError(f"ollama_http_{status}")

    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as exc:
        logger.error(
            "Ollama invalid JSON response url=%s model=%s body=%s",
            url,
            model,
            truncate_for_log(body),
        )
        raise RuntimeError("ollama_invalid_json") from exc

    message_payload = parsed.get("message")
    if not isinstance(message_payload, dict):
        logger.error(
            "Ollama response has unexpected message payload type=%s url=%s model=%s body=%s",
            type(message_payload).__name__,
            url,
            model,
            truncate_for_log(body),
        )
        raise RuntimeError("ollama_invalid_message_payload")

    message = message_payload.get("content")
    if not isinstance(message, str) or not message.strip():
        logger.error(
            "Ollama response missing message content url=%s model=%s body=%s",
            url,
            model,
            truncate_for_log(body),
        )
        raise RuntimeError("ollama_missing_message")

    duration_ms = round((time.monotonic() - start) * 1000.0, 2)
    timings = {
        "total_duration": parsed.get("total_duration"),
        "load_duration": parsed.get("load_duration"),
        "prompt_eval_duration": parsed.get("prompt_eval_duration"),
        "eval_duration": parsed.get("eval_duration"),
    }
    logger.info(
        "Ollama inference model=%s duration_ms=%s total_ns=%s load_ns=%s prompt_eval_ns=%s eval_ns=%s",
        model,
        duration_ms,
        timings["total_duration"],
        timings["load_duration"],
        timings["prompt_eval_duration"],
        timings["eval_duration"],
    )
    return {
        "content": message.strip(),
        "timings": timings,
        "duration_ms": duration_ms,
        "url": url,
    }
