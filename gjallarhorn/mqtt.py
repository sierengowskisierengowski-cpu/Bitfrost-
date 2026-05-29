#!/usr/bin/env python3
"""Gjallarhorn MQTT v0.1.1 — Persistent client manager."""

from __future__ import annotations
import json
import logging
import threading
import time
import uuid
from datetime import datetime, timezone

log = logging.getLogger("heimdall.mqtt")

HEARTBEAT_INTERVAL = 60
RECONNECT_DELAY_MIN = 2
RECONNECT_DELAY_MAX = 60


class MQTTClientManager:
    def __init__(self, config: dict):
        self.config = config
        self.broker = config.get("mqtt_broker", "localhost")
        self.port = config.get("mqtt_port", 1883)
        self.client_id = config.get("mqtt_client_id", "heimdall-guardian")
        self.username = config.get("mqtt_username")
        self.password = config.get("mqtt_password")
        self.tls_enabled = config.get("mqtt_tls_enabled", False)
        self._client = None
        self._connected = False
        self._lock = threading.Lock()
        self._reconnect_delay = RECONNECT_DELAY_MIN

    def _build_client(self):
        try:
            import paho.mqtt.client as mqtt
            try:
                from paho.mqtt.client import CallbackAPIVersion
                client = mqtt.Client(
                    client_id=self.client_id,
                    callback_api_version=CallbackAPIVersion.VERSION2
                )
            except (ImportError, AttributeError):
                client = mqtt.Client(client_id=self.client_id)

            if self.username and self.password:
                client.username_pw_set(self.username, self.password)

            if self.tls_enabled:
                ca = self.config.get("mqtt_ca_cert")
                cert = self.config.get("mqtt_client_cert")
                key = self.config.get("mqtt_client_key")
                client.tls_set(ca_certs=ca, certfile=cert, keyfile=key)
            elif self.broker not in ("localhost", "127.0.0.1"):
                log.warning(
                    "MQTT broker is not localhost but TLS is disabled."
                )

            lwt_payload = json.dumps({
                "status": "offline",
                "timestamp": datetime.now(timezone.utc).isoformat().replace(
                    "+00:00", "Z"
                )
            })
            client.will_set(
                "heimdall/status", lwt_payload, qos=1, retain=True
            )
            client.on_connect = self._on_connect
            client.on_disconnect = self._on_disconnect
            return client

        except ImportError:
            log.warning("paho-mqtt not installed. MQTT disabled.")
            return None

    def _on_connect(self, client, userdata, flags, rc, *args):
        if rc == 0:
            self._connected = True
            self._reconnect_delay = RECONNECT_DELAY_MIN
            log.info(f"MQTT connected to {self.broker}:{self.port}")
            self._publish_retained_online()
        else:
            self._connected = False
            log.warning(f"MQTT connect failed: rc={rc}")

    def _on_disconnect(self, client, userdata, rc, *args):
        self._connected = False
        if rc != 0:
            log.warning(f"MQTT unexpected disconnect: rc={rc}")

    def _publish_retained_online(self):
        if self._client and self._connected:
            payload = json.dumps({
                "status": "online",
                "timestamp": datetime.now(timezone.utc).isoformat().replace(
                    "+00:00", "Z"
                )
            })
            self._client.publish(
                "heimdall/status", payload, qos=1, retain=True
            )

    def connect(self) -> bool:
        with self._lock:
            if self._connected:
                return True
            try:
                self._client = self._build_client()
                if not self._client:
                    return False
                self._client.connect(self.broker, self.port, keepalive=30)
                self._client.loop_start()
                for _ in range(10):
                    if self._connected:
                        return True
                    time.sleep(0.1)
                return self._connected
            except Exception as ex:
                log.warning(f"MQTT connect error: {ex}")
                return False

    def publish(self, topic: str, payload: dict, qos: int = 1) -> bool:
        if not self._connected:
            if not self.connect():
                log.warning(f"MQTT unavailable. Dropping: {topic}")
                return False
        try:
            result = self._client.publish(
                topic, json.dumps(payload), qos=qos
            )
            return result.rc == 0
        except Exception as ex:
            log.error(f"MQTT publish error: {ex}")
            self._connected = False
            return False

    def disconnect(self):
        if self._client:
            try:
                self._client.loop_stop()
                self._client.disconnect()
            except Exception as ex:
                log.debug("MQTT disconnect cleanup: %s", ex)
        self._connected = False


_manager: MQTTClientManager = None
_manager_lock = threading.Lock()


def get_manager(config: dict) -> MQTTClientManager:
    global _manager
    with _manager_lock:
        if _manager is None:
            _manager = MQTTClientManager(config)
            _manager.connect()
        return _manager


def publish_decision(decision: dict, tier: int, config: dict) -> bool:
    manager = get_manager(config)
    topic = (
        "heimdall/alerts/breach"
        if tier == 2
        else "heimdall/alerts/managed"
    )
    payload = {
        "decision_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat().replace(
            "+00:00", "Z"
        ),
        "tier": tier,
        "severity": decision.get("severity", "UNKNOWN"),
        "threat_class": decision.get("threat_class", "unknown"),
        "action_requested": decision.get("action_required", "NONE"),
        "action_effective": decision.get("action_effective", "NONE"),
        "confidence": decision.get("confidence", 0.0),
        "reasoning": str(decision.get("reasoning", ""))[:200],
        "target": decision.get("target"),
        "boundary": decision.get("boundary", "UNKNOWN"),
        "policy_rationale": decision.get("policy_rationale", ""),
        "learning_mode": decision.get("learning_mode", True),
        "dry_run": decision.get("dry_run", True),
    }
    ok = manager.publish(topic, payload, qos=1)
    manager.publish("heimdall/decisions", payload, qos=1)
    return ok


def publish_heartbeat(config: dict, status: dict) -> bool:
    manager = get_manager(config)
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace(
            "+00:00", "Z"
        ),
        "status": "online",
        "tier": status.get("tier", "UNKNOWN"),
        "learning_mode": status.get("learning_mode", True),
        "dry_run": status.get("dry_run", True),
        "autonomous_enabled": status.get("autonomous_enabled", False),
        "events_processed": status.get("events_processed", 0),
        "decisions_made": status.get("decisions_made", 0),
        "fallback_rate": status.get("fallback_rate", 0.0),
        "policy_blocks": status.get("policy_blocks", 0),
    }
    return manager.publish("heimdall/status", payload, qos=0)


class HeartbeatThread(threading.Thread):
    def __init__(self, config: dict, brain_ref):
        super().__init__(daemon=True, name="gjallarhorn.heartbeat")
        self.config = config
        self.brain = brain_ref
        self._stop_event = threading.Event()

    def run(self):
        log.info("Gjallarhorn heartbeat thread started.")
        while not self._stop_event.is_set():
            try:
                status = self.brain.get_status()
                publish_heartbeat(self.config, status)
            except Exception as ex:
                log.warning(f"Heartbeat error: {ex}")
            self._stop_event.wait(HEARTBEAT_INTERVAL)

    def stop(self):
        self._stop_event.set()

    def stop_and_join(self, timeout: float = 5.0):
        self.stop()
        self.join(timeout=timeout)


def mqtt_available(config: dict) -> bool:
    manager = get_manager(config)
    return manager._connected
