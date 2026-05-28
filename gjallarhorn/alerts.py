#!/usr/bin/env python3
"""
Gjallarhorn Alert System v0.1.0

In Norse mythology Gjallarhorn is the horn of Heimdall.
When blown it is heard across all nine realms.
When Heimdall detects a breach he sounds Gjallarhorn.

Tier 1 — Managed: Silent MQTT log to tablet dashboard.
Honeypot activity, automated blocks, minor anomalies.
Handled silently. Reviewed in morning report.

Tier 2 — Breach: MQTT plus audio plus push notification.
Honeypot breakout, host compromise, autonomous action failing.
Overrides quiet hours. Wakes you up at 3AM if needed.
"""

import json
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("heimdall.gjallarhorn")

QUIET_HOURS_START = 23
QUIET_HOURS_END = 7
ALERT_SOUND = Path("~/Projects/bifrost/gjallarhorn/alert.wav").expanduser()
BREACH_SOUND = Path("~/Projects/bifrost/gjallarhorn/breach.wav").expanduser()


def is_quiet_hours() -> bool:
    hour = datetime.now().hour
    if QUIET_HOURS_START > QUIET_HOURS_END:
        return hour >= QUIET_HOURS_START or hour < QUIET_HOURS_END
    return QUIET_HOURS_START <= hour < QUIET_HOURS_END


def play_sound(sound_path: Path):
    try:
        if sound_path.exists():
            subprocess.Popen(
                ["paplay", str(sound_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        else:
            subprocess.Popen(
                ["paplay", "/usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
    except Exception as e:
        log.warning(f"Sound playback failed: {e}")


def send_desktop_notification(title: str, body: str, urgency: str = "normal"):
    try:
        subprocess.Popen([
            "notify-send",
            "--urgency", urgency,
            "--app-name", "Heimdall",
            "--icon", "security-high",
            title,
            body
        ])
    except Exception as e:
        log.warning(f"Desktop notification failed: {e}")


def send_mqtt(decision: dict, tier: int, config: dict):
    try:
        import paho.mqtt.publish as mqtt_publish

        broker = config.get("mqtt_broker", "localhost")
        port = config.get("mqtt_port", 1883)
        topic = (
            "heimdall/alerts/breach"
            if tier == 2
            else "heimdall/alerts/managed"
        )

        payload = json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tier": tier,
            "severity": decision.get("severity"),
            "action": decision.get("action_required"),
            "threat_class": decision.get("threat_class"),
            "reasoning": decision.get("reasoning"),
            "target": decision.get("target"),
            "confidence": decision.get("confidence")
        })

        mqtt_publish.single(
            topic,
            payload=payload,
            hostname=broker,
            port=port,
            qos=1
        )

        log.info(f"Gjallarhorn MQTT published: topic={topic}")

    except Exception as e:
        log.warning(f"MQTT publish failed: {e}")


def format_alert_message(decision: dict) -> tuple[str, str]:
    severity = decision.get("severity", "UNKNOWN")
    action = decision.get("action_required", "NONE")
    threat = decision.get("threat_class", "unknown")
    reasoning = decision.get("reasoning", "")
    target = decision.get("target", "unknown")
    confidence = decision.get("confidence", 0.0)

    title = f"Heimdall [{severity}] — {threat}"
    body = (
        f"Action: {action}\n"
        f"Target: {target}\n"
        f"Confidence: {confidence:.0%}\n"
        f"Reason: {reasoning}"
    )

    return title, body


def alert(tier: int, decision: dict, config: dict):
    """
    Main Gjallarhorn entry point.

    Tier 1 — Managed:
      Silent MQTT to tablet. No sound. No popup.
      Reviewed in morning dashboard.

    Tier 2 — Breach:
      MQTT to tablet. Desktop notification. Audio alert.
      Overrides quiet hours — always fires.
    """
    title, body = format_alert_message(decision)
    severity = decision.get("severity", "UNKNOWN")
    quiet = is_quiet_hours()

    log.info(
        f"Gjallarhorn Tier {tier} — {severity} — "
        f"{decision.get('threat_class')} — quiet={quiet}"
    )

    if tier == 1:
        # Silent MQTT only
        send_mqtt(decision, tier, config)
        log.info("Tier 1 alert: MQTT sent silently.")
        return

    if tier == 2:
        # Always fires — breach overrides quiet hours
        send_mqtt(decision, tier, config)

        # Desktop notification
        urgency = "critical" if severity == "CRITICAL" else "normal"
        send_desktop_notification(
            f"BREACH DETECTED — {title}",
            body,
            urgency=urgency
        )

        # Audio — always plays on breach regardless of quiet hours
        if severity == "CRITICAL":
            play_sound(BREACH_SOUND)
        else:
            play_sound(ALERT_SOUND)

        log.warning(
            f"Tier 2 BREACH ALERT fired. "
            f"severity={severity} quiet_hours_override=True"
        )
        return


def morning_report(config: dict) -> str:
    """
    Generates a summary of overnight Tier 1 alerts.
    Called at 7AM by the scheduler.
    Covers everything that happened during quiet hours.
    """
    import sqlite3
    db_path = Path("~/Projects/bifrost/db/events.db").expanduser()

    if not db_path.exists():
        return "No events database found."

    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                COUNT(*) as total,
                COUNT(CASE WHEN json_extract(heimdall_decision, '$.severity') = 'CRITICAL' THEN 1 END) as critical,
                COUNT(CASE WHEN json_extract(heimdall_decision, '$.severity') = 'HIGH' THEN 1 END) as high,
                COUNT(CASE WHEN json_extract(heimdall_decision, '$.severity') = 'MEDIUM' THEN 1 END) as medium,
                COUNT(CASE WHEN boundary = 'HONEYPOT' THEN 1 END) as honeypot,
                COUNT(CASE WHEN boundary = 'HOST' THEN 1 END) as host
            FROM events
            WHERE created_at >= datetime('now', '-8 hours')
        """)

        row = cursor.fetchone()
        total, critical, high, medium, honeypot, host = row

        cursor.execute("""
            SELECT action_type, COUNT(*) as count
            FROM actions
            WHERE executed_at >= datetime('now', '-8 hours')
            GROUP BY action_type
        """)

        actions = cursor.fetchall()
        conn.close()

        action_summary = ", ".join(
            f"{a[0]}={a[1]}" for a in actions
        ) if actions else "none"

        report = (
            f"Heimdall Morning Report — "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
            f"{'=' * 50}\n"
            f"Last 8 hours:\n"
            f"  Total events : {total}\n"
            f"  Critical     : {critical}\n"
            f"  High         : {high}\n"
            f"  Medium       : {medium}\n"
            f"  Honeypot     : {honeypot}\n"
            f"  Host         : {host}\n"
            f"  Actions taken: {action_summary}\n"
            f"{'=' * 50}"
        )

        return report

    except Exception as e:
        return f"Morning report failed: {e}"


if __name__ == "__main__":
    test_decision = {
        "severity": "CRITICAL",
        "action_required": "BLOCK",
        "threat_class": "container_escape",
        "reasoning": "Honeypot process accessing host filesystem",
        "target": "192.168.0.125",
        "confidence": 0.99,
        "gjallarhorn_tier": 2
    }

    test_config = {
        "mqtt_broker": "localhost",
        "mqtt_port": 1883
    }

    print("Testing Tier 1 alert...")
    alert(1, test_decision, test_config)

    print("Testing Tier 2 breach alert...")
    alert(2, test_decision, test_config)

    print("\nMorning report:")
    print(morning_report(test_config))
