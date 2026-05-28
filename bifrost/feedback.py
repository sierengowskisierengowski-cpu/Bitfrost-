#!/usr/bin/env python3
"""
Bifrost Feedback Loop v0.1.0

When Heimdall makes a wrong call — blocks something
legitimate, kills a process it should not have — you
mark it as a false positive. That correction feeds
back into the system so Heimdall never makes the same
mistake twice on your specific system.

Over time false positive rate approaches zero.
Heimdall gets smarter about YOUR environment.
"""

import json
import sqlite3
import logging
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("heimdall.feedback")

DB_PATH = Path("~/Projects/bifrost/db/events.db").expanduser()


def mark_false_positive(
    event_id: int,
    threat_class: str,
    pattern: str,
    boundary: str = None
):
    """
    Marks an event as a false positive.
    Stores the pattern so Heimdall avoids it in future.
    Also triggers rollback of any action taken.
    """
    if not DB_PATH.exists():
        log.error("Database not found.")
        return False

    try:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()

        # Mark the event
        cursor.execute("""
            UPDATE events
            SET false_positive = 1
            WHERE id = ?
        """, (event_id,))

        # Store the false positive pattern
        cursor.execute("""
            INSERT INTO false_positives
            (threat_class, boundary, pattern, marked_at)
            VALUES (?, ?, ?, ?)
        """, (
            threat_class,
            boundary,
            pattern,
            datetime.now(timezone.utc).isoformat()
        ))

        conn.commit()

        # Check if there is an action to roll back
        cursor.execute("""
            SELECT id, action_type, rollback_data, rolled_back
            FROM actions
            WHERE event_id = ? AND rolled_back = 0
        """, (event_id,))

        actions = cursor.fetchall()
        conn.close()

        for action in actions:
            action_id, action_type, rollback_data, _ = action
            rollback_action(action_id, action_type, rollback_data)

        log.info(
            f"False positive recorded: event_id={event_id} "
            f"threat_class={threat_class} pattern={pattern}"
        )
        return True

    except Exception as e:
        log.error(f"False positive marking failed: {e}")
        return False


def rollback_action(
    action_id: int,
    action_type: str,
    rollback_data: str
):
    """
    Rolls back an autonomous action taken by Heimdall.
    Calls the Go executor rollback endpoint.
    """
    import urllib.request
    import urllib.error

    try:
        payload = json.dumps({"action_id": action_id}).encode()
        req = urllib.request.Request(
            "http://127.0.0.1:8766/rollback",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            result = json.loads(response.read())
            log.info(
                f"Rollback executed: action_id={action_id} "
                f"type={action_type} result={result}"
            )
            return True

    except Exception as e:
        log.warning(
            f"Executor rollback failed: {e}. "
            f"Manual rollback may be required. "
            f"Data: {rollback_data}"
        )
        return False


def get_false_positives(limit: int = 50) -> list:
    """
    Returns recent false positive patterns.
    Included in the Heimdall prompt to prevent repeat mistakes.
    """
    if not DB_PATH.exists():
        return []

    try:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()

        cursor.execute("""
            SELECT threat_class, boundary, pattern, marked_at
            FROM false_positives
            ORDER BY marked_at DESC
            LIMIT ?
        """, (limit,))

        rows = cursor.fetchall()
        conn.close()

        return [
            {
                "threat_class": r[0],
                "boundary": r[1],
                "pattern": r[2],
                "marked_at": r[3]
            }
            for r in rows
        ]

    except Exception as e:
        log.error(f"False positive retrieval failed: {e}")
        return []


def get_action_history(limit: int = 20) -> list:
    """
    Returns recent autonomous actions taken by Heimdall.
    Used in the dashboard and for rollback reference.
    """
    if not DB_PATH.exists():
        return []

    try:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                a.id,
                a.event_id,
                a.action_type,
                a.target,
                a.executed_at,
                a.success,
                a.rolled_back,
                e.boundary,
                e.source
            FROM actions a
            JOIN events e ON a.event_id = e.id
            ORDER BY a.executed_at DESC
            LIMIT ?
        """, (limit,))

        rows = cursor.fetchall()
        conn.close()

        return [
            {
                "action_id": r[0],
                "event_id": r[1],
                "action_type": r[2],
                "target": r[3],
                "executed_at": r[4],
                "success": bool(r[5]),
                "rolled_back": bool(r[6]),
                "boundary": r[7],
                "source": r[8]
            }
            for r in rows
        ]

    except Exception as e:
        log.error(f"Action history retrieval failed: {e}")
        return []


def get_stats() -> dict:
    """
    Returns overall Heimdall performance statistics.
    Shows how accurate Heimdall has been over time.
    """
    if not DB_PATH.exists():
        return {}

    try:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM events")
        total_events = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM events WHERE false_positive = 1"
        )
        false_positives = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM actions")
        total_actions = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM actions WHERE success = 1"
        )
        successful_actions = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM actions WHERE rolled_back = 1"
        )
        rolled_back = cursor.fetchone()[0]

        cursor.execute("""
            SELECT action_type, COUNT(*) as count
            FROM actions
            GROUP BY action_type
            ORDER BY count DESC
        """)
        action_breakdown = dict(cursor.fetchall())

        cursor.execute("""
            SELECT
                json_extract(heimdall_decision, '$.severity'),
                COUNT(*)
            FROM events
            WHERE heimdall_decision IS NOT NULL
            GROUP BY json_extract(heimdall_decision, '$.severity')
        """)
        severity_breakdown = dict(cursor.fetchall())

        conn.close()

        accuracy = (
            round(
                (1 - false_positives / max(total_events, 1)) * 100, 2
            )
            if total_events > 0 else 100.0
        )

        return {
            "total_events": total_events,
            "false_positives": false_positives,
            "accuracy_pct": accuracy,
            "total_actions": total_actions,
            "successful_actions": successful_actions,
            "rolled_back_actions": rolled_back,
            "action_breakdown": action_breakdown,
            "severity_breakdown": severity_breakdown
        }

    except Exception as e:
        log.error(f"Stats retrieval failed: {e}")
        return {}


def print_stats():
    stats = get_stats()
    if not stats:
        print("No statistics available yet.")
        return

    print(f"""
┌─────────────────────────────────────────┐
│  Heimdall Performance Statistics        │
│                                         │
│  Total Events   : {str(stats.get('total_events', 0)):<22}│
│  False Positives: {str(stats.get('false_positives', 0)):<22}│
│  Accuracy       : {str(stats.get('accuracy_pct', 0)) + '%':<22}│
│  Total Actions  : {str(stats.get('total_actions', 0)):<22}│
│  Rolled Back    : {str(stats.get('rolled_back_actions', 0)):<22}│
└─────────────────────────────────────────┘
""")

    breakdown = stats.get("action_breakdown", {})
    if breakdown:
        print("Action breakdown:")
        for action, count in breakdown.items():
            print(f"  {action}: {count}")


if __name__ == "__main__":
    print("Heimdall Feedback System")
    print_stats()

    print("\nRecent false positives:")
    fps = get_false_positives(limit=5)
    for fp in fps:
        print(f"  {fp['threat_class']}: {fp['pattern']}")

    print("\nRecent actions:")
    actions = get_action_history(limit=5)
    for action in actions:
        print(
            f"  [{action['action_type']}] "
            f"target={action['target']} "
            f"success={action['success']} "
            f"rolled_back={action['rolled_back']}"
        )
