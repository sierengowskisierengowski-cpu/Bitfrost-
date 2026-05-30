#!/usr/bin/env python3
"""
lab/validate.py — Bifrost build validation facility.

Ties this run to the current git commit hash (build ID). On the first
invocation it writes a lock file; subsequent runs fail if the commit
has changed, keeping results strictly scoped to one build snapshot.

Pass --reset-lock to re-lock to the current commit (e.g. after a new
build is cut on the same branch).

Usage
-----
  python3 -m lab.validate                        # full suite
  python3 -m lab.validate --subsystem brain      # single subsystem
  python3 -m lab.validate --reset-lock           # re-lock to HEAD
  python3 -m lab.validate --report-dir /tmp/rpt  # custom output dir

Subsystems
----------
  brain        – Heimdall reasoning, guardian decisions, policy gate,
                 failover, circuit-breakers, resilience
  eyes_sensors – Collectors, ingest path, event normalization,
                 replay inputs, schema contracts, path safety
  hands_actions– Executor dispatch gating, rollback / quarantine
  end_to_end   – Safe replay scenarios, resilience drills, demo path
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from lab.scorecard import Scorecard, TestResult

# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parents[1]
LAB_DIR = REPO_ROOT / "lab"
LOCK_FILE = LAB_DIR / ".build_lock"
REPORTS_DIR = LAB_DIR / "reports"
REPLAY_DIR = REPO_ROOT / "examples" / "replay"

# ---------------------------------------------------------------------------
# Subsystem definitions
# ---------------------------------------------------------------------------

# Each entry: list of pytest args (file paths or node IDs / -k filter pairs).
# "test_files" are passed verbatim to pytest.
# "pytest_extra" are appended as-is (e.g. ["-k", "maybe_dispatch"]).
SUBSYSTEMS: Dict[str, Dict] = {
    "brain": {
        "label": "Brain (reasoning / policy / failover / resilience)",
        "test_files": [
            "tests/test_policy_gate.py",
            "tests/test_guardian_config_checksum.py",
            "tests/test_guardian_shutdown.py",
            "tests/test_inference_resilience.py",
            "tests/test_router_failover.py",
            # guardian_policy — policy-gate subtests only (dispatch tests
            # belong to hands_actions and are filtered out here)
            "tests/test_guardian_policy.py",
        ],
        "pytest_extra": ["-k", "not maybe_dispatch"],
    },
    "eyes_sensors": {
        "label": "Eyes/Sensors (collectors / ingest / normalization / schema)",
        "test_files": [
            "tests/test_auditd_collector_rotation.py",
            "tests/test_cowrie_collector_rotation.py",
            "tests/test_paths.py",
            "tests/test_schema.py",
            "tests/test_security.py",
        ],
        "pytest_extra": [],
    },
    "hands_actions": {
        "label": "Hands/Actions (executor dispatch / rollback / quarantine)",
        "test_files": [
            "tests/test_guardian_policy.py",
        ],
        "pytest_extra": ["-k", "maybe_dispatch"],
    },
    "end_to_end": {
        "label": "End-to-End (replay / resilience / demo path)",
        "test_files": [
            "tests/test_demo_replays.py",
            "tests/test_resilience.py",
        ],
        "pytest_extra": [],
        # Replay scenarios are added separately below
    },
}

# Replay scenarios for the end_to_end subsystem.
# expected_action is what the demo harness should produce for the dominant
# event type in each scenario (dry-run mode; policy blocks enforcement).
REPLAY_SCENARIOS: List[Dict] = [
    # NOTE: demo always runs in dry_run=True / learning_mode=True mode.
    # Destructive requested actions (KILL, BLOCK, QUARANTINE) are always
    # downgraded to ALERT by the policy gate; expected_action below reflects
    # the resulting action_effective value in the audit log.
    {
        "file": "benign_web_burst.jsonl",
        "expected_threat": "none",
        "expected_action": "LOG",
    },
    {
        "file": "port_scan.jsonl",
        "expected_threat": "port_scan",
        "expected_action": "ALERT",
    },
    {
        "file": "suspicious_process_spawn.jsonl",
        "expected_threat": "suspicious_spawn",
        "expected_action": "ALERT",
    },
    {
        "file": "mdrfckr_botnet.jsonl",
        "expected_threat": "port_scan",
        "expected_action": "ALERT",
    },
    {
        "file": "cowrie_dns_pivot_2026-05-29.jsonl",
        "expected_threat": "suspicious_spawn",
        "expected_action": "ALERT",
    },
]

# ---------------------------------------------------------------------------
# Build-lock helpers
# ---------------------------------------------------------------------------


def _get_build_id() -> str:
    """Return the current git HEAD commit hash (short form for display only)."""
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        sys.exit("[validate] ERROR: could not resolve git HEAD — is this a git repo?")
    return result.stdout.strip()


def _check_or_write_lock(build_id: str, reset: bool) -> None:
    """Enforce build-lock: refuse to run if HEAD changed since the lock was set."""
    if reset or not LOCK_FILE.exists():
        LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
        LOCK_FILE.write_text(build_id + "\n")
        if reset:
            print(f"[validate] Build lock reset to {build_id[:16]}")
        else:
            print(f"[validate] Build lock created for {build_id[:16]}")
        return

    locked = LOCK_FILE.read_text().strip()
    if locked != build_id:
        print(
            f"\n[validate] ERROR: build hash mismatch.\n"
            f"  Locked : {locked[:16]}\n"
            f"  Current: {build_id[:16]}\n"
            f"\nThis lab is locked to a different build snapshot.\n"
            f"Run with --reset-lock to re-lock to the current commit,\n"
            f"or restore the locked commit before running validation.\n"
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# Pytest runner
# ---------------------------------------------------------------------------


def _run_pytest(
    subsystem: str,
    test_files: List[str],
    pytest_extra: List[str],
    tmp_xml: Path,
) -> List[TestResult]:
    """Run a pytest invocation and parse the JUnit XML result."""
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "--tb=short",
        "-q",
        f"--junitxml={tmp_xml}",
    ] + test_files + pytest_extra

    start = time.monotonic()
    proc = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    elapsed_ms = (time.monotonic() - start) * 1000.0

    results: List[TestResult] = []
    if not tmp_xml.exists():
        # pytest produced no XML (e.g. no tests collected): record as one skip
        results.append(
            TestResult(
                subsystem=subsystem,
                test_id=f"{subsystem}/no-tests-collected",
                scenario="pytest",
                expected_signal="PASS",
                actual_signal="SKIP",
                latency_ms=round(elapsed_ms, 1),
                policy_allowed=None,
                service_stable=True,
                passed=False,
                notes=proc.stdout[-200:].strip() or proc.stderr[-200:].strip(),
            )
        )
        return results

    tree = ET.parse(tmp_xml)
    root = tree.getroot()

    # JUnit XML: <testsuite> contains <testcase> elements; failures/errors are
    # child elements of <testcase>.
    for suite in root.iter("testsuite"):
        for tc in suite.iter("testcase"):
            name = tc.get("name", "unknown")
            classname = tc.get("classname", "")
            duration_s = float(tc.get("time", 0.0))
            latency_ms = round(duration_s * 1000.0, 1)

            failure = tc.find("failure")
            error = tc.find("error")
            skipped = tc.find("skipped")

            if skipped is not None:
                passed = True  # skips are not failures
                actual = "SKIP"
                notes = ""
            elif failure is not None or error is not None:
                passed = False
                actual = "FAIL"
                elem = failure if failure is not None else error
                notes = (elem.text or "").strip()[:200]
            else:
                passed = True
                actual = "PASS"
                notes = ""

            test_id = f"{classname}::{name}" if classname else name

            results.append(
                TestResult(
                    subsystem=subsystem,
                    test_id=test_id,
                    scenario="pytest",
                    expected_signal="PASS",
                    actual_signal=actual,
                    latency_ms=latency_ms,
                    policy_allowed=None,
                    service_stable=proc.returncode in (0, 1),
                    passed=passed,
                    notes=notes,
                )
            )

    # If no test cases were parsed but XML existed, record a sentinel
    if not results:
        results.append(
            TestResult(
                subsystem=subsystem,
                test_id=f"{subsystem}/empty-suite",
                scenario="pytest",
                expected_signal="PASS",
                actual_signal="SKIP",
                latency_ms=round(elapsed_ms, 1),
                policy_allowed=None,
                service_stable=True,
                passed=True,
                notes="No test cases collected",
            )
        )

    return results


# ---------------------------------------------------------------------------
# Replay scenario runner
# ---------------------------------------------------------------------------


def _run_replay(scenario: Dict, tmp_dir: Path) -> TestResult:
    """Run a single demo replay and return a scored TestResult."""
    replay_file = REPLAY_DIR / scenario["file"]
    audit_log = tmp_dir / f"{replay_file.stem}_audit.jsonl"
    expected_action = scenario["expected_action"]

    if not replay_file.exists():
        return TestResult(
            subsystem="end_to_end",
            test_id=f"replay/{scenario['file']}",
            scenario=scenario["file"],
            expected_signal=expected_action,
            actual_signal="MISSING",
            latency_ms=0.0,
            policy_allowed=None,
            service_stable=False,
            passed=False,
            notes="Replay file not found",
        )

    cmd = [
        sys.executable,
        "-m",
        "bifrost.demo",
        "--scenario",
        str(replay_file),
        "--out",
        str(audit_log),
        "--no-color",
    ]

    start = time.monotonic()
    proc = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    latency_ms = round((time.monotonic() - start) * 1000.0, 1)

    service_stable = proc.returncode == 0
    summary_present = "SUMMARY" in proc.stdout

    # Parse audit log: find the dominant (most frequent) effective action
    actual_action = "NONE"
    policy_allowed: Optional[bool] = None
    action_counts: Dict[str, int] = {}

    if audit_log.exists():
        for line in audit_log.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                eff = record.get("action_effective", "")
                if eff:
                    action_counts[eff] = action_counts.get(eff, 0) + 1
                # Track whether any enforcement was allowed
                if record.get("allowed") is True:
                    policy_allowed = True
                elif policy_allowed is None and record.get("allowed") is False:
                    policy_allowed = False
            except json.JSONDecodeError:
                pass

    if action_counts:
        # Pick the most frequent effective action as the representative result
        actual_action = max(action_counts, key=lambda k: action_counts[k])

    # Pass criterion: service stayed up AND audit log was produced AND
    # the expected action was produced at least once in the log.
    passed = (
        service_stable
        and summary_present
        and (expected_action in action_counts or expected_action == "mixed")
    )

    notes = ""
    if not service_stable:
        output = (proc.stderr or proc.stdout or "").strip()
        notes = output[-200:] if output else "No output captured"
    elif not summary_present:
        notes = "SUMMARY line missing from demo output"

    return TestResult(
        subsystem="end_to_end",
        test_id=f"replay/{scenario['file']}",
        scenario=scenario["file"],
        expected_signal=expected_action,
        actual_signal=actual_action,
        latency_ms=latency_ms,
        policy_allowed=policy_allowed,
        service_stable=service_stable,
        passed=passed,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def _run_subsystem(
    name: str,
    defn: Dict,
    scorecard: Scorecard,
    tmp_dir: Path,
) -> None:
    print(f"  → {defn['label']}")

    # Unit / integration tests
    if defn.get("test_files"):
        xml_path = tmp_dir / f"junit_{name}.xml"
        results = _run_pytest(
            subsystem=name,
            test_files=defn["test_files"],
            pytest_extra=defn.get("pytest_extra", []),
            tmp_xml=xml_path,
        )
        for r in results:
            scorecard.add(r)
        passed = sum(1 for r in results if r.passed)
        print(f"     tests: {passed}/{len(results)} passed")

    # Replay scenarios (end_to_end only)
    if name == "end_to_end":
        for scenario in REPLAY_SCENARIOS:
            r = _run_replay(scenario, tmp_dir)
            scorecard.add(r)
            status = "PASS" if r.passed else "FAIL"
            print(
                f"     replay/{scenario['file']:<40} "
                f"expected={r.expected_signal:<10} "
                f"actual={r.actual_signal:<10} [{status}]"
            )


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Bifrost build validation facility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument(
        "--subsystem",
        choices=list(SUBSYSTEMS.keys()),
        default=None,
        help="Run only the named subsystem (default: all)",
    )
    ap.add_argument(
        "--reset-lock",
        action="store_true",
        help="Re-lock to the current git HEAD commit",
    )
    ap.add_argument(
        "--report-dir",
        type=Path,
        default=REPORTS_DIR,
        help="Directory for scorecard output files",
    )
    args = ap.parse_args(argv)

    build_id = _get_build_id()
    _check_or_write_lock(build_id, reset=args.reset_lock)

    run_ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{build_id[:8]}-{run_ts}"

    scorecard = Scorecard(build_id=build_id, run_id=run_id)
    report_dir: Path = args.report_dir
    report_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir = Path(f"/tmp/bifrost_lab_{run_id}")
    tmp_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n[validate] Bifrost build validation facility")
    print(f"[validate] Build : {build_id[:16]}")
    print(f"[validate] Run   : {run_id}")
    print(f"[validate] Scope : {args.subsystem or 'all subsystems'}")
    print()

    subsystems_to_run = (
        {args.subsystem: SUBSYSTEMS[args.subsystem]}
        if args.subsystem
        else SUBSYSTEMS
    )

    for name, defn in subsystems_to_run.items():
        _run_subsystem(name, defn, scorecard, tmp_dir)

    scorecard.print_summary()

    csv_path = report_dir / f"scorecard-{run_id}.csv"
    json_path = report_dir / f"scorecard-{run_id}.json"
    scorecard.write_csv(csv_path)
    scorecard.write_json(json_path)
    print(f"[validate] Reports written:")
    print(f"           CSV  : {csv_path}")
    print(f"           JSON : {json_path}")
    print()

    overall = scorecard.overall_score()
    return 0 if overall["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
