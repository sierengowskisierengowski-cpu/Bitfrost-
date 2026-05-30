#!/usr/bin/env python3
"""
lab/scorecard.py — Bifrost build validation scorecard.

Records per-test results and rolls them up into subsystem scores and
an overall build score. Outputs both CSV (for tracking in spreadsheets)
and JSON (for diff/trend comparison between runs).
"""

from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class TestResult:
    subsystem: str
    test_id: str
    scenario: str
    expected_signal: str
    actual_signal: str
    latency_ms: float
    policy_allowed: Optional[bool]
    service_stable: bool
    passed: bool
    notes: str = ""


class Scorecard:
    """Collects test results and produces scorecard reports for a single build."""

    def __init__(self, build_id: str, run_id: str) -> None:
        self.build_id = build_id
        self.run_id = run_id
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.results: List[TestResult] = []

    # ------------------------------------------------------------------
    def add(self, result: TestResult) -> None:
        self.results.append(result)

    # ------------------------------------------------------------------
    def subsystem_score(self, subsystem: str) -> Dict:
        sub = [r for r in self.results if r.subsystem == subsystem]
        if not sub:
            return {
                "subsystem": subsystem,
                "total": 0,
                "passed": 0,
                "failed": 0,
                "score_pct": None,
            }
        passed = sum(1 for r in sub if r.passed)
        total = len(sub)
        return {
            "subsystem": subsystem,
            "total": total,
            "passed": passed,
            "failed": total - passed,
            "score_pct": round(100.0 * passed / total, 1),
        }

    def overall_score(self) -> Dict:
        total = len(self.results)
        if not total:
            return {"total": 0, "passed": 0, "failed": 0, "score_pct": None}
        passed = sum(1 for r in self.results if r.passed)
        return {
            "total": total,
            "passed": passed,
            "failed": total - passed,
            "score_pct": round(100.0 * passed / total, 1),
        }

    # ------------------------------------------------------------------
    def write_csv(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fields = [
            "build_id",
            "run_id",
            "timestamp",
            "subsystem",
            "test_id",
            "scenario",
            "expected_signal",
            "actual_signal",
            "latency_ms",
            "policy_allowed",
            "service_stable",
            "passed",
            "notes",
        ]
        with open(path, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields)
            writer.writeheader()
            for r in self.results:
                row = asdict(r)
                row["build_id"] = self.build_id
                row["run_id"] = self.run_id
                row["timestamp"] = self.timestamp
                writer.writerow(row)

    def write_json(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        subsystems = sorted({r.subsystem for r in self.results})
        data = {
            "build_id": self.build_id,
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "overall": self.overall_score(),
            "subsystems": {s: self.subsystem_score(s) for s in subsystems},
            "results": [asdict(r) for r in self.results],
        }
        path.write_text(json.dumps(data, indent=2) + "\n")

    # ------------------------------------------------------------------
    def print_summary(self) -> None:
        overall = self.overall_score()
        subsystems = sorted({r.subsystem for r in self.results})

        width = 62
        print()
        print("=" * width)
        print("  BIFROST BUILD VALIDATION REPORT")
        print(f"  Build : {self.build_id[:16]}")
        print(f"  Run   : {self.run_id}")
        print(f"  Time  : {self.timestamp}")
        print("=" * width)

        SUBSYSTEM_LABELS = {
            "brain": "brain",
            "eyes_sensors": "eyes/sensors",
            "hands_actions": "hands/actions",
            "end_to_end": "end-to-end",
        }
        for sub in subsystems:
            s = self.subsystem_score(sub)
            status = "PASS" if s["failed"] == 0 else "FAIL"
            pct = s["score_pct"] if s["score_pct"] is not None else 0.0
            label = SUBSYSTEM_LABELS.get(sub, sub.replace("_", "-"))
            print(f"  {label:<22} {s['passed']:>3}/{s['total']:<3}  {pct:>5.1f}%  [{status}]")

        print("-" * width)
        status = "PASS" if overall["failed"] == 0 else "FAIL"
        pct = overall["score_pct"] if overall["score_pct"] is not None else 0.0
        print(f"  {'OVERALL':<22} {overall['passed']:>3}/{overall['total']:<3}  {pct:>5.1f}%  [{status}]")
        print("=" * width)

        failures = [r for r in self.results if not r.passed]
        if failures:
            print(f"\n  FAILURES ({len(failures)}):")
            for r in failures:
                label = r.test_id if len(r.test_id) <= 55 else r.test_id[-55:]
                print(f"    [{r.subsystem}] {label}")
                if r.notes:
                    print(f"      {r.notes}")
        print()
