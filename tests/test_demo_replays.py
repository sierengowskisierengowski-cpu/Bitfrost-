import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
REPLAY_DIR = REPO_ROOT / "examples" / "replay"
REQUIRED_REPLAYS = [
    "benign_web_burst.jsonl",
    "initial_access.jsonl",
    "execution_tmp_exec.jsonl",
    "persistence_systemd.jsonl",
    "credential_access_chain.jsonl",
    "port_scan.jsonl",
    "lateral_movement.jsonl",
    "suid_binary.jsonl",
    "burst_replay.jsonl",
    "ingest_dependency_down.jsonl",
]


def test_bifrost_demo_module_runs_cli(tmp_path):
    scenario = REPLAY_DIR / "benign_web_burst.jsonl"
    audit_log = tmp_path / "decision_audit.jsonl"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "bifrost.demo",
            "--scenario",
            str(scenario),
            "--out",
            str(audit_log),
            "--no-color",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert audit_log.exists()
    assert "SUMMARY" in result.stdout


def test_required_replay_files_exist_and_are_valid_jsonl():
    for replay_name in REQUIRED_REPLAYS:
        replay_path = REPLAY_DIR / replay_name
        assert replay_path.exists(), replay_name
        lines = [line for line in replay_path.read_text().splitlines() if line.strip()]
        assert lines, replay_name
        for line in lines:
            payload = json.loads(line)
            assert "type" in payload
