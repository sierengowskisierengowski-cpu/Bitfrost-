.PHONY: demo-benign demo-portscan demo-spawn demo-mdrfckr \
        demo-initial-access demo-exec demo-persistence demo-cred \
        demo-lateral demo-suid demo-burst demo-depdown \
        demo-all-attacks test lab-validate lab-validate-reset clean

demo-benign:
	python3 -m bifrost.demo --scenario examples/replay/benign_web_burst.jsonl

demo-portscan:
	python3 -m bifrost.demo --scenario examples/replay/port_scan.jsonl

demo-spawn:
	python3 -m bifrost.demo --scenario examples/replay/suspicious_process_spawn.jsonl

demo-mdrfckr:
	python3 -m bifrost.demo --scenario examples/replay/mdrfckr_botnet.jsonl

demo-initial-access:
	python3 -m bifrost.demo --scenario examples/replay/initial_access.jsonl

demo-exec:
	python3 -m bifrost.demo --scenario examples/replay/execution_tmp_exec.jsonl

demo-persistence:
	python3 -m bifrost.demo --scenario examples/replay/persistence_systemd.jsonl

demo-cred:
	python3 -m bifrost.demo --scenario examples/replay/credential_access_chain.jsonl

demo-lateral:
	python3 -m bifrost.demo --scenario examples/replay/lateral_movement.jsonl

demo-suid:
	python3 -m bifrost.demo --scenario examples/replay/suid_binary.jsonl

demo-burst:
	python3 -m bifrost.demo --scenario examples/replay/burst_replay.jsonl

demo-depdown:
	python3 -m bifrost.demo --scenario examples/replay/ingest_dependency_down.jsonl

demo-all-attacks:
	python3 -m bifrost.demo --scenario examples/replay/initial_access.jsonl
	python3 -m bifrost.demo --scenario examples/replay/execution_tmp_exec.jsonl
	python3 -m bifrost.demo --scenario examples/replay/persistence_systemd.jsonl
	python3 -m bifrost.demo --scenario examples/replay/credential_access_chain.jsonl
	python3 -m bifrost.demo --scenario examples/replay/port_scan.jsonl
	python3 -m bifrost.demo --scenario examples/replay/lateral_movement.jsonl
	python3 -m bifrost.demo --scenario examples/replay/suid_binary.jsonl

test:
	python3 -m pytest tests/ -v

lab-validate:
	python3 -m lab.validate

lab-validate-reset:
	python3 -m lab.validate --reset-lock

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -f logs/decision_audit.jsonl
