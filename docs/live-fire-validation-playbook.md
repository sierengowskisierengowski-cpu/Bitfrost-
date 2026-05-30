# Bifrost Live-Fire Validation Playbook

**Authorized use only.** Run this only in systems you own or where you have
written authorization. Keep testing isolated from production.

This playbook implements a phased live-fire process for validating that Bifrost
holds up under realistic attack pressure in a controlled lab.

Use this together with:

- [lab-attack-simulation.md](./lab-attack-simulation.md)
- [templates/live-fire-scorecard.csv](./templates/live-fire-scorecard.csv)

---

## Phase 0 — Pre-Flight Session Setup (mandatory)

Run this once per lab session before any attack simulation:

```bash
cd /tmp/workspace/sierengowskisierengowski-cpu/Bifrost
cp docs/templates/live-fire-scorecard.csv \
   docs/templates/live-fire-scorecard-$(date +%F)-run01.csv
```

Then pass this gate before continuing:

- Host-only/private network with no production routes
- All VMs snapshotted (`pre-test`)
- Test scope documented (IPs, attack categories, duration)
- Recovery procedure tested (`snapshot restore`)

If any item fails: **stop test execution**.

---

## Phase 1 — Safe Baseline Replay (learning + dry-run)

Start with non-enforcing mode:

```json
{
  "learning_mode": true,
  "dry_run": true,
  "autonomous_actions_enabled": false
}
```

Run the baseline replay from the repository root:

```bash
cd /tmp/workspace/sierengowskisierengowski-cpu/Bifrost
make demo-benign
make demo-all-attacks
```

Gate criteria:

- Pipeline stays healthy (no crashes/hangs)
- Decisions are produced for expected events
- No destructive action is actually enforced
- Benign replay does not produce high-confidence destructive decisions
- Results are captured from `logs/decision_audit.jsonl`

---

## Phase 2 — Progressive Attack Categories

Use the VM commands in [lab-attack-simulation.md](./lab-attack-simulation.md)
and execute categories in this order:

1. Initial access
2. Execution
3. Persistence
4. Credential access
5. Discovery
6. Lateral movement
7. Privilege escalation staging (SUID)

After each category, record expected vs actual behavior in the copied scorecard
CSV:

- Expected threat class, severity, action
- Detection latency
- Whether policy gate allowed or blocked enforcement
- False positives / false negatives

Gate criteria:

- Expected class/action appears in audit output
- Policy gate behavior matches current mode
- No unsafe action on protected/private targets

---

## Phase 3 — Stress and Failure Drills

Validate resilience under pressure and dependency failure.

Replay the stress scenarios first:

```bash
cd /tmp/workspace/sierengowskisierengowski-cpu/Bifrost
make demo-burst
make demo-depdown
```

Then run the equivalent lab-side dependency and network interruption checks.

Recommended checks:

- Event bursts: replay multiple scenario files back-to-back
- Ingest/API disruption: temporarily stop inference endpoint
- Network interruptions between agent and pipeline
- Restart one component while others continue running

Gate criteria:

- System degrades safely (alerts/logs, no unsafe autonomous action)
- Components recover cleanly after dependency restoration
- Event processing resumes without manual data surgery
- Recovery behavior and latency are recorded in scorecard notes

---

## Phase 4 — Lab-Only Enforcement

Only after stable dry-run results, move to enforcement in lab:

```json
{
  "learning_mode": false,
  "dry_run": false,
  "autonomous_actions_enabled": true
}
```

Re-run the same Phase 2 category sequence and verify:

- Intended action is actually executed when policy allows
- RFC1918/loopback protections are honored unless explicitly overridden
- Quarantine and rollback data is recorded correctly

Gate criteria:

- Correct actions with no safety-policy violations
- No destructive action against protected process/IP boundaries

---

## Phase 5 — Tune and Retest Loop

After each run:

1. Classify each scenario result (TP / FP / FN / TN)
2. Adjust thresholds/rules/policy minimally
3. Restore snapshot
4. Replay same scenario set
5. Compare scorecard metrics to previous run

Promote changes only when:

- False positive rate is acceptable for your environment
- Missed critical detections are resolved
- Stability and latency are consistent across repeated runs

---

## Suggested Execution Cadence

Per validation cycle:

1. Phase 0 once per lab session
2. Phase 1 once after config changes
3. Phase 2 full category sweep in dry-run
4. Phase 3 replay and live failure drills
5. Phase 4 full category sweep in enforcement
6. Phase 5 tune-and-repeat as needed

Treat each cycle as complete only when scorecard evidence is filled in.
