# Bifrost Security Platform

The Bridge Is Watched.

An open source AI-powered Endpoint Detection and Response platform
that runs on any hardware from a Raspberry Pi to a workstation.

> **⚠️ AUTHORIZED USE ONLY**
> Bifrost is a defensive security tool. Deploy and operate it **only on systems
> you own or have explicit written authorization to monitor and protect.**
> Unauthorized use against systems you do not own may violate the Computer
> Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent laws
> in your jurisdiction. The authors accept no liability for unauthorized use.
> See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy,
> [docs/lab-attack-simulation.md](docs/lab-attack-simulation.md) for attack
> simulation scenarios, and
> [docs/live-fire-validation-playbook.md](docs/live-fire-validation-playbook.md)
> for phased live-fire lab validation with pass/fail gates.

## What Is Bifrost

Bifrost is a portable AI-powered security sentinel that watches
your Linux system for threats and responds autonomously.

It is not a pattern matcher. It reasons.

Every existing open source security tool matches events against
rules someone wrote in advance. The moment an attacker does
something outside those rules the tool misses it.

Bifrost uses AI to understand what a sequence of events means
in context. A process reading /etc/passwd once is nothing.
The same process then opening an outbound connection then
calling execve is a confirmed credential theft attempt.
Bifrost sees the chain. Bifrost acts on the chain.

## The Mythology

| Component | Role | Mythology |
|---|---|---|
| Yggdrasil | Kernel layer | The world tree — root of everything |
| Bifrost | Event pipeline | The bridge — all signal flows across it |
| Heimdall | AI sentinel | The guardian — watches and acts |
| Gjallarhorn | Alert system | The horn that wakes all realms |

## What Makes Bifrost Different

| Feature | Bifrost | Falco | Wazuh | CrowdStrike |
|---|---|---|---|---|
| AI reasoning | Yes | No | No | Yes |
| Fully local | Yes | Yes | Yes | No |
| Any hardware | Yes | Partial | Partial | No |
| Autonomous response | Yes | No | Partial | Yes |
| Open source | Yes | Yes | Yes | No |
| No cloud dependency | Yes | Yes | Yes | No |
| Rollback support | Yes | No | No | No |
| Portable installer | Yes | No | No | No |

No existing open source EDR combines AI reasoning with
autonomous response on any hardware. Bifrost does.

## Architecture

KERNEL SPACE
  Tetragon eBPF watches syscalls, process, filesystem, network.
  Zero overhead. Unhackable from userspace.

USER SPACE — Go Agent
  Telemetry multiplexer on Unix socket.
  Ships clean events to Bifrost pipeline.
  Executes autonomous actions from Heimdall decisions.

BIFROST PIPELINE — Python
  Extractor strips noise and compresses events to dense JSON.
  Anonymizer scrubs internal data before any external API call.
  Reasoner routes to correct AI model based on hardware tier.

HEIMDALL — AI Sentinel
  Sees attack chains not just individual events.
  Rolling 10-event buffer per process and per IP.
  Deterministic rule engine as fallback — never goes blind.

EXECUTOR — Go
  UFW block on attacking IP.
  Kill process by PID.
  Quarantine suspicious file.
  Full rollback support.

GJALLARHORN — Alert System
  Tier 1: silent MQTT log to tablet.
  Tier 2: MQTT plus audio plus push — breach detected.

## Hardware Tiers

Bifrost detects your hardware at install time and configures itself.
Same decision quality on a Pi as on an RTX 3060.

| Tier | Hardware | Local Model | Fallback |
|---|---|---|---|
| TIER_1 | RTX 3060 / 32GB | Qwen 2.5 Coder 32B | Claude API |
| TIER_2 | 16GB / mid GPU | Qwen 2.5 7B | Groq |
| TIER_3 | 8GB / no GPU | Qwen 2.5 1.5B | Groq then Claude |
| TIER_4 | Minimal / Pi | Rules only | Claude API |

Fallback chain: Local Ollama → Groq → Claude → Deterministic rules

## What Heimdall Watches

Process layer — every execve, privilege escalation, masquerading.
Filesystem layer — /etc/passwd, /etc/shadow, /tmp execution.
Network layer — outbound connections, beaconing, namespace violations.
Memory layer — memfd_create, fileless execution, process hollowing.
Authentication layer — sudo failures, SSH attempts, PAM events.
Container boundary — honeypot breakout detection.

## Response Authority

Autonomous — no approval needed:
  UFW block on attacking IP
  Kill process by PID
  Quarantine suspicious file

Requires approval — Gjallarhorn Tier 2:
  Full system lockdown
  Network isolation
  User account suspension

Every action is logged and reversible.

## Learning Period

Before active guardian mode Heimdall spends 7 days learning
what normal looks like on your specific system.

During learning all events are logged but no autonomous action
is taken. After learning anomaly detection is calibrated and
Heimdall goes active.

## Security and Safe Defaults

Bifrost ships in **learning mode + dry-run** by default. Autonomous actions
(KILL, BLOCK, QUARANTINE) are blocked by the Python policy gate until you
explicitly disable all three safeguards in `heimdall_config.json`:

- `learning_mode: false`
- `dry_run: false`
- `autonomous_actions_enabled: true`

**Do not enable autonomous mode on production systems until you have completed
the 7-day learning period and reviewed false positive rates.**

## Built-In Live Monitoring

Bifrost now ships with a native live monitoring layer inside the Guardian
pipeline. It emits:

- plain-English live incident lines for operators,
- structured JSONL records in parallel for downstream analysis,
- repeat vs new attacker and pattern classification,
- suppression/audit metadata for low-confidence, allowlisted, duplicate, or
  noisy alerts,
- TEST MODE summaries for controlled lab runs.

### Runtime toggles

`heimdall_config.json` now includes these controls:

- `live_monitor_enabled`
- `human_live_enabled`
- `test_mode_enabled`
- `test_mode_summary_interval_seconds`
- `live_confidence_threshold`
- `dedup_cooldown_seconds`
- `noisy_rule_threshold`
- `monitor_safelist`

CLI overrides are available on the Guardian runtime:

```bash
python -m bifrost.guardian --human-live --test-mode --summary-interval 60
python -m bifrost.guardian --no-human-live
python -m bifrost.guardian --live-monitor-json /tmp/live-monitor.jsonl
```

### VM Testing Mode (48h live-fire)

Use VM testing mode for CPU-only Ollama runs (for example VirtualBox + 8GB RAM):

- config precedence is now `environment > vm_test_profile > default config`
- when testing mode/profile is enabled, Guardian applies VM-safe defaults:
  - Ollama host `http://127.0.0.1:11434`
  - connect timeout `10s`, read/overall timeout `120s`
  - context size `llm_num_ctx=1024`
  - recommended Ollama parallelism `OLLAMA_NUM_PARALLEL=1`

Enable with environment variables:

```bash
export HEIMDALL_TEST_MODE_ENABLED=true
export HEIMDALL_CONFIG_PROFILE=vm-test
export OLLAMA_HOST=http://127.0.0.1:11434
export HEIMDALL_LLM_CONNECT_TIMEOUT_SECONDS=10
export HEIMDALL_LLM_READ_TIMEOUT_SECONDS=120
export HEIMDALL_LLM_TIMEOUT_SECONDS=120
export HEIMDALL_LLM_NUM_CTX=1024
export OLLAMA_NUM_PARALLEL=1
```

Systemd override example:

```ini
# /etc/systemd/system/bifrost-guardian.service.d/vm-testing.conf
[Service]
Environment="HEIMDALL_TEST_MODE_ENABLED=true"
Environment="HEIMDALL_CONFIG_PROFILE=vm-test"
Environment="OLLAMA_HOST=http://127.0.0.1:11434"
Environment="HEIMDALL_LLM_CONNECT_TIMEOUT_SECONDS=10"
Environment="HEIMDALL_LLM_READ_TIMEOUT_SECONDS=120"
Environment="HEIMDALL_LLM_TIMEOUT_SECONDS=120"
Environment="HEIMDALL_LLM_NUM_CTX=1024"
Environment="OLLAMA_NUM_PARALLEL=1"
```

Then reload:

```bash
sudo systemctl daemon-reload
sudo systemctl restart bifrost-guardian
```

During testing mode:

- human-readable live feed includes timestamp, severity marker, boundary/source,
  threat class, confidence, action, and outcome.
- structured JSONL (`live_monitor.jsonl`) includes incident records plus
  pipeline-step records, model call metadata, pass/fail assessment, and periodic
  strengths/weaknesses summaries.

To disable and revert:

```bash
unset HEIMDALL_TEST_MODE_ENABLED HEIMDALL_CONFIG_PROFILE
sudo systemctl restart bifrost-guardian
```

### What operators see

Each live line includes:

- timestamp,
- host,
- severity,
- plain-English summary,
- source/attacker identity,
- repeat/new attacker plus repeat/new pattern classification,
- counts in recent rolling windows,
- action taken.

Structured records are written to `live_monitor.jsonl` beside `guardian.log`
unless `live_monitor_jsonl_path` overrides it.

### Interpreting repeat/new and suppression output

- `attacker_status=new` means the attacker identity has not been seen in the
  current monitoring history window.
- `attacker_status=repeat` means the identity was already seen and is counted in
  the rolling windows.
- `pattern_status=new` means the behavior fingerprint is new even if the actor
  is already known.
- Suppression reasons are logged in structured output as:
  - `allowlisted`
  - `below_confidence_threshold`
  - `dedup_cooldown`
  - `noisy_rule_dampening`

Suppressed records remain visible in JSONL so defensive audit trails stay
intact while operator alert fatigue is reduced.

### Service tokens (required in production)

After `python setup.py`, source the generated token file:

    source /etc/heimdall/bifrost_tokens.env   # or your config directory

| Token | Purpose |
|---|---|
| `BIFROST_INGEST_TOKEN` | Authenticates Go collector → Python ingest |
| `BIFROST_EXECUTOR_TOKEN` | Authenticates Python → Go executor |
| `BIFROST_DASHBOARD_TOKEN` | Authenticates dashboard/API access |

Set `HEIMDALL_ENV=production` (default) to enforce token requirements.

### API keys

Store API keys in environment variables only — never in config files or logs:

    export HEIMDALL_API_KEY=your_groq_key
    export HEIMDALL_CLAUDE_KEY=your_claude_key

### Privileges

The Go agent requires `sudo` for UFW block/unblock only. Guardian runs as an
unprivileged user. Quarantined files are chmod 000 in a mode-700 directory.

### Uninstall

    sudo systemctl stop bifrost-guardian bifrost-agent
    sudo systemctl disable bifrost-guardian bifrost-agent
    sudo rm /etc/systemd/system/bifrost-*.service
    sudo systemctl daemon-reload
    # Optional — removes all data:
    # sudo rm -rf /var/lib/heimdall /var/log/heimdall /etc/heimdall

## Installation

Requirements: Linux, Python 3.8+, Go 1.21+, Ollama optional.

    git clone https://github.com/sierengowskisierengowski-cpu/Bifrost
    cd Bifrost
    python setup.py
    sudo bash install.sh
    sudo bash kernel/tetragon/setup.sh
    sudo systemctl start bifrost-guardian
    sudo systemctl start bifrost-agent

To run a lab-focused operator session with live feed and TEST MODE summaries:

```bash
python -m bifrost.guardian --human-live --test-mode --summary-interval 60
```

Set API keys for cloud fallback:

    export HEIMDALL_API_KEY=your_groq_key
    export HEIMDALL_CLAUDE_KEY=your_claude_key

## Proven On Real Attacks

Bifrost was developed and tested against live attack data from
GowskiNet — a fully operational home security research lab that
has captured 4600 plus real attacks from threat actors in 47 countries.

Notable test case — mdrfckr botnet campaign May 26 2026:
  Duration: 17 hours of live SSH botnet activity
  Session data: 63853 lines
  Credentials harvested: 50 plus unique pairs
  Artifacts: backdoor RSA key captured
  Countries: Russia, China, Netherlands, Canada, Azure cloud IPs

This is not a simulated test. Real attack data. Real threat actors.

## File Structure

    bifrost/
    setup.py                  hardware detection and installer
    install.sh                systemd service installer
    bifrost/
        guardian.py           main runtime loop
        ingest.py             HTTP endpoint for Go agent
        extractor.py          noise stripping and compression
        reasoner.py           Heimdall AI routing and decisions
        anonymizer.py         privacy layer before external APIs
        baseline.py           7 day learning period engine
        feedback.py           false positive loop and rollback
    gjallarhorn/
        alerts.py             tier 1 and tier 2 alert routing
    agent/
        collector.go          Unix socket telemetry multiplexer
        executor.go           autonomous action engine
    kernel/tetragon/
        policies/             eBPF tracing policies
        setup.sh              Tetragon installer

## Roadmap

v0.1.0 Current: Core pipeline complete. Python and Go connected.
v0.2.0 Live testing against GowskiNet. Autonomous response hardening.
v0.3.0 eBPF circuit breaker. Dynamic deception engine.
v1.0.0 Federated threat intel. Attack replay. Public release.

## Creator

Joseph Sierengowski (gowski-star)
Self-taught developer and security researcher.
Operator of GowskiNet — 4600 plus real captured attacks.

The bridge is watched. Heimdall never sleeps.
