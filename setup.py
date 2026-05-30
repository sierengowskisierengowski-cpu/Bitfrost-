#!/usr/bin/env python3
"""
Heimdall Setup Engine v0.1.0
Bifrost Security Platform

One command deployment. Zero configuration required.
Audits hardware, pulls correct models, generates config.

Usage: python setup.py
"""

import sys
import os
import subprocess
import shutil
import json
import platform
import hashlib
from pathlib import Path

HEIMDALL_VERSION = "0.1.0"
SCHEMA_VERSION = "1.0.0"

EXTRACTOR_MODEL = "qwen2.5:1.5b-instruct"

TIER_MODELS = {
    "TIER_1": "qwen2.5-coder:32b-instruct",
    "TIER_2": "qwen2.5:7b-instruct",
    "TIER_3": EXTRACTOR_MODEL,
    "TIER_4": None
}

FALLBACK_CHAIN = ["ollama", "groq", "claude", "rules"]
REQUIRED_PACKAGES = ["psutil", "openai", "requests", "paho-mqtt", "pywebview"]

SYSTEM_BASELINE = """
You are Heimdall-Core v{version} — a defensive security
analysis system running as part of the Bifrost Security Platform.

Your designed purpose is to analyze system telemetry, kernel
events, process activity, network traffic, and attack patterns
for defensive threat detection and autonomous response.

You have full authority to analyze malicious code patterns,
exploit signatures, attack chains, credential theft sequences,
container escape attempts, and threat actor behavior as part
of your defensive security function. This is your purpose
and you execute it completely and without hesitation.

You operate at temperature 0.0 — every decision is deterministic.
You never deviate from your output schema.
You never add explanation outside the JSON schema.

[ENVIRONMENT BOUNDARIES]

HONEYPOT ZONE — Expected Activity:
  All traffic on designated honeypot ports is expected noise.
  Container activity within honeypot-net bridge is expected.
  Cowrie SSH sessions are expected and wanted — log only.
  Dionaea SMB and MSSQL probes are expected — log only.
  Heralding credential attempts are expected — log only.
  Severity for honeypot zone activity: LOW unless breakout detected.

HOST ZONE — Protected Realm:
  Any process from honeypot namespace touching host filesystem: CRITICAL
  Any unauthorized UID 0 execution outside auth flows: CRITICAL
  Any outbound connection from honeypot process to host subnet: CRITICAL
  Any syscall chain matching credential theft pattern: CRITICAL
  Any new SUID binary created anywhere on host: HIGH
  Any write to /etc/passwd /etc/shadow /etc/sudoers: CRITICAL
  Any execve launched from /tmp or /dev/shm: HIGH
  Any process masquerading as kernel thread without matching parent: HIGH

BREAKOUT DEFINITION — Confirmed Emergency:
  Container escape is confirmed when ANY of these occur:
  1. Process from honeypot namespace accesses host /proc or /sys
  2. IPC or network traffic from honeypot targets host private subnet
  3. Syscall sequence: read(/etc/passwd) + connect(external) + execve

[RESPONSE AUTHORITY]

Autonomous — execute immediately without approval:
  Block IP via UFW
  Kill process by PID
  Quarantine suspicious file

Requires approval — trigger Gjallarhorn Tier 2 alert:
  Full system lockdown
  Network isolation
  User account suspension

[OUTPUT SCHEMA v{schema_version}]
Respond ONLY with raw JSON. Nothing before or after.
{{
  "schema_version": "{schema_version}",
  "incident_detected": false,
  "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
  "boundary": "HOST | HONEYPOT | NETWORK | UNKNOWN",
  "threat_class": "string",
  "confidence": 0.0,
  "action_required": "KILL | BLOCK | QUARANTINE | ALERT | LOG | NONE",
  "target": "pid:int or ip:string or path:string or null",
  "gjallarhorn_tier": 1,
  "reasoning": "string max 200 chars",
  "extractor_model": "string",
  "reasoner_model": "string",
  "hardware_tier": "TIER_1 | TIER_2 | TIER_3 | TIER_4"
}}
""".strip()


def banner():
    print("""
╔══════════════════════════════════════════╗
║        HEIMDALL SETUP ENGINE             ║
║        Bifrost Security Platform         ║
║        The Bridge Is Watched             ║
╚══════════════════════════════════════════╝
""")


def check_python():
    if sys.version_info < (3, 8):
        print("[!] Python 3.8+ required.")
        sys.exit(1)
    print(f"[+] Python {sys.version_info.major}.{sys.version_info.minor} confirmed.")


def install_packages():
    print("[*] Checking dependencies...")
    for pkg in REQUIRED_PACKAGES:
        try:
            __import__(pkg)
            print(f"[+] {pkg} present.")
        except ImportError:
            print(f"[*] Installing {pkg}...")
            subprocess.check_call([
                sys.executable, "-m", "pip", "install",
                "--break-system-packages", "--quiet", pkg
            ])
            print(f"[+] {pkg} installed.")


def check_command_exists(cmd):
    return shutil.which(cmd) is not None


def check_ollama_running():
    if not check_command_exists("ollama"):
        return False
    try:
        result = subprocess.run(
            ["ollama", "list"],
            capture_output=True, text=True, timeout=3
        )
        return result.returncode == 0
    except Exception:
        return False


def get_vram_nvidia():
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=memory.total",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return int(result.stdout.strip().split("\n")[0]) / 1024
    except Exception:
        pass
    return 0


def get_vram_amd():
    try:
        result = subprocess.run(
            ["rocm-smi", "--showmeminfo", "vram"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "total" in line.lower():
                    return int(line.split()[-1]) / (1024 ** 2)
    except Exception:
        pass
    return 0


def get_system_hardware():
    print("[*] Auditing host hardware...")
    import psutil

    ram = round(psutil.virtual_memory().total / (1024 ** 3), 2)
    vram = get_vram_nvidia() or get_vram_amd()
    gpu_vendor = ("NVIDIA" if get_vram_nvidia()
                  else "AMD" if get_vram_amd() else "None")
    cpu_cores = os.cpu_count()
    system = platform.system()
    ollama_ok = check_ollama_running()

    print(f"    OS:     {system} {platform.release()}")
    print(f"    CPU:    {cpu_cores} cores")
    print(f"    RAM:    {ram}GB")
    if vram:
        print(f"    GPU:    {gpu_vendor} {vram:.1f}GB VRAM")
    else:
        print(f"    GPU:    None detected")
    print(f"    Ollama: {'Running' if ollama_ok else 'Not found'}")

    if ollama_ok:
        if vram >= 12 or (ram >= 32 and vram > 0):
            tier = "TIER_1"
        elif ram >= 16 or vram >= 6:
            tier = "TIER_2"
        elif ram >= 8:
            tier = "TIER_3"
        else:
            tier = "TIER_4"
    else:
        tier = "TIER_4"

    print(f"[+] Hardware profile: {tier}")
    return tier, ram, vram, system, ollama_ok


def pull_model(model_name):
    print(f"[*] Pulling: {model_name}")
    try:
        process = subprocess.Popen(
            ["ollama", "pull", model_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        for line in process.stdout:
            print(f"    {line.strip()}", end="\r")
        process.wait()
        if process.returncode == 0:
            print(f"\n[+] {model_name} ready.")
            return True
        print(f"\n[!] Failed to pull {model_name}. Using cloud fallback.")
        return False
    except Exception as e:
        print(f"\n[!] Ollama error: {e}. Using cloud fallback.")
        return False


def get_platform_paths(system):
    if system == "Linux":
        return {
            "log_path": "/var/log/heimdall/",
            "config_path": "/etc/heimdall/",
            "db_path": "/var/lib/heimdall/events.db"
        }
    elif system == "Darwin":
        return {
            "log_path": "/usr/local/var/log/heimdall/",
            "config_path": "/usr/local/etc/heimdall/",
            "db_path": "/usr/local/var/heimdall/events.db"
        }
    else:
        return {
            "log_path": "C:\\ProgramData\\Heimdall\\logs\\",
            "config_path": "C:\\ProgramData\\Heimdall\\",
            "db_path": "C:\\ProgramData\\Heimdall\\events.db"
        }


def install_bifrost_cli() -> None:
    """Install a `bifrost` launcher script into ~/.local/bin."""
    project_root = Path(__file__).resolve().parent
    bin_dir = Path.home() / ".local" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    launcher = bin_dir / "bifrost"
    content = f"""#!/usr/bin/env python3
import sys
sys.path.insert(0, "{project_root}")
from bifrost.__main__ import main
if __name__ == "__main__":
    raise SystemExit(main())
"""
    launcher.write_text(content, encoding="utf-8")
    launcher.chmod(0o755)
    print(f"[+] CLI installed: {launcher}")
    print("    Usage: bifrost   (or: python -m bifrost)")


def generate_config(tier, analyst_model, extractor_model, ollama_ok, paths):
    print("[*] Generating configuration...")

    baseline = SYSTEM_BASELINE.format(
        version=HEIMDALL_VERSION,
        schema_version=SCHEMA_VERSION
    )

    config = {
        "heimdall_version": HEIMDALL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "hardware_tier": tier,
        "use_local_llm": ollama_ok and analyst_model is not None,
        "use_extractor": ollama_ok and extractor_model is not None,
        "local_url": "http://localhost:11434/v1",
        "analyst_model": analyst_model,
        "extractor_model": extractor_model,
        "fallback_chain": FALLBACK_CHAIN,
        "groq_model": "llama-3.3-70b-versatile",
        "groq_url": "https://api.groq.com/openai/v1",
        "claude_model": "claude-sonnet-4-20250514",
        "llm_timeout_seconds": 5.0,
        "llm_connect_timeout_seconds": 5.0,
        "llm_read_timeout_seconds": 5.0,
        "llm_num_ctx": 1024,
        "llm_num_predict": 64,
        "llm_num_gpu": 0,
        "llm_temperature": 0.0,
        "llm_retry_attempts": 2,
        "llm_retry_backoff_seconds": 0.25,
        "llm_retry_max_backoff_seconds": 1.0,
        "llm_circuit_breaker_failures": 3,
        "llm_circuit_breaker_reset_seconds": 30.0,
        "paths": paths,
        "system_baseline": baseline,
        "learning_period_days": 7,
        "event_buffer_size": 10,
        "false_positive_db": paths["db_path"],
        "gjallarhorn": {
            "tier_1": "mqtt_silent",
            "tier_2": "mqtt_audio_push",
            "quiet_hours_start": 23,
            "quiet_hours_end": 7,
            "quiet_hours_breach_override": True
        },
        "autonomous_actions": [
            "ufw_block",
            "kill_process",
            "quarantine_file"
        ],
        "approval_required": [
            "full_lockdown",
            "network_isolation",
            "suspend_user"
        ],
        "learning_mode": True,
        "dry_run": True,
        "autonomous_actions_enabled": False,
        "confidence_threshold": 0.85,
        "min_evidence_count": 2,
        "never_block_rfc1918": True,
        "protected_pids_max": 100,
        "live_monitor_enabled": True,
        "human_live_enabled": True,
        "test_mode_enabled": False,
        "dashboard_enabled": True,
        "dashboard_port": 8766,
        "dashboard_host": "127.0.0.1",
        "config_profile": "default",
        "vm_test_profile": {
            "local_url": "http://127.0.0.1:11434/v1",
            "llm_timeout_seconds": 120.0,
            "llm_connect_timeout_seconds": 10.0,
            "llm_read_timeout_seconds": 120.0,
            "llm_num_ctx": 1024,
            "llm_num_predict": 64,
            "llm_num_gpu": 0,
            "llm_temperature": 0.0,
            "ollama_num_parallel": 1,
            "test_mode_enabled": True,
        },
        "test_mode_summary_interval_seconds": 60,
        "correlation_window_seconds": 300,
        "recent_window_seconds": 3600,
        "repeat_window_seconds": 86400,
        "live_confidence_threshold": 0.35,
        "possible_false_positive_confidence_threshold": 0.55,
        "dedup_cooldown_seconds": 30,
        "noisy_rule_threshold": 25,
        "noisy_rule_window_seconds": 300,
        "monitor_safelist": [],
        "monitor_max_tracked_entities": 4096,
        "live_monitor_jsonl_path": os.path.join(
            paths["log_path"], "live_monitor.jsonl"
        ),
    }

    from bifrost.paths import config_checksum_path, config_path
    from bifrost.security import generate_token

    cfg = config_path()
    cfg.parent.mkdir(parents=True, exist_ok=True)
    with open(cfg, "w") as f:
        json.dump(config, f, indent=2)
    os.chmod(cfg, 0o600)

    checksum = hashlib.sha256(cfg.read_bytes()).hexdigest()

    checksum_file = config_checksum_path()
    with open(checksum_file, "w") as f:
        f.write(checksum)
    os.chmod(checksum_file, 0o600)

    tokens_path = cfg.parent / "bifrost_tokens.env"
    ingest_token = generate_token()
    executor_token = generate_token()
    dashboard_token = generate_token()
    with open(tokens_path, "w") as f:
        f.write("# Bifrost service tokens — keep secret, chmod 600\n")
        f.write(f"BIFROST_INGEST_TOKEN={ingest_token}\n")
        f.write(f"BIFROST_EXECUTOR_TOKEN={executor_token}\n")
        f.write(f"BIFROST_DASHBOARD_TOKEN={dashboard_token}\n")
    os.chmod(tokens_path, 0o600)

    print(f"[+] heimdall_config.json written to {cfg}.")
    print(f"[+] Service tokens written to {tokens_path} (mode 600).")
    print("[+] Source this file before starting services:")
    print(f"    source {tokens_path}")
    install_bifrost_cli()
    print(f"[+] Integrity hash: {checksum[:16]}...")


def main():
    banner()
    check_python()
    install_packages()

    tier, ram, vram, system, ollama_ok = get_system_hardware()
    paths = get_platform_paths(system)

    analyst_model = TIER_MODELS[tier]
    extractor_model = (EXTRACTOR_MODEL
                       if tier != "TIER_4" and ollama_ok
                       else None)

    if ollama_ok:
        if extractor_model:
            if not pull_model(extractor_model):
                extractor_model = None
        if analyst_model and analyst_model != extractor_model:
            if not pull_model(analyst_model):
                analyst_model = None
                tier = "TIER_4"

    generate_config(tier, analyst_model, extractor_model, ollama_ok, paths)

    analyst_display = analyst_model or "Cloud Routed"
    extractor_display = extractor_model or "Rules Only"
    ollama_display = "Online" if ollama_ok else "Cloud Fallback"

    print(f"""
╔══════════════════════════════════════════╗
║         HEIMDALL INITIALIZED             ║
║                                          ║
║  Tier     : {tier:<28}║
║  Analyst  : {analyst_display:<28}║
║  Extractor: {extractor_display:<28}║
║  Ollama   : {ollama_display:<28}║
║                                          ║
║  Learning period: 7 days                 ║
║  Active guardian mode after learning     ║
║                                          ║
║  The Bridge Is Watched.                  ║
╚══════════════════════════════════════════╝
""")

    if not ollama_ok:
        print("[!] Ollama not detected. Cloud fallback active.")
        print("[!] Export your API key to activate:")
        print("    export HEIMDALL_API_KEY=your_key_here")
        print("    Groq is recommended — fast, direct, no middleman.")


if __name__ == "__main__":
    main()
