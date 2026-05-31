export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type CircuitState = "CLOSED" | "OPEN" | "HALF-OPEN";
export type ThreatLevel = Severity;

export interface Incident {
  id: string;
  timestamp: string;
  severity: Severity;
  threatClass: string;
  attackerIp: string;
  mitreTechnique: string;
  mitreTechniqueName: string;
  mitreTactic: string;
  actionTaken: string;
  confidenceScore: number;
  summary: string;
  model: string;
  latencyMs: number;
}

export interface CredentialAttempt {
  username: string;
  password: string;
}

export interface AttackerEvent {
  timestamp: string;
  type: string;
  command: string;
  decision: string;
  severity: Severity;
}

export interface SessionRecord {
  id: string;
  start: string;
  durationSec: number;
  commands: number;
}

export interface Attacker {
  ip: string;
  country: string;
  countryCode: string;
  flag: string;
  firstSeen: string;
  lastSeen: string;
  totalHits: number;
  threatLevel: ThreatLevel;
  attackTypes: string[];
  hassh: string;
  ja4: string;
  events: AttackerEvent[];
  credentials: CredentialAttempt[];
  sessions: SessionRecord[];
}

export interface TimeBucket {
  t: string;
  label: string;
  count: number;
  uniqueAttackers: number;
  topAttackers: { ip: string; count: number }[];
}

export interface AIModelStatus {
  model: string;
  lastResponseMs: number;
  successRate: number;
  failureRate: number;
  circuitState: CircuitState;
  prewarm: boolean;
}

export interface HardwareStatus {
  tier: string;
  ramUsed: number;
  ramTotal: number;
  cpuPercent: number;
  diskUsed: number;
  diskTotal: number;
  uptimeSec: number;
}

export interface GuardianConfig {
  learningMode: boolean;
  dryRun: boolean;
  autonomous: boolean;
  confidenceThreshold: number;
  modelsLoaded: string[];
  hardwareTier: string;
  databasePath: string;
  logPath: string;
  cowrieLogPath: string;
  ingestPort: number;
  dashboardPort: number;
  guardianHost: string;
  tokens: { ingest: boolean; executor: boolean; dashboard: boolean };
}

export interface LiveEvent {
  id: string;
  timestamp: string;
  attackerIp: string;
  attackType: string;
  category: string;
  commandRun: string;
  decision: string;
  confidence: number;
  model: string;
  latencyMs: number;
  severity: Severity;
}

export interface MitreTechnique {
  id: string;
  name: string;
  count: number;
}

export interface MitreTactic {
  id: string;
  name: string;
  techniques: MitreTechnique[];
}

export interface CategoryCount {
  name: string;
  count: number;
}

export interface Counters {
  eventsPerMin: number;
  activeAttackers: number;
  queueDepth: number;
  processedToday: number;
}

export interface OverviewStats {
  totalEvents: number;
  incidents: number;
  blockedPct: number;
  uniqueAttackers: number;
  lastHour: number;
  criticalHigh: number;
}

export interface GuardianState {
  incidents: Incident[];
  attackers: Attacker[];
  aiModel: AIModelStatus;
  hardware: HardwareStatus;
  config: GuardianConfig;
  categories: CategoryCount[];
  counters: Counters;
  liveEvents: LiveEvent[];
}

export type ConnectionStatus = "connected" | "connecting" | "disconnected";

export interface ConnectionInfo {
  status: ConnectionStatus;
  source: "live" | "mock";
  lastUpdated: number;
  retryInSec: number;
  baseUrl: string;
}

export type TimeRange = "1H" | "24H" | "7D" | "30D" | "ALL";
