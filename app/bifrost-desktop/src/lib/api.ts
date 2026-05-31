import { useSyncExternalStore } from "react";
import type {
  GuardianState,
  ConnectionInfo,
  LiveEvent,
  Incident,
  TimeRange,
  TimeBucket,
  OverviewStats,
} from "./types";
import { generateGuardianState, makeLiveEvent, buildMitre } from "./mockData";

/* ---------------- settings ---------------- */

export interface AppSettings {
  guardianHost: string;
  dashboardPort: number;
  ingestPort: number;
  refreshIntervalMs: number;
  screensaverMs: number;
  fontScale: number;
  sessionTimeoutMin: number;
  desktopNotifications: boolean;
}

const SETTINGS_KEY = "bifrost.settings";

const DEFAULT_SETTINGS: AppSettings = {
  guardianHost: "127.0.0.1",
  dashboardPort: 8766,
  ingestPort: 8765,
  refreshIntervalMs: 5000,
  screensaverMs: 5 * 60 * 1000,
  fontScale: 1,
  sessionTimeoutMin: 30,
  desktopNotifications: true,
};

// Cache a stable snapshot so useSyncExternalStore doesn't loop: only return a
// new object reference when the persisted value actually changes.
let cachedRaw: string | null = null;
let cachedSettings: AppSettings = { ...DEFAULT_SETTINGS };

export function getSettings(): AppSettings {
  let raw: string | null = null;
  try {
    raw = localStorage.getItem(SETTINGS_KEY);
  } catch {
    /* ignore */
  }
  if (raw === cachedRaw) return cachedSettings;
  cachedRaw = raw;
  try {
    cachedSettings = raw ? { ...DEFAULT_SETTINGS, ...JSON.parse(raw) } : { ...DEFAULT_SETTINGS };
  } catch {
    cachedSettings = { ...DEFAULT_SETTINGS };
  }
  return cachedSettings;
}

export function saveSettings(patch: Partial<AppSettings>) {
  const next = { ...getSettings(), ...patch };
  const raw = JSON.stringify(next);
  localStorage.setItem(SETTINGS_KEY, raw);
  cachedRaw = raw;
  cachedSettings = next;
  guardian.applySettings(next);
  settingsListeners.forEach((l) => l());
}

const settingsListeners = new Set<() => void>();
export function useSettings(): AppSettings {
  return useSyncExternalStore(
    (cb) => {
      settingsListeners.add(cb);
      return () => settingsListeners.delete(cb);
    },
    getSettings,
    getSettings
  );
}

export function baseUrl(s: AppSettings = getSettings()) {
  return `http://${s.guardianHost}:${s.dashboardPort}`;
}

/* ---------------- guardian client ---------------- */

const MAX_LIVE = 200;

class GuardianClient {
  private state: GuardianState = generateGuardianState();
  private conn: ConnectionInfo = {
    status: "connecting",
    source: "mock",
    lastUpdated: Date.now(),
    retryInSec: 0,
    baseUrl: baseUrl(),
  };
  private stateListeners = new Set<() => void>();
  private connListeners = new Set<() => void>();
  private liveListeners = new Set<() => void>();
  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private liveTimer: ReturnType<typeof setTimeout> | null = null;
  private tickTimer: ReturnType<typeof setInterval> | null = null;
  private retryTimer: ReturnType<typeof setInterval> | null = null;
  private backoff = 1;
  private started = false;

  start() {
    if (this.started) return;
    this.started = true;
    this.poll();
    this.pollTimer = setInterval(() => this.poll(), getSettings().refreshIntervalMs);
    this.scheduleLive();
    this.tickTimer = setInterval(() => this.tick(), 4000);
    this.retryTimer = setInterval(() => {
      if (this.conn.status === "disconnected" && this.conn.retryInSec > 0) {
        this.setConn({ retryInSec: this.conn.retryInSec - 1 });
      }
    }, 1000);
  }

  applySettings(_s: AppSettings) {
    this.conn = { ...this.conn, baseUrl: baseUrl() };
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = setInterval(() => this.poll(), getSettings().refreshIntervalMs);
    }
    this.poll();
  }

  private async poll() {
    const url = `${baseUrl()}/api/state`;
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 2500);
      const res = await fetch(url, { signal: ctrl.signal });
      clearTimeout(t);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = (await res.json()) as Partial<GuardianState>;
      this.state = { ...this.state, ...data };
      this.backoff = 1;
      this.setConn({ status: "connected", source: "live", lastUpdated: Date.now(), retryInSec: 0 });
      this.emitState();
    } catch {
      // No guardian reachable — fall back to the rich local model (also powers offline mode).
      this.backoff = Math.min(this.backoff * 2, 30);
      this.setConn({
        status: "disconnected",
        source: "mock",
        retryInSec: this.backoff,
        lastUpdated: this.conn.lastUpdated,
      });
    }
  }

  private scheduleLive() {
    const delay = 1000 + Math.random() * 2000;
    this.liveTimer = setTimeout(() => {
      const evt = makeLiveEvent(this.state.attackers);
      this.state = { ...this.state, liveEvents: [evt, ...this.state.liveEvents].slice(0, MAX_LIVE) };
      this.emitLive();
      this.scheduleLive();
    }, delay);
  }

  private tick() {
    const c = { ...this.state.counters };
    c.eventsPerMin = Math.max(10, c.eventsPerMin + (Math.floor(Math.random() * 21) - 10));
    c.activeAttackers = Math.max(1, c.activeAttackers + (Math.floor(Math.random() * 5) - 2));
    c.queueDepth = Math.max(0, c.queueDepth + (Math.floor(Math.random() * 5) - 2));
    c.processedToday += Math.floor(Math.random() * 30);
    const hw = { ...this.state.hardware };
    hw.cpuPercent = Math.min(98, Math.max(8, hw.cpuPercent + (Math.floor(Math.random() * 13) - 6)));
    hw.ramUsed = Math.min(hw.ramTotal, Math.max(2, hw.ramUsed + (Math.random() - 0.5) * 0.4));
    hw.uptimeSec += 4;
    const ai = { ...this.state.aiModel, lastResponseMs: 110 + Math.floor(Math.random() * 200) };
    this.state = { ...this.state, counters: c, hardware: hw, aiModel: ai };
    this.emitState();
  }

  /* live mutations from UI (e.g. toggles) */
  patchConfig(patch: Partial<GuardianState["config"]>) {
    this.state = { ...this.state, config: { ...this.state.config, ...patch } };
    this.emitState();
  }

  private setConn(patch: Partial<ConnectionInfo>) {
    this.conn = { ...this.conn, ...patch };
    this.connListeners.forEach((l) => l());
  }
  private emitState() {
    this.stateListeners.forEach((l) => l());
  }
  private emitLive() {
    this.liveListeners.forEach((l) => l());
  }

  subscribeState = (cb: () => void) => {
    this.stateListeners.add(cb);
    return () => this.stateListeners.delete(cb);
  };
  subscribeConn = (cb: () => void) => {
    this.connListeners.add(cb);
    return () => this.connListeners.delete(cb);
  };
  subscribeLive = (cb: () => void) => {
    this.liveListeners.add(cb);
    return () => this.liveListeners.delete(cb);
  };
  getState = () => this.state;
  getConn = () => this.conn;
  getLive = () => this.state.liveEvents;
}

export const guardian = new GuardianClient();

/* ---------------- hooks ---------------- */

export function useGuardian(): GuardianState {
  return useSyncExternalStore(guardian.subscribeState, guardian.getState, guardian.getState);
}

export function useConnection(): ConnectionInfo {
  return useSyncExternalStore(guardian.subscribeConn, guardian.getConn, guardian.getConn);
}

export function useLiveEvents(): LiveEvent[] {
  return useSyncExternalStore(guardian.subscribeLive, guardian.getLive, guardian.getLive);
}

/* ---------------- derived helpers ---------------- */

export function rangeMs(r: TimeRange): number {
  switch (r) {
    case "1H": return 3600_000;
    case "24H": return 86400_000;
    case "7D": return 7 * 86400_000;
    case "30D": return 30 * 86400_000;
    case "ALL": return Infinity;
  }
}

export function filterByRange<T extends { timestamp: string }>(items: T[], r: TimeRange): T[] {
  const span = rangeMs(r);
  if (span === Infinity) return items;
  const cutoff = Date.now() - span;
  return items.filter((i) => +new Date(i.timestamp) >= cutoff);
}

export function computeOverview(incidents: Incident[], attackerCount: number, processedToday: number): OverviewStats {
  const lastHourCut = Date.now() - 3600_000;
  const lastHour = incidents.filter((i) => +new Date(i.timestamp) >= lastHourCut).length;
  const criticalHigh = incidents.filter((i) => i.severity === "CRITICAL" || i.severity === "HIGH").length;
  const blocked = incidents.filter((i) => i.actionTaken !== "MONITORED").length;
  return {
    totalEvents: processedToday,
    incidents: incidents.length,
    blockedPct: incidents.length ? Math.round((blocked / incidents.length) * 1000) / 10 : 0,
    uniqueAttackers: attackerCount,
    lastHour,
    criticalHigh,
  };
}

export function buildBuckets(incidents: Incident[], r: TimeRange, slots = 24): TimeBucket[] {
  const span = r === "ALL" ? 30 * 86400_000 : rangeMs(r);
  const now = Date.now();
  const start = now - span;
  const size = span / slots;
  const buckets: TimeBucket[] = Array.from({ length: slots }, (_, i) => {
    const t0 = start + i * size;
    return {
      t: new Date(t0).toISOString(),
      label: formatBucketLabel(new Date(t0), r),
      count: 0,
      uniqueAttackers: 0,
      topAttackers: [],
    };
  });
  const perBucketIps: Record<number, Record<string, number>> = {};
  for (const inc of incidents) {
    const ts = +new Date(inc.timestamp);
    if (ts < start || ts > now) continue;
    const idx = Math.min(slots - 1, Math.floor((ts - start) / size));
    buckets[idx].count++;
    perBucketIps[idx] = perBucketIps[idx] || {};
    perBucketIps[idx][inc.attackerIp] = (perBucketIps[idx][inc.attackerIp] || 0) + 1;
  }
  buckets.forEach((b, idx) => {
    const ips = perBucketIps[idx] || {};
    b.uniqueAttackers = Object.keys(ips).length;
    b.topAttackers = Object.entries(ips)
      .map(([ip, count]) => ({ ip, count }))
      .sort((a, c) => c.count - a.count)
      .slice(0, 3);
  });
  return buckets;
}

function formatBucketLabel(d: Date, r: TimeRange): string {
  if (r === "1H") return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  if (r === "24H") return d.toLocaleTimeString([], { hour: "2-digit" });
  return d.toLocaleDateString([], { month: "short", day: "numeric" });
}

export { buildMitre };
