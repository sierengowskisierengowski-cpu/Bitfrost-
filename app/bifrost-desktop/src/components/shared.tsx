import { motion } from "framer-motion";
import type { ReactNode } from "react";
import type { Severity, TimeRange } from "@/lib/types";

export function severityClass(s: Severity): string {
  return {
    CRITICAL: "severity-critical",
    HIGH: "severity-high",
    MEDIUM: "severity-medium",
    LOW: "severity-low",
    INFO: "severity-info",
  }[s];
}

export function SeverityBadge({ severity, className = "" }: { severity: Severity; className?: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] font-bold font-mono tracking-wider ${severityClass(
        severity
      )} ${className}`}
    >
      {severity}
    </span>
  );
}

export function GlassCard({
  children,
  className = "",
  tilt = false,
}: {
  children: ReactNode;
  className?: string;
  tilt?: boolean;
}) {
  return (
    <div className={`glass-panel rounded-xl ${tilt ? "card-hover-tilt" : ""} ${className}`}>{children}</div>
  );
}

export function StatCard({
  label,
  value,
  icon,
  accent = "#E040FB",
  sub,
  delay = 0,
}: {
  label: string;
  value: string;
  icon: ReactNode;
  accent?: string;
  sub?: string;
  delay?: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay, type: "spring", stiffness: 120, damping: 18 }}
      className="glass-panel rounded-xl card-hover-tilt p-5 flex flex-col gap-3 relative overflow-hidden"
    >
      <div className="absolute -right-6 -top-6 w-24 h-24 rounded-full blur-2xl opacity-25" style={{ background: accent }} />
      <div className="flex items-center justify-between">
        <span className="text-xs uppercase tracking-wider text-muted-foreground">{label}</span>
        <span style={{ color: accent }}>{icon}</span>
      </div>
      <div className="text-3xl font-bold font-mono tracking-tight rainbow-text">{value}</div>
      {sub && <div className="text-xs text-muted-foreground font-mono">{sub}</div>}
    </motion.div>
  );
}

export function RangePills({
  value,
  onChange,
  options = ["1H", "24H", "7D", "30D", "ALL"],
}: {
  value: TimeRange;
  onChange: (r: TimeRange) => void;
  options?: TimeRange[];
}) {
  return (
    <div className="inline-flex rounded-lg border border-border/60 bg-black/30 p-1 gap-1">
      {options.map((o) => (
        <button
          key={o}
          onClick={() => onChange(o)}
          className={`px-3 py-1 rounded-md text-xs font-mono font-semibold transition-all ${
            value === o ? "rainbow-bg text-white shadow" : "text-muted-foreground hover:text-foreground hover:bg-white/5"
          }`}
        >
          {o}
        </button>
      ))}
    </div>
  );
}

export function PageHeader({ title, desc, right }: { title: string; desc?: string; right?: ReactNode }) {
  return (
    <div className="flex items-end justify-between gap-4 mb-6 flex-wrap">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">{title}</h1>
        {desc && <p className="text-sm text-muted-foreground mt-1">{desc}</p>}
      </div>
      {right}
    </div>
  );
}

export function Toggle({
  checked,
  onChange,
  label,
  accent = "#E040FB",
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
  accent?: string;
}) {
  return (
    <button
      onClick={() => onChange(!checked)}
      className="flex items-center gap-3 group no-drag"
      type="button"
    >
      <span
        className="relative w-11 h-6 rounded-full transition-all duration-300 border border-white/10"
        style={{
          background: checked ? accent : "rgba(255,255,255,0.08)",
          boxShadow: checked ? `0 0 14px -2px ${accent}` : "none",
        }}
      >
        <span
          className="absolute top-0.5 h-5 w-5 rounded-full bg-white transition-all duration-300"
          style={{ left: checked ? "22px" : "2px" }}
        />
      </span>
      <span className="text-sm">{label}</span>
    </button>
  );
}

export function Bar({ value, max, color }: { value: number; max: number; color: string }) {
  const pct = max ? Math.min(100, (value / max) * 100) : 0;
  return (
    <div className="h-2 w-full rounded-full bg-white/8 overflow-hidden">
      <div className="h-full rounded-full transition-all duration-500" style={{ width: `${pct}%`, background: color }} />
    </div>
  );
}

export function EmptyState({ message }: { message: string }) {
  return (
    <div className="flex items-center justify-center py-16 text-sm text-muted-foreground font-mono">{message}</div>
  );
}
