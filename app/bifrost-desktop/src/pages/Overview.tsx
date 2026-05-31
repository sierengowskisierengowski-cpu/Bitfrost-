import { useMemo, useState } from "react";
import { Link } from "wouter";
import { Activity, ShieldAlert, ShieldCheck, Crosshair, Clock, Flame } from "lucide-react";
import { ResponsiveContainer, BarChart, Bar, XAxis, Tooltip, Cell } from "recharts";
import { useGuardian, filterByRange, computeOverview, buildBuckets } from "@/lib/api";
import type { TimeRange } from "@/lib/types";
import { StatCard, RangePills, PageHeader, SeverityBadge } from "@/components/shared";
import { fmtNum, fmtRelative } from "@/lib/format";

const RAINBOW = ["#7B2FBE", "#9D4EDD", "#C4607A", "#E040FB", "#E91E8C", "#F48FB1"];

export default function Overview() {
  const { incidents, attackers, counters } = useGuardian();
  const [range, setRange] = useState<TimeRange>("24H");

  const filtered = useMemo(() => filterByRange(incidents, range), [incidents, range]);
  const stats = useMemo(
    () => computeOverview(filtered, attackers.length, counters.processedToday),
    [filtered, attackers.length, counters.processedToday]
  );
  const buckets = useMemo(() => buildBuckets(filtered, range), [filtered, range]);
  const recent = filtered.slice(0, 100);

  return (
    <div>
      <PageHeader
        title="Overview"
        desc="Heimdall's watch over the rainbow bridge"
        right={<RangePills value={range} onChange={setRange} />}
      />

      <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4 mb-6">
        <StatCard label="Total Events" value={fmtNum(stats.totalEvents)} icon={<Activity className="w-4 h-4" />} accent="#9D4EDD" delay={0} />
        <StatCard label="Incidents" value={fmtNum(stats.incidents)} icon={<ShieldAlert className="w-4 h-4" />} accent="#E040FB" delay={0.05} />
        <StatCard label="Blocked" value={`${stats.blockedPct}%`} icon={<ShieldCheck className="w-4 h-4" />} accent="#4ECDC4" delay={0.1} />
        <StatCard label="Unique Attackers" value={fmtNum(stats.uniqueAttackers)} icon={<Crosshair className="w-4 h-4" />} accent="#C4607A" delay={0.15} />
        <StatCard label="Last Hour" value={fmtNum(stats.lastHour)} icon={<Clock className="w-4 h-4" />} accent="#E91E8C" delay={0.2} />
        <StatCard label="Critical + High" value={fmtNum(stats.criticalHigh)} icon={<Flame className="w-4 h-4" />} accent="#FF6B35" delay={0.25} />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="glass-panel rounded-xl p-5 xl:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold">Activity Timeline</h3>
            <span className="text-xs text-muted-foreground font-mono">{range}</span>
          </div>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={buckets}>
              <defs>
                <linearGradient id="rainbowBar" x1="0" y1="1" x2="0" y2="0">
                  <stop offset="0%" stopColor="#7B2FBE" />
                  <stop offset="50%" stopColor="#E040FB" />
                  <stop offset="100%" stopColor="#F48FB1" />
                </linearGradient>
              </defs>
              <XAxis dataKey="label" tick={{ fill: "#888", fontSize: 10, fontFamily: "JetBrains Mono" }} interval="preserveStartEnd" />
              <Tooltip
                cursor={{ fill: "rgba(255,255,255,0.04)" }}
                contentStyle={{ background: "#0c0c0c", border: "1px solid #222", borderRadius: 8, fontSize: 12, fontFamily: "JetBrains Mono" }}
                labelStyle={{ color: "#E040FB" }}
              />
              <Bar dataKey="count" radius={[4, 4, 0, 0]} fill="url(#rainbowBar)">
                {buckets.map((_, i) => (
                  <Cell key={i} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="glass-panel rounded-xl p-5 flex flex-col min-h-0">
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-semibold">Recent Incidents</h3>
            <Link href="/incidents">
              <span className="text-xs text-[#E040FB] hover:underline cursor-pointer">View all</span>
            </Link>
          </div>
          <div className="overflow-auto scroll-thin -mr-2 pr-2" style={{ maxHeight: 220 }}>
            {recent.map((inc) => (
              <div
                key={inc.id}
                className="flex items-center gap-3 py-2 border-b border-white/5 last:border-0 hover:bg-white/[0.03] rounded px-1"
              >
                <SeverityBadge severity={inc.severity} />
                <div className="flex-1 min-w-0">
                  <div className="text-xs truncate">{inc.threatClass}</div>
                  <div className="text-[10px] text-muted-foreground font-mono">{inc.attackerIp}</div>
                </div>
                <div className="text-[10px] text-muted-foreground font-mono shrink-0">{fmtRelative(inc.timestamp)}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="mt-4 flex items-center gap-6 text-xs text-muted-foreground font-mono glass-panel rounded-xl px-5 py-3">
        <span>events/min <span className="text-foreground">{counters.eventsPerMin}</span></span>
        <span>active attackers <span className="text-foreground">{counters.activeAttackers}</span></span>
        <span>queue depth <span className="text-foreground">{counters.queueDepth}</span></span>
        <span>processed today <span className="text-foreground">{fmtNum(counters.processedToday)}</span></span>
      </div>
    </div>
  );
}
