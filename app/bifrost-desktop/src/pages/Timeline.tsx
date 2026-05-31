import { useMemo, useState } from "react";
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid } from "recharts";
import { useGuardian, filterByRange, buildBuckets } from "@/lib/api";
import type { TimeRange } from "@/lib/types";
import { PageHeader, RangePills, SeverityBadge } from "@/components/shared";
import { fmtDateTime } from "@/lib/format";

export default function Timeline() {
  const { incidents } = useGuardian();
  const [range, setRange] = useState<TimeRange>("7D");

  const filtered = useMemo(() => filterByRange(incidents, range), [incidents, range]);
  const buckets = useMemo(() => buildBuckets(filtered, range, 48), [filtered, range]);
  const notable = useMemo(
    () => filtered.filter((i) => i.severity === "CRITICAL" || i.severity === "HIGH").slice(0, 40),
    [filtered]
  );

  return (
    <div>
      <PageHeader
        title="Timeline"
        desc="Attack volume and notable events over time"
        right={<RangePills value={range} onChange={setRange} />}
      />

      <div className="glass-panel rounded-xl p-5 mb-6">
        <ResponsiveContainer width="100%" height={300}>
          <AreaChart data={buckets}>
            <defs>
              <linearGradient id="tlArea" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#E040FB" stopOpacity={0.7} />
                <stop offset="100%" stopColor="#7B2FBE" stopOpacity={0.05} />
              </linearGradient>
              <linearGradient id="tlStroke" x1="0" y1="0" x2="1" y2="0">
                <stop offset="0%" stopColor="#9D4EDD" />
                <stop offset="100%" stopColor="#F48FB1" />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
            <XAxis dataKey="label" tick={{ fill: "#888", fontSize: 10, fontFamily: "JetBrains Mono" }} interval="preserveStartEnd" />
            <YAxis tick={{ fill: "#888", fontSize: 10, fontFamily: "JetBrains Mono" }} width={32} />
            <Tooltip
              cursor={{ stroke: "#E040FB", strokeWidth: 1 }}
              contentStyle={{ background: "#0c0c0c", border: "1px solid #222", borderRadius: 8, fontSize: 12, fontFamily: "JetBrains Mono" }}
              labelStyle={{ color: "#E040FB" }}
            />
            <Area type="monotone" dataKey="count" stroke="url(#tlStroke)" strokeWidth={2} fill="url(#tlArea)" />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <h3 className="font-semibold mb-4">Notable Events</h3>
      <div className="relative pl-6">
        <div className="absolute left-[7px] top-2 bottom-2 w-[2px] rainbow-bg opacity-40" />
        {notable.map((inc) => (
          <div key={inc.id} className="relative mb-4">
            <span className="absolute -left-[22px] top-1.5 w-3.5 h-3.5 rounded-full rainbow-bg ring-4 ring-background" />
            <div className="glass-panel rounded-lg p-4 card-hover-tilt">
              <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-3">
                  <SeverityBadge severity={inc.severity} />
                  <span className="text-sm font-semibold">{inc.threatClass}</span>
                </div>
                <span className="text-[10px] font-mono text-muted-foreground">{fmtDateTime(inc.timestamp)}</span>
              </div>
              <div className="text-xs text-muted-foreground">{inc.summary}</div>
              <div className="flex items-center gap-4 mt-2 text-[10px] font-mono text-muted-foreground">
                <span className="text-[#9D4EDD]">{inc.attackerIp}</span>
                <span>{inc.mitreTechnique} · {inc.mitreTechniqueName}</span>
                <span>{inc.actionTaken}</span>
              </div>
            </div>
          </div>
        ))}
        {notable.length === 0 && <div className="text-sm text-muted-foreground font-mono py-8">No notable events in this range.</div>}
      </div>
    </div>
  );
}
