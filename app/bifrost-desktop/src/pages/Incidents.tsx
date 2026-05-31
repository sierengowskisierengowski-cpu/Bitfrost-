import { useMemo, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Download, Search, ChevronDown } from "lucide-react";
import { useGuardian, filterByRange } from "@/lib/api";
import type { TimeRange, Severity, Incident } from "@/lib/types";
import { RangePills, PageHeader, SeverityBadge } from "@/components/shared";
import { fmtDateTime } from "@/lib/format";

const SEVS: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const PAGE = 25;

function toCsv(rows: Incident[]): string {
  const head = ["id", "timestamp", "severity", "threatClass", "attackerIp", "mitreTechnique", "actionTaken", "confidenceScore", "summary"];
  const body = rows.map((r) =>
    [r.id, r.timestamp, r.severity, r.threatClass, r.attackerIp, r.mitreTechnique, r.actionTaken, r.confidenceScore, `"${r.summary.replace(/"/g, '""')}"`].join(",")
  );
  return [head.join(","), ...body].join("\n");
}

export default function Incidents() {
  const { incidents } = useGuardian();
  const [range, setRange] = useState<TimeRange>("7D");
  const [sev, setSev] = useState<Severity | "ALL">("ALL");
  const [tc, setTc] = useState<string>("ALL");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(0);
  const [open, setOpen] = useState<string | null>(null);

  const threatClasses = useMemo(() => Array.from(new Set(incidents.map((i) => i.threatClass))).sort(), [incidents]);

  const filtered = useMemo(() => {
    let r = filterByRange(incidents, range);
    if (sev !== "ALL") r = r.filter((i) => i.severity === sev);
    if (tc !== "ALL") r = r.filter((i) => i.threatClass === tc);
    if (q.trim()) r = r.filter((i) => i.attackerIp.includes(q.trim()));
    return r;
  }, [incidents, range, sev, tc, q]);

  const pages = Math.max(1, Math.ceil(filtered.length / PAGE));
  const cur = Math.min(page, pages - 1);
  const view = filtered.slice(cur * PAGE, cur * PAGE + PAGE);

  const exportCsv = () => {
    const blob = new Blob([toCsv(filtered)], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `bifrost-incidents-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const selectCls = "bg-black/40 border border-border rounded-lg px-3 py-2 text-xs font-mono outline-none focus:border-[#E040FB]";

  return (
    <div>
      <PageHeader
        title="Incidents"
        desc={`${filtered.length} incidents in view`}
        right={<RangePills value={range} onChange={(r) => { setRange(r); setPage(0); }} />}
      />

      <div className="flex flex-wrap items-center gap-3 mb-4">
        <select value={sev} onChange={(e) => { setSev(e.target.value as Severity | "ALL"); setPage(0); }} className={selectCls}>
          <option value="ALL">All severities</option>
          {SEVS.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select value={tc} onChange={(e) => { setTc(e.target.value); setPage(0); }} className={selectCls}>
          <option value="ALL">All threat classes</option>
          {threatClasses.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <div className="flex items-center gap-2 bg-black/40 border border-border rounded-lg px-3">
          <Search className="w-3.5 h-3.5 text-muted-foreground" />
          <input
            value={q}
            onChange={(e) => { setQ(e.target.value); setPage(0); }}
            placeholder="Search attacker IP"
            className="bg-transparent py-2 text-xs font-mono outline-none w-40"
          />
        </div>
        <button onClick={exportCsv} className="ml-auto flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-semibold rainbow-bg text-white">
          <Download className="w-3.5 h-3.5" /> Export CSV
        </button>
      </div>

      <div className="glass-panel rounded-xl overflow-hidden">
        <div className="grid grid-cols-[150px_90px_1fr_130px_90px_90px_70px] gap-3 px-4 py-3 border-b border-border/50 text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">
          <span>Timestamp</span><span>Severity</span><span>Threat / Summary</span><span>Attacker IP</span><span>MITRE</span><span>Action</span><span>Conf.</span>
        </div>
        <div>
          {view.map((inc) => (
            <div key={inc.id} className="border-b border-white/5 last:border-0">
              <button
                onClick={() => setOpen(open === inc.id ? null : inc.id)}
                className="w-full grid grid-cols-[150px_90px_1fr_130px_90px_90px_70px] gap-3 px-4 py-3 text-left items-center hover:bg-white/[0.03] transition-colors relative group"
              >
                <span className="absolute left-0 top-0 bottom-0 w-[2px] opacity-0 group-hover:opacity-100 rainbow-bg transition-opacity" />
                <span className="text-[11px] font-mono text-muted-foreground">{fmtDateTime(inc.timestamp)}</span>
                <SeverityBadge severity={inc.severity} />
                <span className="text-xs truncate">{inc.threatClass}</span>
                <span className="text-[11px] font-mono text-[#9D4EDD]">{inc.attackerIp}</span>
                <span className="text-[11px] font-mono text-muted-foreground">{inc.mitreTechnique}</span>
                <span className="text-[11px] font-mono">{inc.actionTaken}</span>
                <span className="text-[11px] font-mono flex items-center gap-1">
                  {inc.confidenceScore}%
                  <ChevronDown className={`w-3 h-3 transition-transform ${open === inc.id ? "rotate-180" : ""}`} />
                </span>
              </button>
              <AnimatePresence>
                {open === inc.id && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    className="overflow-hidden bg-black/30"
                  >
                    <div className="px-6 py-4 grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
                      <Detail label="Incident ID" value={inc.id} />
                      <Detail label="MITRE Technique" value={`${inc.mitreTechnique} · ${inc.mitreTechniqueName}`} />
                      <Detail label="Tactic" value={inc.mitreTactic} />
                      <Detail label="Decided by" value={`${inc.model} (${inc.latencyMs}ms)`} />
                      <div className="col-span-2 md:col-span-4">
                        <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">Summary</div>
                        <div className="text-muted-foreground">{inc.summary}</div>
                      </div>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          ))}
          {view.length === 0 && <div className="py-12 text-center text-sm text-muted-foreground font-mono">No incidents match these filters.</div>}
        </div>
      </div>

      <div className="flex items-center justify-between mt-4 text-xs font-mono text-muted-foreground">
        <span>Page {cur + 1} of {pages}</span>
        <div className="flex gap-2">
          <button onClick={() => setPage(Math.max(0, cur - 1))} disabled={cur === 0} className="px-3 py-1.5 rounded-lg border border-border disabled:opacity-30 hover:bg-white/5">Prev</button>
          <button onClick={() => setPage(Math.min(pages - 1, cur + 1))} disabled={cur >= pages - 1} className="px-3 py-1.5 rounded-lg border border-border disabled:opacity-30 hover:bg-white/5">Next</button>
        </div>
      </div>
    </div>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">{label}</div>
      <div className="font-mono">{value}</div>
    </div>
  );
}
