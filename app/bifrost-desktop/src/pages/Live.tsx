import { useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Pause, Play, Radio } from "lucide-react";
import { useLiveEvents, useConnection } from "@/lib/api";
import type { Severity } from "@/lib/types";
import { PageHeader, SeverityBadge } from "@/components/shared";
import { fmtTime } from "@/lib/format";

const SEVS: (Severity | "ALL")[] = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export default function Live() {
  const events = useLiveEvents();
  const conn = useConnection();
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState<Severity | "ALL">("ALL");
  const [frozen, setFrozen] = useState(events);

  useEffect(() => {
    if (!paused) setFrozen(events);
  }, [events, paused]);

  const shown = useMemo(
    () => (filter === "ALL" ? frozen : frozen.filter((e) => e.severity === filter)),
    [frozen, filter]
  );

  const latestId = useRef<string | null>(null);
  const isNew = (id: string) => {
    if (paused) return false;
    return shown.length > 0 && shown[0].id === id && id !== latestId.current;
  };
  useEffect(() => {
    if (shown.length) latestId.current = shown[0].id;
  }, [shown]);

  return (
    <div className="flex flex-col h-[calc(100vh-120px)]">
      <PageHeader
        title="Live Monitor"
        desc="Real-time decision stream from the guardian"
        right={
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-2 text-xs font-mono">
              <Radio className={`w-4 h-4 ${conn.status === "connected" ? "text-[#4ECDC4]" : "text-[#FF6B35]"} ${paused ? "" : "animate-pulse"}`} />
              {paused ? "Paused" : "Streaming"} · {conn.source}
            </span>
            <div className="inline-flex rounded-lg border border-border/60 bg-black/30 p-1 gap-1">
              {SEVS.map((s) => (
                <button
                  key={s}
                  onClick={() => setFilter(s)}
                  className={`px-2.5 py-1 rounded-md text-[10px] font-mono font-semibold transition-all ${
                    filter === s ? "rainbow-bg text-white" : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {s}
                </button>
              ))}
            </div>
            <button onClick={() => setPaused((p) => !p)} className="flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-semibold border border-border hover:bg-white/5">
              {paused ? <><Play className="w-3.5 h-3.5" /> Resume</> : <><Pause className="w-3.5 h-3.5" /> Pause</>}
            </button>
          </div>
        }
      />

      <div className="glass-panel rounded-xl flex-1 overflow-hidden flex flex-col">
        <div className="grid grid-cols-[90px_130px_1fr_120px_90px_70px] gap-3 px-4 py-2.5 border-b border-border/50 text-[10px] uppercase tracking-wider text-muted-foreground font-semibold shrink-0">
          <span>Time</span><span>Attacker</span><span>Command</span><span>Decision</span><span>Severity</span><span>Conf.</span>
        </div>
        <div className="flex-1 overflow-auto scroll-thin">
          <AnimatePresence initial={false}>
            {shown.map((e) => (
              <motion.div
                key={e.id}
                initial={isNew(e.id) ? { opacity: 0, backgroundColor: "rgba(224,64,251,0.18)" } : false}
                animate={{ opacity: 1, backgroundColor: "rgba(0,0,0,0)" }}
                transition={{ duration: 0.9 }}
                className="grid grid-cols-[90px_130px_1fr_120px_90px_70px] gap-3 px-4 py-2.5 items-center border-b border-white/5 text-xs hover:bg-white/[0.02]"
              >
                <span className="font-mono text-muted-foreground text-[11px]">{fmtTime(e.timestamp)}</span>
                <span className="font-mono text-[#9D4EDD] text-[11px] truncate">{e.attackerIp}</span>
                <span className="font-mono text-foreground/90 truncate" title={e.commandRun}>{e.commandRun}</span>
                <span className="font-mono text-[11px]">{e.decision}</span>
                <SeverityBadge severity={e.severity} />
                <span className="font-mono text-[11px]">{e.confidence}%</span>
              </motion.div>
            ))}
          </AnimatePresence>
          {shown.length === 0 && <div className="py-16 text-center text-sm text-muted-foreground font-mono">Awaiting events…</div>}
        </div>
      </div>
    </div>
  );
}
