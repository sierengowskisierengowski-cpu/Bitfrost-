import { useEffect } from "react";
import { motion } from "framer-motion";
import { BifrostLogo } from "./BifrostLogo";
import { useGuardian } from "@/lib/api";
import { fmtNum } from "@/lib/format";

export function Screensaver({ onWake }: { onWake: () => void }) {
  const { counters, attackers } = useGuardian();

  useEffect(() => {
    const wake = () => onWake();
    window.addEventListener("mousemove", wake);
    window.addEventListener("mousedown", wake);
    window.addEventListener("keydown", wake);
    window.addEventListener("touchstart", wake);
    return () => {
      window.removeEventListener("mousemove", wake);
      window.removeEventListener("mousedown", wake);
      window.removeEventListener("keydown", wake);
      window.removeEventListener("touchstart", wake);
    };
  }, [onWake]);

  const stats = [
    { label: "ATTACKS TODAY", value: fmtNum(counters.processedToday) },
    { label: "ACTIVE ATTACKERS", value: fmtNum(counters.activeAttackers) },
    { label: "EVENTS / MIN", value: fmtNum(counters.eventsPerMin) },
    { label: "TRACKED ADVERSARIES", value: fmtNum(attackers.length) },
  ];

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-[60] flex flex-col items-center justify-center select-none cursor-none"
    >
      <div className="aurora" />
      <div className="relative z-10 flex flex-col items-center">
        <BifrostLogo className="w-20 h-20 float-soft" />
        <div className="text-3xl font-extrabold tracking-[0.3em] rainbow-text mt-6">BIFROST</div>
        <div className="text-xs text-muted-foreground font-mono mt-2 tracking-wide">Heimdall is watching</div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-8 mt-16">
          {stats.map((s, i) => (
            <motion.div
              key={s.label}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: [0.4, 1, 0.4], y: 0 }}
              transition={{ opacity: { duration: 4, repeat: Infinity, delay: i * 0.5 }, y: { duration: 0.6 } }}
              className="text-center"
            >
              <div className="text-4xl font-bold font-mono text-white/90">{s.value}</div>
              <div className="text-[10px] tracking-[0.2em] text-muted-foreground mt-2">{s.label}</div>
            </motion.div>
          ))}
        </div>

        <div className="absolute -bottom-32 text-[11px] text-muted-foreground/60 font-mono">
          Move the mouse or press any key to return
        </div>
      </div>
    </motion.div>
  );
}
