import { Link, useLocation } from "wouter";
import type { ReactNode } from "react";
import { motion } from "framer-motion";
import {
  LayoutDashboard, ShieldAlert, Crosshair, Radio, Activity,
  Grid3x3, Settings as SettingsIcon, ScrollText, Minus, Square, X,
} from "lucide-react";
import { BifrostLogo } from "./BifrostLogo";
import { useGuardian, useConnection } from "@/lib/api";
import { fmtUptime } from "@/lib/format";
import { isTauri, minimizeWindow, toggleMaximize, closeWindow } from "@/lib/tauri";

const NAV = [
  { path: "/overview", label: "Overview", icon: LayoutDashboard },
  { path: "/incidents", label: "Incidents", icon: ShieldAlert },
  { path: "/attackers", label: "Attackers", icon: Crosshair },
  { path: "/live", label: "Live Monitor", icon: Radio },
  { path: "/timeline", label: "Timeline", icon: Activity },
  { path: "/mitre", label: "MITRE ATT&CK", icon: Grid3x3 },
  { path: "/settings", label: "Settings", icon: SettingsIcon },
  { path: "/legal", label: "Legal", icon: ScrollText },
];

function ConnectionStatus() {
  const conn = useConnection();
  const ok = conn.status === "connected";
  return (
    <div className="flex items-center gap-2 text-xs font-mono no-drag">
      <span
        className="w-2 h-2 rounded-full"
        style={{
          background: ok ? "#4ECDC4" : "#FF2D2D",
          boxShadow: `0 0 8px ${ok ? "#4ECDC4" : "#FF2D2D"}`,
        }}
      />
      {ok ? (
        <span className="text-[#4ECDC4]">Connected</span>
      ) : (
        <span className="text-[#FF6B35]">
          Disconnected{conn.retryInSec > 0 ? ` · retry ${conn.retryInSec}s` : ""}
        </span>
      )}
    </div>
  );
}

function StatusBar() {
  const { aiModel, hardware } = useGuardian();
  return (
    <div className="hidden lg:flex items-center gap-4 text-[11px] font-mono text-muted-foreground no-drag">
      <span className="text-foreground/80">{aiModel.model}</span>
      <span className="text-white/20">|</span>
      <span>{hardware.tier}</span>
      <span className="text-white/20">|</span>
      <span>RAM {hardware.ramUsed.toFixed(1)}/{hardware.ramTotal}GB</span>
      <span className="text-white/20">|</span>
      <span>CPU {Math.round(hardware.cpuPercent)}%</span>
      <span className="text-white/20">|</span>
      <span>up {fmtUptime(hardware.uptimeSec)}</span>
    </div>
  );
}

function WindowControls() {
  if (!isTauri()) return null;
  return (
    <div className="flex items-center gap-1 no-drag ml-2">
      <button onClick={minimizeWindow} className="p-1.5 rounded hover:bg-white/10 transition-colors" aria-label="Minimize">
        <Minus className="w-3.5 h-3.5" />
      </button>
      <button onClick={toggleMaximize} className="p-1.5 rounded hover:bg-white/10 transition-colors" aria-label="Maximize">
        <Square className="w-3 h-3" />
      </button>
      <button onClick={closeWindow} className="p-1.5 rounded hover:bg-[#FF2D2D]/80 transition-colors" aria-label="Close">
        <X className="w-3.5 h-3.5" />
      </button>
    </div>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const [location] = useLocation();
  const active = (p: string) => location === p || (p === "/overview" && (location === "/" || location === ""));

  return (
    <div className="h-screen w-full bg-background p-[2px] rainbow-border overflow-hidden">
      <div className="h-full w-full flex flex-col rounded-[10px] bg-background/95 overflow-hidden relative">
        {/* ambient aurora */}
        <div className="absolute inset-0 pointer-events-none opacity-[0.18]">
          <div className="absolute top-0 left-1/4 w-1/2 h-1/2 bg-[#7B2FBE] blur-[160px]" />
          <div className="absolute bottom-0 right-1/4 w-1/2 h-1/2 bg-[#E040FB] blur-[160px]" />
        </div>

        {/* title bar */}
        <header className="drag-region h-11 shrink-0 flex items-center justify-between px-4 border-b border-border/50 glass-panel z-20 group">
          <div className="flex items-center gap-2 no-drag">
            <BifrostLogo className="w-5 h-5 group-hover:rotate-3 transition-transform" />
            <span className="text-sm font-bold tracking-wide rainbow-text">BIFROST</span>
          </div>
          <div className="flex items-center gap-4">
            <StatusBar />
            <ConnectionStatus />
            <WindowControls />
          </div>
        </header>

        <div className="flex-1 flex overflow-hidden z-10">
          {/* sidebar */}
          <aside className="w-60 shrink-0 border-r border-border/50 bg-sidebar/60 glass-panel flex flex-col">
            <div className="px-5 py-5 border-b border-border/40 flex items-center gap-3">
              <BifrostLogo className="w-9 h-9 float-soft" />
              <div>
                <div className="font-extrabold tracking-wide leading-none">BIFROST</div>
                <div className="text-[10px] tracking-[0.25em] text-muted-foreground mt-1">RAINBOW BRIDGE</div>
              </div>
            </div>
            <nav className="flex-1 p-3 flex flex-col gap-1 overflow-auto scroll-thin">
              {NAV.map((n) => {
                const Icon = n.icon;
                const on = active(n.path);
                return (
                  <Link key={n.path} href={n.path}>
                    <div
                      className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm cursor-pointer transition-all ${
                        on ? "nav-active font-semibold" : "text-muted-foreground hover:text-foreground hover:bg-white/5"
                      }`}
                    >
                      <Icon className="w-4 h-4 shrink-0" />
                      {n.label}
                    </div>
                  </Link>
                );
              })}
            </nav>
            <div className="p-4 border-t border-border/40">
              <div className="text-[10px] text-muted-foreground font-mono leading-relaxed">
                The Bridge Is Watched.
                <br />
                Heimdall Never Sleeps.
              </div>
            </div>
          </aside>

          {/* content */}
          <motion.main
            key={location}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.25 }}
            className="flex-1 overflow-auto scroll-thin p-6"
          >
            {children}
          </motion.main>
        </div>
      </div>
    </div>
  );
}
