import { useState } from "react";
import { ShieldCheck, KeyRound, RotateCcw, Server, MonitorCog, Cpu } from "lucide-react";
import { useGuardian, useSettings, saveSettings, guardian } from "@/lib/api";
import { PageHeader, Toggle } from "@/components/shared";
import { setPassword, setSetupComplete, passwordStrength } from "@/lib/app-state";

function Card({ icon, title, children }: { icon: React.ReactNode; title: string; children: React.ReactNode }) {
  return (
    <div className="glass-panel rounded-xl p-5">
      <div className="flex items-center gap-2 mb-4">
        <span className="text-[#E040FB]">{icon}</span>
        <h3 className="font-semibold">{title}</h3>
      </div>
      {children}
    </div>
  );
}

const inputCls = "bg-black/40 border border-border rounded-lg px-3 py-2 text-sm font-mono outline-none focus:border-[#E040FB] w-full";

export default function Settings() {
  const { config } = useGuardian();
  const s = useSettings();
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [pwMsg, setPwMsg] = useState("");

  const changePw = async () => {
    if (pw.length < 4 || pw !== pw2) {
      setPwMsg("Passwords must match and be at least 4 characters.");
      return;
    }
    await setPassword(pw);
    setPw("");
    setPw2("");
    setPwMsg("Password updated.");
  };

  const strength = passwordStrength(pw);

  return (
    <div>
      <PageHeader title="Settings" desc="Tune the guardian and the dashboard" />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card icon={<ShieldCheck className="w-4 h-4" />} title="Guardian Behavior">
          <div className="space-y-4">
            <Toggle checked={config.learningMode} onChange={(v) => guardian.patchConfig({ learningMode: v })} label="Learning Mode" accent="#9D4EDD" />
            <Toggle checked={config.dryRun} onChange={(v) => guardian.patchConfig({ dryRun: v })} label="Dry Run (observe, do not enforce)" accent="#FFD166" />
            <Toggle checked={config.autonomous} onChange={(v) => guardian.patchConfig({ autonomous: v })} label="Autonomous Mode" accent="#E040FB" />
            <div>
              <div className="flex items-center justify-between text-xs mb-2">
                <span className="text-muted-foreground">Confidence threshold</span>
                <span className="font-mono">{config.confidenceThreshold}%</span>
              </div>
              <input
                type="range" min={50} max={99} value={config.confidenceThreshold}
                onChange={(e) => guardian.patchConfig({ confidenceThreshold: Number(e.target.value) })}
                className="w-full accent-[#E040FB]"
              />
            </div>
            {config.autonomous && !config.dryRun && (
              <div className="text-[11px] text-[#FF6B35] font-mono">⚠ Autonomous enforcement is active. Actions are taken without approval.</div>
            )}
          </div>
        </Card>

        <Card icon={<Server className="w-4 h-4" />} title="Guardian Connection">
          <div className="space-y-3">
            <div>
              <label className="text-xs text-muted-foreground">Host</label>
              <input value={s.guardianHost} onChange={(e) => saveSettings({ guardianHost: e.target.value })} className={inputCls} />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs text-muted-foreground">Dashboard port</label>
                <input type="number" value={s.dashboardPort} onChange={(e) => saveSettings({ dashboardPort: Number(e.target.value) })} className={inputCls} />
              </div>
              <div>
                <label className="text-xs text-muted-foreground">Ingest port</label>
                <input type="number" value={s.ingestPort} onChange={(e) => saveSettings({ ingestPort: Number(e.target.value) })} className={inputCls} />
              </div>
            </div>
            <div>
              <label className="text-xs text-muted-foreground">Refresh interval (ms)</label>
              <input type="number" value={s.refreshIntervalMs} onChange={(e) => saveSettings({ refreshIntervalMs: Number(e.target.value) })} className={inputCls} />
            </div>
          </div>
        </Card>

        <Card icon={<MonitorCog className="w-4 h-4" />} title="Dashboard Preferences">
          <div className="space-y-4">
            <div>
              <div className="flex items-center justify-between text-xs mb-2">
                <span className="text-muted-foreground">Screensaver timeout (minutes)</span>
                <span className="font-mono">{Math.round(s.screensaverMs / 60000)}</span>
              </div>
              <input type="range" min={1} max={30} value={Math.round(s.screensaverMs / 60000)}
                onChange={(e) => saveSettings({ screensaverMs: Number(e.target.value) * 60000 })} className="w-full accent-[#E040FB]" />
            </div>
            <div>
              <div className="flex items-center justify-between text-xs mb-2">
                <span className="text-muted-foreground">Session timeout (minutes)</span>
                <span className="font-mono">{s.sessionTimeoutMin}</span>
              </div>
              <input type="range" min={5} max={120} step={5} value={s.sessionTimeoutMin}
                onChange={(e) => saveSettings({ sessionTimeoutMin: Number(e.target.value) })} className="w-full accent-[#E040FB]" />
            </div>
            <Toggle checked={s.desktopNotifications} onChange={(v) => saveSettings({ desktopNotifications: v })} label="Desktop notifications" accent="#4ECDC4" />
          </div>
        </Card>

        <Card icon={<KeyRound className="w-4 h-4" />} title="Security">
          <div className="space-y-3">
            <input type="password" placeholder="New password" value={pw} onChange={(e) => { setPw(e.target.value); setPwMsg(""); }} className={inputCls} />
            {pw && (
              <div className="flex gap-1">
                {[0, 1, 2, 3].map((i) => (
                  <div key={i} className="h-1 flex-1 rounded-full" style={{ background: i < strength.score ? ["#FF2D2D", "#FF6B35", "#FFD166", "#4ECDC4"][strength.score - 1] : "rgba(255,255,255,0.1)" }} />
                ))}
              </div>
            )}
            <input type="password" placeholder="Confirm password" value={pw2} onChange={(e) => { setPw2(e.target.value); setPwMsg(""); }} className={inputCls} />
            <button onClick={changePw} className="rounded-lg py-2 text-sm font-semibold rainbow-bg text-white w-full">Update password</button>
            {pwMsg && <div className="text-[11px] font-mono text-muted-foreground">{pwMsg}</div>}

            <div className="pt-3 border-t border-border/40">
              <button
                onClick={() => { setSetupComplete(false); location.reload(); }}
                className="flex items-center gap-2 text-xs text-[#FF6B35] hover:text-[#FF2D2D]"
              >
                <RotateCcw className="w-3.5 h-3.5" /> Re-run setup wizard
              </button>
            </div>
          </div>
        </Card>

        <Card icon={<Cpu className="w-4 h-4" />} title="System">
          <div className="grid grid-cols-2 gap-3 text-xs font-mono">
            <Info k="Hardware tier" v={config.hardwareTier} />
            <Info k="Models loaded" v={String(config.modelsLoaded.length)} />
            <Info k="Database" v={config.databasePath} />
            <Info k="Cowrie log" v={config.cowrieLogPath} />
            <Info k="Ingest token" v={config.tokens.ingest ? "set" : "unset"} />
            <Info k="Dashboard token" v={config.tokens.dashboard ? "set" : "unset"} />
          </div>
        </Card>
      </div>
    </div>
  );
}

function Info({ k, v }: { k: string; v: string }) {
  return (
    <div className="min-w-0">
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{k}</div>
      <div className="truncate text-foreground/90" title={v}>{v}</div>
    </div>
  );
}
