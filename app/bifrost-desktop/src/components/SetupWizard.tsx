import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Check, Loader2, ArrowRight, ArrowLeft, Wifi, WifiOff } from "lucide-react";
import { BifrostLogo } from "./BifrostLogo";
import { LegalPanel } from "./Legal";
import { setPassword, setLegalAccepted, setSetupComplete } from "@/lib/app-state";
import { getSettings, saveSettings, baseUrl } from "@/lib/api";
import { guardianFetch } from "@/lib/guardianFetch";
import { passwordStrength } from "@/lib/app-state";

function BridgeArt() {
  return (
    <svg className="w-72 h-28" viewBox="0 0 400 120">
      <defs>
        <linearGradient id="wzb" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor="#7B2FBE" />
          <stop offset="50%" stopColor="#E040FB" />
          <stop offset="100%" stopColor="#F48FB1" />
        </linearGradient>
      </defs>
      <motion.path
        d="M 0 110 Q 200 -10 400 110"
        stroke="url(#wzb)"
        strokeWidth="5"
        fill="none"
        strokeLinecap="round"
        initial={{ pathLength: 0 }}
        animate={{ pathLength: 1 }}
        transition={{ duration: 1.6, ease: "easeInOut" }}
        style={{ filter: "drop-shadow(0 0 12px rgba(224,64,251,0.6))" }}
      />
    </svg>
  );
}

const STEPS = ["Welcome", "Legal", "Password", "Paths", "Connection", "Ready"];

export function SetupWizard({ onComplete }: { onComplete: () => void }) {
  const [step, setStep] = useState(0);
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const s0 = getSettings();
  const [cowrie, setCowrie] = useState("/opt/cowrie/var/log/cowrie/cowrie.json");
  const [dbPath, setDbPath] = useState("/var/lib/bifrost/guardian.db");
  const [host, setHost] = useState(s0.guardianHost);
  const [port, setPort] = useState(s0.dashboardPort);
  const [testState, setTestState] = useState<"idle" | "testing" | "ok" | "fail">("idle");

  const strength = passwordStrength(pw);
  const pwValid = pw.length >= 4 && pw === pw2;

  const next = () => setStep((s) => Math.min(STEPS.length - 1, s + 1));
  const back = () => setStep((s) => Math.max(0, s - 1));

  const runTest = async () => {
    setTestState("testing");
    saveSettings({ guardianHost: host, dashboardPort: port });
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 2500);
      const res = await guardianFetch(
        `${baseUrl({ ...s0, guardianHost: host, dashboardPort: port })}/api/state`,
        { signal: ctrl.signal, credentials: "include" },
      );
      clearTimeout(t);
      setTestState(res.ok ? "ok" : "fail");
    } catch {
      setTestState("fail");
    }
  };

  const finish = async () => {
    await setPassword(pw);
    setLegalAccepted(true);
    saveSettings({ guardianHost: host, dashboardPort: port });
    localStorage.setItem("bifrost.paths", JSON.stringify({ cowrie, dbPath }));
    setSetupComplete(true);
    onComplete();
  };

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-[#060606] overflow-hidden p-6">
      <div className="absolute inset-0 pointer-events-none opacity-20">
        <div className="absolute top-1/4 left-1/4 w-1/2 h-1/2 bg-[#7B2FBE] blur-[160px]" />
        <div className="absolute bottom-1/4 right-1/4 w-1/2 h-1/2 bg-[#E040FB] blur-[160px]" />
      </div>

      <div className="relative z-10 w-full max-w-2xl h-[600px] glass-panel rounded-2xl p-8 flex flex-col">
        {/* progress */}
        <div className="flex items-center gap-2 mb-6">
          {STEPS.map((label, i) => (
            <div key={label} className="flex items-center gap-2 flex-1">
              <div
                className={`h-1.5 flex-1 rounded-full transition-all ${i <= step ? "rainbow-bg" : "bg-white/10"}`}
              />
            </div>
          ))}
        </div>
        <div className="text-[10px] tracking-[0.2em] text-muted-foreground mb-4">
          STEP {step + 1} / {STEPS.length} · {STEPS[step].toUpperCase()}
        </div>

        <div className="flex-1 min-h-0">
          <AnimatePresence mode="wait">
            <motion.div
              key={step}
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              transition={{ duration: 0.25 }}
              className="h-full"
            >
              {step === 0 && (
                <div className="h-full flex flex-col items-center justify-center text-center">
                  <BridgeArt />
                  <BifrostLogo className="w-16 h-16 -mt-6 float-soft" />
                  <h2 className="text-3xl font-extrabold tracking-[0.15em] rainbow-text mt-4">BIFROST</h2>
                  <p className="text-sm text-muted-foreground mt-3 font-mono">The Bridge Is Watched.</p>
                  <p className="text-xs text-muted-foreground/70 mt-6 max-w-md">
                    Welcome, Heimdall. Let's prepare your watch over the rainbow bridge. This takes about a minute.
                  </p>
                </div>
              )}

              {step === 1 && <LegalPanel onAccept={next} />}

              {step === 2 && (
                <div className="h-full flex flex-col justify-center max-w-md mx-auto w-full">
                  <h2 className="text-xl font-bold mb-6">Set your dashboard password</h2>
                  <label className="text-xs text-muted-foreground mb-1">Password</label>
                  <input
                    type="password"
                    value={pw}
                    onChange={(e) => setPw(e.target.value)}
                    className="bg-black/40 border border-border rounded-lg px-3 py-2.5 text-sm font-mono outline-none focus:border-[#E040FB] mb-3"
                  />
                  <div className="flex gap-1 mb-1">
                    {[0, 1, 2, 3].map((i) => (
                      <div
                        key={i}
                        className="h-1 flex-1 rounded-full"
                        style={{
                          background:
                            i < strength.score
                              ? ["#FF2D2D", "#FF6B35", "#FFD166", "#4ECDC4"][strength.score - 1]
                              : "rgba(255,255,255,0.1)",
                        }}
                      />
                    ))}
                  </div>
                  <div className="text-[10px] text-muted-foreground mb-4 font-mono">{pw && strength.label}</div>
                  <label className="text-xs text-muted-foreground mb-1">Confirm password</label>
                  <input
                    type="password"
                    value={pw2}
                    onChange={(e) => setPw2(e.target.value)}
                    className="bg-black/40 border border-border rounded-lg px-3 py-2.5 text-sm font-mono outline-none focus:border-[#E040FB]"
                  />
                  {pw2 && pw !== pw2 && <div className="text-[10px] text-[#FF2D2D] mt-1">Passwords do not match.</div>}
                </div>
              )}

              {step === 3 && (
                <div className="h-full flex flex-col justify-center max-w-md mx-auto w-full">
                  <h2 className="text-xl font-bold mb-6">Configure paths</h2>
                  <label className="text-xs text-muted-foreground mb-1">Cowrie honeypot log</label>
                  <input
                    value={cowrie}
                    onChange={(e) => setCowrie(e.target.value)}
                    className="bg-black/40 border border-border rounded-lg px-3 py-2.5 text-sm font-mono outline-none focus:border-[#E040FB] mb-4"
                  />
                  <label className="text-xs text-muted-foreground mb-1">Guardian database</label>
                  <input
                    value={dbPath}
                    onChange={(e) => setDbPath(e.target.value)}
                    className="bg-black/40 border border-border rounded-lg px-3 py-2.5 text-sm font-mono outline-none focus:border-[#E040FB]"
                  />
                  <p className="text-[10px] text-muted-foreground/60 mt-4">
                    In the desktop build a native file picker is available; paths can be edited later in Settings.
                  </p>
                </div>
              )}

              {step === 4 && (
                <div className="h-full flex flex-col justify-center max-w-md mx-auto w-full">
                  <h2 className="text-xl font-bold mb-6">Test guardian connection</h2>
                  <div className="flex gap-3 mb-4">
                    <input
                      value={host}
                      onChange={(e) => setHost(e.target.value)}
                      className="flex-1 bg-black/40 border border-border rounded-lg px-3 py-2.5 text-sm font-mono outline-none focus:border-[#E040FB]"
                    />
                    <input
                      type="number"
                      value={port}
                      onChange={(e) => setPort(Number(e.target.value))}
                      className="w-28 bg-black/40 border border-border rounded-lg px-3 py-2.5 text-sm font-mono outline-none focus:border-[#E040FB]"
                    />
                  </div>
                  <button
                    onClick={runTest}
                    disabled={testState === "testing"}
                    className="rounded-lg py-2.5 text-sm font-semibold rainbow-bg text-white"
                  >
                    {testState === "testing" ? "Testing…" : "Test connection"}
                  </button>
                  <div className="mt-4 text-sm font-mono flex items-center gap-2">
                    {testState === "testing" && <Loader2 className="w-4 h-4 animate-spin" />}
                    {testState === "ok" && (
                      <span className="text-[#4ECDC4] flex items-center gap-2">
                        <Wifi className="w-4 h-4" /> Guardian reachable
                      </span>
                    )}
                    {testState === "fail" && (
                      <span className="text-[#FF6B35] flex items-center gap-2">
                        <WifiOff className="w-4 h-4" /> Could not reach guardian — you can configure this later.
                      </span>
                    )}
                  </div>
                </div>
              )}

              {step === 5 && (
                <div className="h-full flex flex-col items-center justify-center text-center">
                  <BridgeArt />
                  <BifrostLogo className="w-16 h-16 -mt-6 float-soft" />
                  <h2 className="text-2xl font-extrabold rainbow-text mt-4">Heimdall is Online</h2>
                  <p className="text-sm text-muted-foreground mt-3 font-mono">The Bridge Is Watched.</p>
                </div>
              )}
            </motion.div>
          </AnimatePresence>
        </div>

        {/* nav */}
        <div className="flex items-center justify-between mt-6 pt-4 border-t border-border/40">
          <button
            onClick={back}
            disabled={step === 0}
            className="flex items-center gap-1 text-sm text-muted-foreground disabled:opacity-30 hover:text-foreground"
          >
            <ArrowLeft className="w-4 h-4" /> Back
          </button>
          {step === 5 ? (
            <button onClick={finish} className="flex items-center gap-2 rounded-xl px-6 py-2.5 text-sm font-bold rainbow-bg text-white">
              Launch Bifrost <ArrowRight className="w-4 h-4" />
            </button>
          ) : step === 1 ? (
            <div className="text-[10px] text-muted-foreground">Accept to continue</div>
          ) : (
            <button
              onClick={next}
              disabled={step === 2 && !pwValid}
              className="flex items-center gap-2 rounded-xl px-6 py-2.5 text-sm font-bold rainbow-bg text-white disabled:opacity-40"
            >
              {step === 4 && testState === "idle" ? "Skip / Continue" : "Continue"} <ArrowRight className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
