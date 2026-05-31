import { useRef, useState } from "react";
import { BifrostLogo } from "./BifrostLogo";

const SECTIONS: { h: string; b: string }[] = [
  {
    h: "1. Authorized Use Only",
    b: "Bifrost is an autonomous intrusion-detection and active-defense system intended exclusively for use on infrastructure you own or are explicitly authorized to defend. You are solely responsible for ensuring that your deployment complies with all applicable laws and regulations in your jurisdiction.",
  },
  {
    h: "2. Research, Lab & Honeypot Environments",
    b: "This software is designed for research, laboratory, and honeypot environments. Bifrost ingests and analyzes adversary activity captured by deception infrastructure (such as Cowrie). Do not deploy Bifrost on production systems carrying real user traffic without a thorough review of its autonomous response behavior.",
  },
  {
    h: "3. Autonomous Actions Warning",
    b: "When Autonomous Mode is enabled, Bifrost may take active defensive actions — including blocking, isolating, throttling, and tarpitting connections — without human approval. These actions are driven by AI model decisions and confidence thresholds. You accept full responsibility for any action taken on your behalf. Use Dry Run mode to observe decisions without enforcement.",
  },
  {
    h: "4. Data Handling",
    b: "Bifrost stores captured session data, attacker fingerprints, attempted credentials, and command transcripts in a local database. Attempted credentials are redacted in the interface. You are responsible for the secure storage, retention, and disposal of all collected data in accordance with your privacy obligations.",
  },
  {
    h: "5. No Warranty",
    b: "This software is provided \"as is\", without warranty of any kind, express or implied. In no event shall the authors be liable for any claim, damages, or other liability arising from the use of this software. Detection is probabilistic and may produce false positives and false negatives.",
  },
  {
    h: "6. Acknowledgement",
    b: "By accepting this disclaimer you confirm that you understand the autonomous nature of this system, that you are authorized to deploy it on the target environment, and that you accept all associated risk.",
  },
];

export function LegalPanel({ onAccept }: { onAccept?: () => void }) {
  const [atBottom, setAtBottom] = useState(false);
  const [progress, setProgress] = useState(0);
  const ref = useRef<HTMLDivElement>(null);

  const onScroll = () => {
    const el = ref.current;
    if (!el) return;
    const max = el.scrollHeight - el.clientHeight;
    const p = max > 0 ? el.scrollTop / max : 1;
    setProgress(p);
    if (p > 0.98) setAtBottom(true);
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-3 mb-4">
        <BifrostLogo className="w-10 h-10 float-soft" />
        <div>
          <h2 className="text-xl font-bold">Legal Disclaimer</h2>
          <p className="text-xs text-muted-foreground">Please read fully before continuing.</p>
        </div>
      </div>

      <div className="flex-1 flex gap-3 min-h-0">
        <div ref={ref} onScroll={onScroll} className="flex-1 overflow-auto scroll-thin pr-4 glass-panel rounded-xl p-6">
          {SECTIONS.map((s) => (
            <div key={s.h} className="mb-6">
              <h3 className="text-sm font-semibold text-foreground mb-2">{s.h}</h3>
              <p className="text-sm text-muted-foreground leading-relaxed">{s.b}</p>
            </div>
          ))}
          <p className="text-xs text-muted-foreground/60 font-mono mt-8">— End of disclaimer —</p>
        </div>
        <div className="w-1.5 rounded-full bg-white/5 overflow-hidden">
          <div
            className="w-full rounded-full rainbow-bg transition-all"
            style={{ height: `${Math.round(progress * 100)}%` }}
          />
        </div>
      </div>

      {onAccept && (
        <button
          disabled={!atBottom}
          onClick={onAccept}
          className={`mt-5 w-full rounded-xl py-3 text-sm font-bold transition-all ${
            atBottom ? "rainbow-bg text-white shadow-lg" : "bg-white/5 text-muted-foreground cursor-not-allowed"
          }`}
        >
          {atBottom ? "I Understand and Accept" : "Scroll to the bottom to accept"}
        </button>
      )}
    </div>
  );
}
