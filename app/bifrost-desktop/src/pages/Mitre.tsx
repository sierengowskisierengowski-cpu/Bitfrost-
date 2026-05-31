import { useMemo } from "react";
import { useGuardian, buildMitre } from "@/lib/api";
import { PageHeader } from "@/components/shared";
import { fmtNum } from "@/lib/format";

function heat(count: number, max: number): { bg: string; fg: string } {
  if (count === 0) return { bg: "rgba(255,255,255,0.03)", fg: "#555" };
  const t = max ? count / max : 0;
  const stops = ["#2A1B3D", "#5A2A8C", "#7B2FBE", "#9D4EDD", "#C4607A", "#E040FB", "#E91E8C"];
  const idx = Math.min(stops.length - 1, Math.floor(t * (stops.length - 1)));
  return { bg: stops[idx], fg: t > 0.35 ? "#fff" : "#ddd" };
}

export default function Mitre() {
  const { incidents } = useGuardian();
  const tactics = useMemo(() => buildMitre(incidents), [incidents]);
  const max = useMemo(
    () => Math.max(1, ...tactics.flatMap((t) => t.techniques.map((x) => x.count))),
    [tactics]
  );
  const totalTechniques = tactics.reduce((s, t) => s + t.techniques.length, 0);

  return (
    <div>
      <PageHeader
        title="MITRE ATT&CK"
        desc={`${tactics.length} tactics · ${totalTechniques} techniques observed`}
      />

      <div className="flex items-center gap-2 mb-5 text-[10px] font-mono text-muted-foreground">
        <span>Less</span>
        <div className="flex gap-1">
          {["#2A1B3D", "#5A2A8C", "#7B2FBE", "#9D4EDD", "#C4607A", "#E040FB", "#E91E8C"].map((c) => (
            <span key={c} className="w-4 h-4 rounded" style={{ background: c }} />
          ))}
        </div>
        <span>More</span>
      </div>

      <div className="flex gap-3 overflow-x-auto scroll-thin pb-4">
        {tactics.map((t) => {
          const sum = t.techniques.reduce((s, x) => s + x.count, 0);
          return (
            <div key={t.id} className="w-56 shrink-0">
              <div className="glass-panel rounded-t-lg px-3 py-2.5 border-b-2 border-[#E040FB]/40">
                <div className="text-xs font-semibold truncate">{t.name}</div>
                <div className="flex items-center justify-between text-[10px] font-mono text-muted-foreground mt-0.5">
                  <span>{t.id}</span>
                  <span>{fmtNum(sum)}</span>
                </div>
              </div>
              <div className="space-y-1.5 mt-1.5">
                {t.techniques.map((x) => {
                  const c = heat(x.count, max);
                  return (
                    <div
                      key={x.id}
                      className="rounded-md px-2.5 py-2 transition-transform hover:scale-[1.02] cursor-default"
                      style={{ background: c.bg, color: c.fg }}
                      title={`${x.id} ${x.name} — ${x.count} incidents`}
                    >
                      <div className="text-[11px] font-medium truncate">{x.name}</div>
                      <div className="flex items-center justify-between text-[9px] font-mono opacity-80">
                        <span>{x.id}</span>
                        <span>{fmtNum(x.count)}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
