import { useEffect, useState } from "react";

export function ScanProgress({ stages }) {
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    const started = Date.now();
    const timer = setInterval(() => setElapsed(Math.floor((Date.now() - started) / 1000)), 1000);
    return () => clearInterval(timer);
  }, []);

  return <div className="mt-5 border-t border-leaf/25 pt-4">
    <div className="flex items-center justify-between gap-3 text-xs text-leaf">
      <span>Scan in progress</span>
      <span className="font-mono tabular-nums">{elapsed}s elapsed</span>
    </div>
    <div role="progressbar" aria-label="Scan in progress"
      className="mt-2 h-1.5 overflow-hidden rounded-full bg-leaf/15">
      <div className="scan-progress-fill h-full w-1/3 rounded-full bg-leaf" />
    </div>
    <div className="mt-4" role="status" aria-live="polite" aria-atomic="false">
      {!stages.length && <p className="text-sm text-leaf">Connecting to the scanner…</p>}
      <ul className="space-y-3">
        {stages.map((stage) => <li key={stage.stage} className="flex items-start gap-2.5" data-scan-stage={stage.stage} data-stage-status={stage.status}>
          <span aria-hidden="true" className={`mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center text-xs font-bold ${stage.status === "running" ? "text-ink" : "text-leaf"}`}>
            {stage.status === "running" ? <span className="writing-dot" /> : stage.status === "complete" ? "✓" : "—"}
          </span>
          <div className="min-w-0">
            <p className={`text-sm ${stage.status === "running" ? "font-semibold text-ink" : "text-leaf"}`}>
              {stage.label}<span className="sr-only">: {stage.status}</span>
              {stage.status === "unavailable" && <span aria-hidden="true" className="ml-2 text-xs">Unavailable</span>}
            </p>
            {stage.status === "running" && stage.detail && <p className="mt-0.5 text-xs leading-relaxed text-leaf">{stage.detail}</p>}
          </div>
        </li>)}
      </ul>
    </div>
    {elapsed >= 15 && <p className="mt-4 text-xs leading-relaxed text-leaf">Still working. Some websites take longer to load or inspect.</p>}
  </div>;
}
