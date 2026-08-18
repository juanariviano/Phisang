import { AnimatePresence, motion } from "framer-motion";
import { CLASS_META } from "../lib/copy.js";
import { StatusGlyph } from "./StatusGlyph.jsx";

function Skeleton() {
  return (
    <div className="space-y-4">
      <div className="h-24 animate-pulse rounded-2xl bg-white/6" />
      <div className="grid grid-cols-2 gap-3">
        <div className="h-16 animate-pulse rounded-xl bg-white/6" />
        <div className="h-16 animate-pulse rounded-xl bg-white/6" />
        <div className="h-16 animate-pulse rounded-xl bg-white/6" />
        <div className="h-16 animate-pulse rounded-xl bg-white/6" />
      </div>
    </div>
  );
}

function Metric({ label, value }) {
  return (
    <div className="border-t border-white/8 py-3">
      <span className="block text-[11px] uppercase tracking-[0.14em] text-mist">{label}</span>
      <strong className="mt-1 block font-mono text-sm font-medium">{value}</strong>
    </div>
  );
}

export function ResultPanel({ busy, result }) {
  if (!busy && !result) return null;
  const cls = result?.classification || "checking";
  const meta = CLASS_META[cls] || CLASS_META.unavailable;
  const intel = result?.threat_intel || {};
  const heuristic = result?.heuristic || {};

  return (
    <AnimatePresence mode="wait">
      <motion.section
        key={busy ? "checking" : result.scan_id || "result"}
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -8 }}
        transition={{ type: "spring", stiffness: 100, damping: 20 }}
        className="rounded-[2rem] border border-white/8 bg-panel/80 p-6 shadow-[inset_0_1px_0_rgba(255,255,255,0.08)] md:p-8"
        aria-live="polite"
      >
        {busy && !result ? (
          <Skeleton />
        ) : (
          <>
            <div className="flex flex-col gap-5 sm:flex-row sm:items-start">
              <div className={`grid size-16 place-items-center rounded-2xl ${meta.wash} ${meta.tone}`}>
                <StatusGlyph kind={cls} />
              </div>
              <div className="min-w-0">
                <p className={`text-[11px] uppercase tracking-[0.18em] ${meta.tone}`}>{meta.title}</p>
                <h2 className="mt-2 text-2xl font-semibold tracking-tight md:text-3xl">{meta.hint}</h2>
                <p className="mt-3 break-all font-mono text-xs leading-relaxed text-mist">
                  {result.normalized_url}
                </p>
              </div>
            </div>

            {cls === "benign" && (
              <p className="mt-6 border-l-2 border-accent/70 pl-4 text-sm leading-relaxed text-paper/80">
                Not listed is not safe. LinkGuard did not visit this page. The placeholder model only inspected the URL string.
              </p>
            )}
            {cls === "unavailable" && (
              <p className="mt-6 border-l-2 border-unavailable pl-4 text-sm leading-relaxed text-paper/80">
                Degraded result. A feed or model check failed, so LinkGuard will not call this URL benign.
              </p>
            )}

            <div className="mt-8 grid grid-cols-1 sm:grid-cols-2">
              <Metric label="Classification" value={cls} />
              <Metric label="Confidence" value={`${result.confidence}%`} />
              <Metric label="Decision stage" value={result.decision_stage} />
              <Metric label="Scan ID" value={result.scan_id} />
              <Metric label="URLhaus" value={intel.matched ? "Match" : "No match"} />
              <Metric label="Threat" value={intel.threat_type || intel.feed_status || "—"} />
              <Metric
                label="Heuristic"
                value={`${heuristic.label || "skipped"} · ${heuristic.confidence ?? "—"}%`}
              />
              <Metric label="Policy" value={result.policy_version} />
            </div>

            {result.llm?.reasoning && (
              <blockquote className="mt-6 text-[15px] leading-relaxed text-paper/90">
                <span className="mb-2 block text-[11px] uppercase tracking-[0.16em] text-mist">Gemini reasoning</span>
                {result.llm.reasoning}
              </blockquote>
            )}

            {result.signals?.length > 0 && (
              <ul className="mt-6 divide-y divide-white/8">
                {result.signals.map((signal) => (
                  <li key={signal} className="py-3 text-sm leading-relaxed text-mist">
                    {signal}
                  </li>
                ))}
              </ul>
            )}
          </>
        )}
      </motion.section>
    </AnimatePresence>
  );
}
