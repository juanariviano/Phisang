import { AnimatePresence, motion } from "framer-motion";
import { CLASS_META } from "../lib/copy.js";
import { Banana } from "./Banana.jsx";
import { PeelStrips } from "./PeelStrips.jsx";

/** Verdict word, ripeness chip, and the one-line reading of the state. */
function Verdict({ cls, meta }) {
  return (
    <div className="flex items-center gap-5">
      <Banana state={cls} width={116} className="shrink-0" />
      <div className="min-w-0">
        <div className="flex flex-wrap items-baseline gap-x-2.5 gap-y-1">
          <h2
            className={`font-display text-[1.75rem] font-extrabold leading-none tracking-tight ${
              meta.rots ? "text-peel" : meta.tone
            }`}
          >
            {meta.verdict}
          </h2>
          <span
            className={`text-[10px] font-bold uppercase tracking-[0.2em] ${
              meta.rots ? "off-rot" : "text-leaf"
            }`}
          >
            {meta.ripeness}
          </span>
        </div>
        <p
          className={`mt-2 max-w-[34ch] text-sm leading-relaxed ${
            meta.rots ? "text-flesh" : "text-forest"
          }`}
        >
          {meta.hint}
        </p>
      </div>
    </div>
  );
}

function Peeling({ url }) {
  return (
    <div className="space-y-6">
      <Verdict cls="checking" meta={CLASS_META.checking} />
      {/* The sweep runs over the strips themselves, so the loading state shows
          the work being done rather than an abstract bar filling. */}
      <div className="sweep rounded">
        <PeelStrips url={url} dense />
      </div>
    </div>
  );
}

function Metric({ label, value }) {
  return (
    <div className="rule-rot border-t border-leaf/30 py-2.5">
      <span className="off-rot block text-[10px] font-bold uppercase tracking-[0.14em] text-leaf">
        {label}
      </span>
      <strong className="on-rot mt-0.5 block break-all font-mono text-[13px] font-medium text-ink">
        {value}
      </strong>
    </div>
  );
}

export function ResultPanel({ busy, result, url }) {
  if (!busy && !result) return null;

  const cls = busy && !result ? "checking" : result?.classification || "unavailable";
  const meta = CLASS_META[cls] || CLASS_META.unavailable;
  const intel = result?.threat_intel || {};
  const heuristic = result?.heuristic || {};
  const blocked = cls === "malware" || cls === "phishing";

  return (
    <AnimatePresence mode="wait">
      <motion.section
        key={busy && !result ? "checking" : result.scan_id || "result"}
        initial={{ opacity: 0, y: 18 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -10 }}
        transition={{ type: "spring", stiffness: 140, damping: 20 }}
        className={`overflow-hidden rounded-xl border-[2.5px] border-ink ${
          meta.rots ? "rotted" : "bg-paper"
        }`}
        aria-live="polite"
      >
        {/* Caution tape belongs to malware alone. */}
        {meta.rots && <div className="hazard-rule" />}

        <div className="p-6 md:p-7">
          {busy && !result ? (
            <Peeling url={url} />
          ) : (
            <>
              <Verdict cls={cls} meta={meta} />

              {blocked && (
                <p
                  className={`mt-6 border-l-4 py-2 pl-4 text-sm font-semibold leading-relaxed ${
                    meta.rots ? "border-peel text-peel" : "border-rot text-rot"
                  }`}
                >
                  Do not open this address in a normal tab.
                </p>
              )}
              {cls === "benign" && (
                <p className="mt-6 border-l-4 border-leaf py-2 pl-4 text-sm leading-relaxed text-forest">
                  Not listed is not safe. Phisang did not visit this page — the placeholder model
                  only inspected the address string.
                </p>
              )}
              {cls === "unavailable" && (
                <p className="mt-6 border-l-4 border-leaf py-2 pl-4 text-sm leading-relaxed text-forest">
                  Degraded result. A feed or model check failed, so Phisang will not call this
                  address clean.
                </p>
              )}

              <div className="mt-7">
                <p className="off-rot mb-2.5 text-[10px] font-bold uppercase tracking-[0.18em] text-leaf">
                  The peel
                </p>
                <PeelStrips url={result.normalized_url} dense />
              </div>

              <div className="mt-7 grid grid-cols-1 sm:grid-cols-2 sm:gap-x-6">
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
                <blockquote
                  className={`mt-7 border-l-4 py-1 pl-4 ${meta.rots ? "border-peel" : "border-ink"}`}
                >
                  <span className="off-rot mb-1.5 block text-[10px] font-bold uppercase tracking-[0.18em] text-leaf">
                    Gemini reasoning
                  </span>
                  <p className="on-rot text-[15px] leading-relaxed text-forest">
                    {result.llm.reasoning}
                  </p>
                </blockquote>
              )}

              {result.signals?.length > 0 && (
                <div className="mt-7">
                  <p className="off-rot mb-1 text-[10px] font-bold uppercase tracking-[0.18em] text-leaf">
                    Signals
                  </p>
                  <ul>
                    {result.signals.map((signal) => (
                      <li
                        key={signal}
                        className="rule-rot on-rot border-t border-leaf/30 py-2.5 text-sm leading-relaxed text-forest"
                      >
                        {signal}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </>
          )}
        </div>

        {meta.rots && <div className="hazard-rule" />}
      </motion.section>
    </AnimatePresence>
  );
}
