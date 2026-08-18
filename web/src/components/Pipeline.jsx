import { memo } from "react";
import { motion } from "framer-motion";

const STEPS = [
  { id: "01", label: "URLhaus", detail: "Exact URL, then related host path" },
  { id: "02", label: "Lexical model", detail: "Placeholder scoring, 80% gate" },
  { id: "03", label: "Gemini", detail: "Only if the local check is inconclusive" },
];

export const Pipeline = memo(function Pipeline() {
  return (
    <div className="relative overflow-hidden rounded-[2rem] border border-white/8 bg-panel/80 p-8 shadow-[inset_0_1px_0_rgba(255,255,255,0.08)] md:p-10">
      <p className="text-[11px] uppercase tracking-[0.2em] text-mist">Idle pipeline</p>
      <h2 className="mt-3 max-w-[16ch] text-3xl font-semibold tracking-tight">Three gates. One honest verdict.</h2>
      <ol className="mt-10 space-y-0 divide-y divide-white/8">
        {STEPS.map((step, index) => (
          <motion.li
            key={step.id}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.12 * index, type: "spring", stiffness: 100, damping: 20 }}
            className="flex items-start gap-5 py-5"
          >
            <span className="relative mt-1 font-mono text-xs text-accent">
              {step.id}
              <span className="absolute -left-2 top-1/2 h-1.5 w-1.5 -translate-y-1/2 rounded-full bg-accent">
                <span className="absolute inset-0 animate-ping rounded-full bg-accent/70" />
              </span>
            </span>
            <div>
              <p className="font-medium tracking-tight">{step.label}</p>
              <p className="mt-1 text-sm leading-relaxed text-mist">{step.detail}</p>
            </div>
          </motion.li>
        ))}
      </ol>
      <p className="mt-6 text-sm text-mist">The destination page is never fetched or rendered.</p>
    </div>
  );
});
