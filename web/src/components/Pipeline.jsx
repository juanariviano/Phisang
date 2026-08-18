import { memo } from "react";
import { motion } from "framer-motion";
import { PeelStrips } from "./PeelStrips.jsx";

const GATES = [
  { label: "URLhaus", detail: "Exact address, then the related host path" },
  { label: "Lexical model", detail: "Placeholder scoring, 80% gate" },
  { label: "Gemini", detail: "Only when the local check is inconclusive" },
];

/**
 * The idle panel. Numbering stays because the gates really do run in order and
 * stop at the first confident answer — the sequence carries information.
 */
export const Pipeline = memo(function Pipeline({ url }) {
  return (
    <div className="overflow-hidden rounded-xl border-[2.5px] border-ink bg-paper p-6 md:p-7">
      <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-leaf">The peel</p>
      <div className="mt-2.5">
        <PeelStrips url={url} dense />
      </div>

      <div className="my-7 border-t-2 border-dashed border-leaf/35" />

      <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-leaf">Three gates</p>
      <h2 className="mt-2 max-w-[16ch] font-display text-2xl font-extrabold leading-[1.02] tracking-tight text-ink md:text-[1.75rem]">
        First confident answer wins.
      </h2>
      <ol className="mt-5">
        {GATES.map((gate, index) => (
          <motion.li
            key={gate.label}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 * index, type: "spring", stiffness: 120, damping: 20 }}
            className="flex items-start gap-3.5 border-t border-leaf/35 py-3.5"
          >
            <span className="mt-0.5 grid size-6 shrink-0 place-items-center rounded-full bg-ink font-mono text-[11px] font-bold text-peel">
              {index + 1}
            </span>
            <div>
              <p className="font-display font-extrabold tracking-tight text-ink">{gate.label}</p>
              <p className="mt-0.5 text-sm leading-relaxed text-leaf">{gate.detail}</p>
            </div>
          </motion.li>
        ))}
      </ol>
      <p className="mt-4 text-sm leading-relaxed text-leaf">
        The destination page is never fetched or rendered.
      </p>
    </div>
  );
});
