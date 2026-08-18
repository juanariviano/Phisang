import { AnimatePresence, motion } from "framer-motion";
import { peelUrl } from "../lib/peel.js";

/**
 * The signature element. The address splits into labelled strips as you type,
 * which is both the demo and the honest description of the product: Phisang
 * reads these parts and never requests the page they point at.
 *
 * Strips unfurl top-down rather than sliding in — a peel opening, not a card
 * arriving.
 */
export function PeelStrips({ url, dense = false }) {
  const { valid, parts } = peelUrl(url);

  if (!valid || !parts.length) {
    return (
      <div className="rounded border-2 border-dashed border-leaf/40 px-4 py-5 text-center">
        <p className="font-mono text-xs text-leaf">Paste an address to split it into its parts</p>
      </div>
    );
  }

  return (
    <ul className={`flex flex-col ${dense ? "gap-1" : "gap-1.5"}`}>
      <AnimatePresence initial={false}>
        {parts.map((part, index) => (
          <motion.li
            key={part.key}
            layout
            initial={{ opacity: 0, clipPath: "inset(0 0 100% 0)" }}
            animate={{ opacity: 1, clipPath: "inset(0 0 0% 0)" }}
            exit={{ opacity: 0, clipPath: "inset(0 0 100% 0)" }}
            transition={{ delay: index * 0.045, duration: 0.32, ease: [0.16, 1, 0.3, 1] }}
            className="strip"
          >
            <span className="strip-label">{part.label}</span>
            <span className={`strip-value ${dense ? "text-[11px]" : "text-[13px]"}`}>
              {part.value}
            </span>
            {part.note && <span className="strip-note">{part.note}</span>}
          </motion.li>
        ))}
      </AnimatePresence>
    </ul>
  );
}
