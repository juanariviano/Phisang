import { motion } from "framer-motion";
import { verdictMeta } from "../lib/copy.js";

export function InventoryRail({ scans, onRefresh }) {
  return (
    <section className="mt-20 border-t-[2.5px] border-ink pt-7">
      <div className="flex items-end justify-between gap-4">
        <div>
          <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-leaf">The bunch</p>
          <h2 className="mt-1 font-display text-xl font-extrabold tracking-tight text-ink">
            Recent peels
          </h2>
        </div>
        <button
          type="button"
          onClick={onRefresh}
          className="cursor-pointer rounded-full border-2 border-leaf/55 px-3.5 py-1.5 text-xs font-semibold text-forest transition-colors duration-200 hover:border-ink hover:bg-paper"
        >
          Refresh
        </button>
      </div>

      {!scans.length ? (
        <p className="mt-7 max-w-[46ch] text-sm leading-relaxed text-leaf">
          Your recent checks will appear here.
        </p>
      ) : (
        <ul className="mt-5">
          {scans.map((scan, index) => {
            const meta = verdictMeta(scan, scan.classification);
            return (
              <motion.li
                key={scan.scan_id}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.045, type: "spring", stiffness: 120, damping: 20 }}
                className="grid grid-cols-1 items-center gap-1.5 border-t border-leaf/35 py-3 md:grid-cols-[11rem_minmax(0,1fr)]"
              >
                <span className="flex items-center gap-2">
                  <span
                    className={`size-3 shrink-0 rounded-full border border-ink/45 ${meta.dot}`}
                    aria-hidden="true"
                  />
                  <span className={`text-xs font-extrabold uppercase tracking-[0.1em] ${meta.tone}`}>
                    {meta.verdict}
                  </span>
                </span>
                <span className="truncate font-mono text-xs text-leaf" title={scan.normalized_url}>
                  {scan.normalized_url}
                </span>
              </motion.li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
