import { motion } from "framer-motion";
import { CLASS_META } from "../lib/copy.js";

export function InventoryRail({ scans, onRefresh }) {
  return (
    <section className="mt-16 border-t border-white/8 pt-8">
      <div className="flex items-end justify-between gap-4">
        <div>
          <p className="text-[11px] uppercase tracking-[0.18em] text-mist">Inventory</p>
          <h2 className="mt-2 text-xl font-semibold tracking-tight">Recent scans</h2>
        </div>
        <button
          type="button"
          onClick={onRefresh}
          className="text-sm text-mist underline-offset-4 transition-colors hover:text-paper hover:underline"
        >
          Refresh
        </button>
      </div>

      {!scans.length ? (
        <p className="mt-8 max-w-[42ch] text-sm leading-relaxed text-mist">
          Nothing stored yet. Analyze a URL and the verdict will land here for this API session.
        </p>
      ) : (
        <ul className="mt-6 divide-y divide-white/8">
          {scans.map((scan, index) => {
            const meta = CLASS_META[scan.classification] || CLASS_META.unavailable;
            return (
              <motion.li
                key={scan.scan_id}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.05, type: "spring", stiffness: 100, damping: 20 }}
                className="grid grid-cols-1 gap-2 py-4 md:grid-cols-[140px_minmax(0,1fr)] md:items-center"
              >
                <span className={`text-xs font-semibold uppercase tracking-[0.14em] ${meta.tone}`}>
                  {meta.title}
                </span>
                <span className="truncate font-mono text-xs text-mist" title={scan.normalized_url}>
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
