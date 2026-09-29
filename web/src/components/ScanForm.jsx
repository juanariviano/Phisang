import { EXAMPLES } from "../lib/copy.js";
import { MagneticButton } from "./MagneticButton.jsx";

export function ScanForm({ url, setUrl, busy, error, onSubmit, isRescan = false }) {
  return (
    <form onSubmit={onSubmit} className="mt-9 flex flex-col gap-2.5" autoComplete="off">
      <label htmlFor="url-input" className="text-sm font-bold text-forest">
        URL to peel
      </label>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-stretch">
        <input
          id="url-input"
          value={url}
          onChange={(event) => setUrl(event.target.value)}
          spellCheck={false}
          inputMode="url"
          placeholder="https://example.com/path"
          aria-describedby="url-help"
          aria-invalid={error ? "true" : undefined}
          className="w-full rounded-lg border-[2.5px] border-ink bg-paper px-4 py-3.5 font-mono text-sm text-ink outline-none transition-colors placeholder:text-leaf/70 focus:bg-flesh/45"
        />
        <MagneticButton disabled={busy} className="w-full sm:w-auto">
          {busy ? (isRescan ? "Rescanning" : "Peeling") : (isRescan ? "Rescan" : "Peel URL")}
        </MagneticButton>
      </div>
      {error ? (
        <p className="text-sm font-semibold text-rot" role="alert">
          {error}
        </p>
      ) : (
        <p id="url-help" className="text-sm text-leaf">
          HTTP and HTTPS only. The address stays on this machine and the local API.
        </p>
      )}
      <div className="mt-4 flex flex-wrap items-center gap-2">
        <span className="text-[11px] font-bold uppercase tracking-[0.18em] text-leaf">Try</span>
        {EXAMPLES.map((item) => (
          <button
            key={item.url}
            type="button"
            onClick={() => setUrl(item.url)}
            className="cursor-pointer rounded-full border-2 border-leaf/55 px-3.5 py-1.5 text-xs font-semibold text-forest transition-all duration-200 hover:border-ink hover:bg-paper active:scale-95"
          >
            {item.label}
          </button>
        ))}
      </div>
    </form>
  );
}
