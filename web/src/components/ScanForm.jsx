import { EXAMPLES } from "../lib/copy.js";
import { MagneticButton } from "./MagneticButton.jsx";

export function ScanForm({ url, setUrl, busy, error, onSubmit }) {
  return (
    <form onSubmit={onSubmit} className="mt-10 flex flex-col gap-2" autoComplete="off">
      <label htmlFor="url-input" className="text-sm text-mist">
        URL to analyze
      </label>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-stretch">
        <input
          id="url-input"
          value={url}
          onChange={(event) => setUrl(event.target.value)}
          spellCheck={false}
          placeholder="https://example.com/path"
          className="w-full rounded-2xl border border-white/10 bg-ink px-4 py-3.5 font-mono text-sm text-paper outline-none transition-[border-color] placeholder:text-mist/50 focus:border-accent/60"
        />
        <MagneticButton disabled={busy} className="w-full sm:w-auto">
          {busy ? "Analyzing" : "Analyze"}
        </MagneticButton>
      </div>
      {error ? (
        <p className="text-sm text-accent" role="alert">
          {error}
        </p>
      ) : (
        <p className="text-sm text-mist">HTTP and HTTPS only. Query strings stay on this machine and the local API.</p>
      )}
      <div className="mt-4 flex flex-wrap items-center gap-2">
        <span className="text-xs uppercase tracking-[0.16em] text-mist">Try</span>
        {EXAMPLES.map((item) => (
          <button
            key={item.url}
            type="button"
            onClick={() => setUrl(item.url)}
            className="rounded-full border border-white/10 px-3 py-1.5 text-xs text-paper transition-transform active:scale-[0.98] hover:border-white/25"
          >
            {item.label}
          </button>
        ))}
      </div>
    </form>
  );
}
