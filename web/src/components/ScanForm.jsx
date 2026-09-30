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
        <button type="submit" disabled={busy}
          className="w-full cursor-pointer rounded-full bg-ink px-8 py-3.5 font-display text-sm font-extrabold uppercase tracking-[0.1em] text-peel transition-colors hover:bg-forest disabled:cursor-not-allowed disabled:bg-leaf/40 disabled:text-paper sm:w-auto">
          {busy ? (isRescan ? "Rescanning" : "Peeling") : (isRescan ? "Rescan" : "Peel URL")}
        </button>
      </div>
      {error ? (
        <p className="text-sm font-semibold text-rot" role="alert">
          {error}
        </p>
      ) : (
        <p id="url-help" className="text-sm text-leaf">
          Paste a website address to check it without opening it in your browser.
        </p>
      )}
    </form>
  );
}
