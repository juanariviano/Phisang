import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Grain } from "./components/Grain.jsx";
import { InventoryRail } from "./components/InventoryRail.jsx";
import { Pipeline } from "./components/Pipeline.jsx";
import { ResultPanel } from "./components/ResultPanel.jsx";
import { ScanForm } from "./components/ScanForm.jsx";

export default function App() {
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [health, setHealth] = useState(null);
  const [scans, setScans] = useState([]);

  async function loadHealth() {
    try {
      const res = await fetch("/api/v1/health");
      setHealth(await res.json());
    } catch {
      setHealth({ status: "down" });
    }
  }

  async function loadInventory() {
    try {
      const res = await fetch("/api/v1/scans?limit=8");
      const data = await res.json();
      setScans(data.scans || []);
    } catch {
      setScans([]);
    }
  }

  useEffect(() => {
    loadHealth();
    loadInventory();
  }, []);

  async function onSubmit(event) {
    event.preventDefault();
    const value = url.trim();
    if (!value) return;
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const res = await fetch("/api/v1/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: value, client: "web" }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.message || "Could not analyze this URL");
        setResult(null);
        return;
      }
      setResult(data);
      loadInventory();
      loadHealth();
    } catch {
      setError("Backend unreachable. Start the API on port 8000.");
    } finally {
      setBusy(false);
    }
  }

  const healthLabel =
    health?.status === "ok" && health.gemini_configured
      ? "API ready"
      : health?.status === "down"
        ? "API unreachable"
        : "API degraded";

  return (
    <div className="relative min-h-[100dvh] overflow-x-hidden">
      <Grain />
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -left-24 top-[-8rem] h-72 w-72 rounded-full bg-accent/15 blur-3xl md:h-96 md:w-96"
      />
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -right-16 top-40 h-64 w-64 rounded-full bg-paper/5 blur-3xl"
      />

      <div className="relative mx-auto w-full max-w-[1400px] px-4 py-8 sm:px-6 md:px-8 md:py-12">
        <header className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <span className="grid size-10 place-items-center rounded-xl bg-accent text-sm font-bold tracking-wide text-paper">
              LG
            </span>
            <div>
              <p className="text-sm font-semibold tracking-tight">LinkGuard</p>
              <p className="text-xs text-mist">URLhaus · lexical gate · Gemini</p>
            </div>
          </div>
          <div className="flex items-center gap-2 self-start rounded-full border border-white/10 px-3 py-1.5 text-xs text-mist sm:self-auto">
            <span className="relative flex size-2">
              <span className="absolute inset-0 animate-ping rounded-full bg-accent/70" />
              <span className="relative size-2 rounded-full bg-accent" />
            </span>
            {healthLabel}
          </div>
        </header>

        <main className="mt-12 grid grid-cols-1 items-start gap-10 lg:mt-16 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,0.85fr)] lg:gap-16">
          <section>
            <p className="text-[11px] uppercase tracking-[0.22em] text-accent">Malicious URL detection · POC</p>
            <h1 className="mt-4 max-w-[14ch] text-4xl font-semibold tracking-tighter md:text-6xl md:leading-none">
              Inspect the link. Skip the page.
            </h1>
            <p className="mt-5 max-w-[62ch] text-base leading-relaxed text-mist">
              LinkGuard checks known malware in URLhaus, scores the URL string with a placeholder model, and asks Gemini only when that local check is inconclusive. Destinations are never crawled.
            </p>
            <ScanForm url={url} setUrl={setUrl} busy={busy} error={error} onSubmit={onSubmit} />
            <p className="mt-8 max-w-[62ch] text-xs leading-relaxed text-mist">
              Do not open the malware sample in a normal tab. Threat matches are attributed to{" "}
              <a className="text-paper underline-offset-4 hover:underline" href="https://urlhaus.abuse.ch/" target="_blank" rel="noreferrer">
                URLhaus / abuse.ch
              </a>
              .
            </p>
          </section>

          <aside className="lg:sticky lg:top-8">
            {busy || result ? <ResultPanel busy={busy} result={result} /> : <Pipeline />}
          </aside>
        </main>

        <InventoryRail scans={scans} onRefresh={loadInventory} />

        <footer className="mt-16 overflow-hidden border-t border-white/8 pt-6">
          <motion.p
            className="whitespace-nowrap font-mono text-[11px] uppercase tracking-[0.22em] text-mist"
            animate={{ x: ["0%", "-50%"] }}
            transition={{ duration: 28, repeat: Infinity, ease: "linear" }}
          >
            Policy poc-flowchart-v1.1 · Not listed is not safe · No page crawl · Heuristic is not a trained model · URLhaus by abuse.ch · Policy poc-flowchart-v1.1 · Not listed is not safe · No page crawl · Heuristic is not a trained model · URLhaus by abuse.ch ·
          </motion.p>
        </footer>
      </div>
    </div>
  );
}
