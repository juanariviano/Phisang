import { useEffect, useState } from "react";
import { InventoryRail } from "./components/InventoryRail.jsx";
import { Banana } from "./components/Banana.jsx";
import { Pipeline } from "./components/Pipeline.jsx";
import { ResultPanel } from "./components/ResultPanel.jsx";
import { Bench } from "./components/Bench.jsx";
import { ScanForm } from "./components/ScanForm.jsx";

export default function App() {
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [scans, setScans] = useState([]);

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
        setError(data.message || "Could not peel this address");
        setResult(null);
        return;
      }
      setResult(data);
      loadInventory();
    } catch {
      setError("Backend unreachable. Start the API on port 8000.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="relative min-h-[100dvh] overflow-x-hidden">
      <Bench />

      <div className="relative mx-auto w-full max-w-[1320px] px-4 py-8 sm:px-6 md:px-8 md:py-10">
        <header className="flex items-center gap-3">
          {/* The brand mark is the same banana the verdicts use, sealed. Upright
              it is 1:3 and reads as a sliver, so the lockup tilts it. */}
          <Banana state="benign" frame="tight" height={38} className="rotate-[-20deg]" />
          <p className="font-display text-xl font-extrabold leading-none tracking-tight text-ink">
            Phisang
          </p>
        </header>

        <main className="mt-12 grid grid-cols-1 items-start gap-10 lg:mt-16 lg:grid-cols-[minmax(0,1.05fr)_minmax(0,0.95fr)] lg:gap-14">
          <section>
            <p className="text-[11px] font-bold uppercase tracking-[0.22em] text-leaf">
              Malicious URL detection
            </p>
            <h1 className="mt-3.5 max-w-[12ch] font-display text-[clamp(2.9rem,7.6vw,5.25rem)] font-extrabold leading-[0.88] tracking-[-0.04em] text-ink">
              We read the peel, never the fruit.
            </h1>
            <p className="mt-6 max-w-[54ch] text-base leading-relaxed text-forest">
              Phisang splits an address into its parts, checks the known-malware feed, scores the
              string, and asks Gemini only when the local check is inconclusive. The page it points
              at is never opened.
            </p>

            <ScanForm url={url} setUrl={setUrl} busy={busy} error={error} onSubmit={onSubmit} />

            <p className="mt-10 max-w-[54ch] text-xs leading-relaxed text-leaf">
              Do not open the malware sample in a normal tab. Threat matches are attributed to{" "}
              <a
                className="font-semibold text-ink underline underline-offset-2"
                href="https://urlhaus.abuse.ch/"
                target="_blank"
                rel="noreferrer"
              >
                URLhaus / abuse.ch
              </a>
              .
            </p>
          </section>

          <aside className="lg:sticky lg:top-8">
            {busy || result ? (
              <ResultPanel busy={busy} result={result} url={url} />
            ) : (
              <Pipeline url={url} />
            )}
          </aside>
        </main>

        <InventoryRail scans={scans} onRefresh={loadInventory} />

        <footer className="mt-14 border-t-[2.5px] border-ink pt-5">
          <ul className="flex flex-wrap gap-x-6 gap-y-1.5 font-mono text-[11px] font-medium uppercase tracking-[0.16em] text-leaf">
            <li>Made with 💘 by Phisang team</li>
          </ul>
        </footer>
      </div>
    </div>
  );
}
