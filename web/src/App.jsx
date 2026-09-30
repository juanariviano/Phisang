import { useEffect, useRef, useState } from "react";
import { LayoutGroup, motion, useReducedMotion } from "framer-motion";
import { InventoryRail } from "./components/InventoryRail.jsx";
import { BrandMark } from "./components/BrandMark.jsx";
import { Pipeline } from "./components/Pipeline.jsx";
import { ResultPanel } from "./components/ResultPanel.jsx";
import { Bench } from "./components/Bench.jsx";
import { ScanForm } from "./components/ScanForm.jsx";
import { readScanStream } from "./lib/explanationStream.js";

export default function App() {
  const reducedMotion = useReducedMotion();
  const [hasCompleted, setHasCompleted] = useState(false);
  const layoutTransition = reducedMotion ? { duration: 0 } : { type: "spring", stiffness: 110, damping: 24 };
  const [url, setUrl] = useState("");
  const [rescanTarget, setRescanTarget] = useState(null);
  const editVersion = useRef(0);
  function changeUrl(value) {
    editVersion.current += 1;
    setUrl(value);
    setRescanTarget(null);
  }
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState([]);
  const scanController = useRef(null);
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
    return () => scanController.current?.abort();
  }, []);

  async function onSubmit(event) {
    event.preventDefault();
    await runScan(rescanTarget || url.trim(), Boolean(rescanTarget));
  }

  async function runScan(value, rescan = false) {
    if (!value || busy) return;
    const submittedVersion = editVersion.current;
    setBusy(true);
    setError("");
    setResult(null);
    setProgress([]);
    scanController.current = new AbortController();
    try {
      const res = await fetch("/api/v1/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "text/event-stream" },
        signal: scanController.current.signal,
        body: JSON.stringify({ url: value, client: "web", rescan }),
      });
      let data;
      await readScanStream(res, {
        onProgress: (stage) => setProgress((current) => current.some((s) => s.stage === stage.stage)
          ? current.map((s) => s.stage === stage.stage ? stage : s) : [...current, stage]),
        onDone: (value) => { data = value; },
      });
      setResult(data);
      setHasCompleted(true);
      if (editVersion.current === submittedVersion) {
        setRescanTarget(data.normalized_url || value);
      }
      loadInventory();
    } catch (err) {
      if (err.name !== "AbortError") setError(err instanceof TypeError
        ? "The scanner could not be reached. Please try again shortly." : err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="relative min-h-[100dvh] overflow-x-hidden">
      <Bench />

      <div className="relative mx-auto w-full max-w-[1320px] px-4 py-8 sm:px-6 md:px-8 md:py-10">
        <header className="flex items-center gap-3">
          <BrandMark />
          <p className="font-display text-2xl font-extrabold leading-none tracking-tight text-ink">
            Phisang
          </p>
        </header>

        <LayoutGroup>
        <motion.main layout="position" transition={{ layout: layoutTransition }} data-layout={hasCompleted ? "stacked" : "columns"}
          className={`mt-12 grid grid-cols-1 items-start gap-7 lg:mt-16 ${hasCompleted ? "mx-auto max-w-[960px]" : "lg:grid-cols-[minmax(0,1.05fr)_minmax(0,0.95fr)] lg:gap-14"}`}>
          <motion.section layout="position" transition={{ layout: layoutTransition }}>
            {!hasCompleted && <>
            <p className="text-[11px] font-bold uppercase tracking-[0.22em] text-leaf">
              Malicious URL detection
            </p>
            <h1 className="mt-3.5 max-w-[12ch] font-display text-[clamp(2.9rem,7.6vw,5.25rem)] font-extrabold leading-[0.88] tracking-[-0.04em] text-ink">
              Check a link before you trust it.
            </h1>
            <p className="mt-6 max-w-[54ch] text-base leading-relaxed text-forest">
              Not sure about a website? Check for signs of phishing and malware,
              then see what the findings mean before you share personal details.
            </p>
            </>}
            {hasCompleted && <h1 className="font-display text-3xl font-extrabold tracking-tight text-ink sm:text-4xl">Check a link</h1>}
            <ScanForm url={url} setUrl={changeUrl} isRescan={Boolean(rescanTarget)} busy={busy} error={error} onSubmit={onSubmit} />

            {!hasCompleted && <p className="mt-10 max-w-[54ch] text-xs leading-relaxed text-leaf">
              Known threat information from{" "}
              <a
                className="font-semibold text-ink underline underline-offset-2"
                href="https://urlhaus.abuse.ch/"
                target="_blank"
                rel="noreferrer"
              >
                URLhaus / abuse.ch
              </a>
              .
            </p>}
          </motion.section>

          <motion.aside layout="position" transition={{ layout: layoutTransition }} className="min-w-0" data-result-region>
            {busy || result ? (
              <ResultPanel busy={busy} result={result} progress={progress} />
            ) : (
              <Pipeline url={url} />
            )}
          </motion.aside>
        </motion.main>
        </LayoutGroup>

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
