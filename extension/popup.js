const badge = document.getElementById("badge");
const urlEl = document.getElementById("url");
const summary = document.getElementById("summary");
const caveat = document.getElementById("caveat");
const signals = document.getElementById("signals");
const tech = document.getElementById("tech");
const enabled = document.getElementById("enabled");

chrome.storage.local.get({ protectionEnabled: true }, (stored) => {
  enabled.checked = stored.protectionEnabled !== false;
});
enabled.addEventListener("change", () => {
  chrome.storage.local.set({ protectionEnabled: enabled.checked });
});

function render(payload) {
  if (!payload?.result) {
    summary.textContent = "Open an http(s) page while the LinkGuard API is running on localhost:8000.";
    return;
  }
  const result = payload.result;
  const cls = result.classification || "unavailable";
  badge.textContent = cls;
  badge.className = `badge ${cls}`;
  urlEl.textContent = payload.url || result.normalized_url || "";
  summary.textContent = result.llm?.reasoning || (result.signals || [])[0] || "No explanation available.";

  if (cls === "benign") {
    caveat.classList.remove("hidden");
    caveat.textContent = "Not listed ≠ safe. This result only means LinkGuard found no URLhaus match and no strong lexical risk.";
  } else if (cls === "unavailable") {
    caveat.classList.remove("hidden");
    caveat.textContent = "Degraded result: a required check failed. This is not a clean verdict.";
  }

  signals.innerHTML = (result.signals || [])
    .map((item) => `<li>${String(item).replaceAll("&", "&amp;").replaceAll("<", "&lt;")}</li>`)
    .join("");
  tech.textContent = JSON.stringify(
    {
      scan_id: result.scan_id,
      normalized_url: result.normalized_url,
      decision_stage: result.decision_stage,
      confidence: result.confidence,
      threat_intel: result.threat_intel,
      heuristic: result.heuristic,
      policy_version: result.policy_version,
    },
    null,
    2
  );
}

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const tabId = tabs[0]?.id;
  chrome.runtime.sendMessage({ type: "GET_TAB_RESULT", tabId }, render);
});
