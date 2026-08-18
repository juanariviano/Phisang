const form = document.querySelector("#scan-form");
const input = document.querySelector("#url-input");
const resultEl = document.querySelector("#result");
const healthPill = document.querySelector("#health-pill");
const inventoryEl = document.querySelector("#inventory-list");

const STATE = {
  malware: { icon: "⛔", title: "Malware", hint: "Known or likely malware distribution URL." },
  phishing: { icon: "⚠️", title: "Phishing", hint: "The URL string looks like a credential or brand trap." },
  benign: { icon: "○", title: "Benign (not listed)", hint: "No URLhaus match and no strong lexical risk. This is not a guarantee of safety." },
  unavailable: { icon: "◇", title: "Unavailable", hint: "A required check failed. This is a degraded result, not a clean one." },
  checking: { icon: "…", title: "Checking", hint: "Lookup and analysis in progress." },
};

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

async function loadHealth() {
  try {
    const res = await fetch("/api/v1/health");
    const data = await res.json();
    const missing = [];
    if (!data.urlhaus_configured) missing.push("URLhaus key");
    if (!data.gemini_configured) missing.push("Gemini key");
    if (data.status === "ok" && data.gemini_configured) {
      healthPill.textContent = "API ready";
      healthPill.className = "pill pill-ok";
    } else {
      healthPill.textContent = missing.length ? `Degraded · missing ${missing.join(", ")}` : "API degraded";
      healthPill.className = "pill pill-bad";
    }
  } catch {
    healthPill.textContent = "API unreachable";
    healthPill.className = "pill pill-bad";
  }
}

function renderChecking(url) {
  resultEl.classList.remove("hidden");
  resultEl.innerHTML = `
    <div class="result-head">
      <div class="badge state-checking"><span class="icon">${STATE.checking.icon}</span>Checking</div>
      <div>
        <h2>Analyzing URL</h2>
        <div class="url">${escapeHtml(url)}</div>
        <p class="fineprint">${STATE.checking.hint}</p>
      </div>
    </div>
  `;
}

function renderResult(data) {
  const cls = data.classification || "unavailable";
  const state = STATE[cls] || STATE.unavailable;
  const intel = data.threat_intel || {};
  const heuristic = data.heuristic || {};
  const llm = data.llm || {};
  const signals = (data.signals || []).map((s) => `<li>${escapeHtml(s)}</li>`).join("");
  const reasoning = llm.reasoning
    ? `<div class="reasoning"><span class="k">Gemini reasoning</span>${escapeHtml(llm.reasoning)}</div>`
    : "";
  const caveat =
    cls === "benign"
      ? `<div class="caveat">Not listed ≠ safe. LinkGuard did not visit this page, and the placeholder model only inspected the URL string.</div>`
      : cls === "unavailable"
        ? `<div class="caveat">Degraded result. A feed or model check failed, so LinkGuard will not call this URL benign.</div>`
        : "";

  resultEl.classList.remove("hidden");
  resultEl.innerHTML = `
    <div class="result-head">
      <div class="badge state-${escapeHtml(cls)}"><span class="icon">${state.icon}</span>${escapeHtml(state.title)}</div>
      <div>
        <h2>${escapeHtml(state.hint)}</h2>
        <div class="url">${escapeHtml(data.normalized_url || "")}</div>
      </div>
    </div>
    ${caveat}
    <div class="meta-grid">
      <div><span>Classification</span><strong>${escapeHtml(cls)}</strong></div>
      <div><span>Confidence</span><strong>${escapeHtml(data.confidence)}%</strong></div>
      <div><span>Decision stage</span><strong>${escapeHtml(data.decision_stage)}</strong></div>
      <div><span>Scan ID</span><strong>${escapeHtml(data.scan_id)}</strong></div>
      <div><span>URLhaus</span><strong>${intel.matched ? "Match" : "No match"}</strong></div>
      <div><span>Feed / threat</span><strong>${escapeHtml(intel.threat_type || intel.feed_status || "—")}</strong></div>
      <div><span>Heuristic</span><strong>${escapeHtml(heuristic.label || "skipped")} · ${heuristic.confidence ?? "—"}%</strong></div>
      <div><span>Policy</span><strong>${escapeHtml(data.policy_version)}</strong></div>
    </div>
    ${reasoning}
    <ul class="signals">${signals}</ul>
    <p class="fineprint">${(data.limitations || []).map(escapeHtml).join(" · ")}</p>
  `;
}

function renderError(payload, fallback) {
  resultEl.classList.remove("hidden");
  resultEl.innerHTML = `
    <div class="result-head">
      <div class="badge state-unavailable"><span class="icon">◇</span>Unavailable</div>
      <div>
        <h2>${escapeHtml(payload.message || fallback)}</h2>
        <p class="fineprint">${escapeHtml(payload.error_code || "analysis_incomplete")}</p>
      </div>
    </div>
  `;
}

async function loadInventory() {
  try {
    const res = await fetch("/api/v1/scans?limit=8");
    const data = await res.json();
    const scans = data.scans || [];
    if (!scans.length) {
      inventoryEl.textContent = "No scans yet.";
      return;
    }
    inventoryEl.innerHTML = scans
      .map(
        (scan) => `
        <div class="row">
          <strong>${escapeHtml(scan.classification)}</strong>
          <small title="${escapeHtml(scan.normalized_url)}">${escapeHtml(scan.normalized_url)}</small>
        </div>`
      )
      .join("");
  } catch {
    inventoryEl.textContent = "Inventory unavailable.";
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const url = input.value.trim();
  if (!url) return;
  renderChecking(url);
  try {
    const res = await fetch("/api/v1/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, client: "web" }),
    });
    const data = await res.json();
    if (!res.ok) {
      renderError(data, "Could not analyze this URL");
      return;
    }
    renderResult(data);
    loadInventory();
  } catch {
    renderError({ message: "Backend unreachable. Start the API on port 8000." }, "");
  }
});

document.querySelectorAll("#examples button").forEach((button) => {
  button.addEventListener("click", () => {
    input.value = button.dataset.url;
    input.focus();
  });
});

document.querySelector("#refresh-inventory").addEventListener("click", loadInventory);

loadHealth();
loadInventory();
