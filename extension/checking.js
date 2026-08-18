const params = new URLSearchParams(location.search);
const url = params.get("url") || "";
const tabId = Number(params.get("tabId") || "0");
const API_BASE = "http://localhost:8000";

document.getElementById("url").textContent = url;
const statusEl = document.getElementById("status");

async function run() {
  try {
    const res = await fetch(`${API_BASE}/api/v1/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, client: "extension" }),
    });
    const result = await res.json();
    if (!res.ok) {
      throw new Error(result.message || result.error_code || "analyze failed");
    }
    statusEl.textContent = `Decision: ${result.classification} via ${result.decision_stage}`;
    await chrome.runtime.sendMessage({ type: "ANALYSIS_RESULT", tabId, url, result });
  } catch (error) {
    statusEl.textContent = "Backend unavailable — allowing navigation with a degraded warning.";
    await chrome.runtime.sendMessage({
      type: "ANALYSIS_ERROR",
      tabId,
      url,
      error: String(error),
    });
  }
}

run();
