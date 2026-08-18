function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function show(id, text) {
  document.getElementById(id).textContent = text || "";
}

chrome.runtime.sendMessage({ type: "GET_TAB_RESULT" }, (payload) => {
  const result = payload?.result || {};
  const url = payload?.url || result.normalized_url || "";
  const cls = result.classification || "malware";
  document.body.classList.add(cls === "phishing" ? "is-phishing" : "is-malware");

  show("eyebrow", cls === "phishing" ? "Phishing warning" : "Malware warning");
  show("title", cls === "phishing" ? "This looks like a phishing URL" : "This URL is listed as malware");
  show("url", url);
  show(
    "summary",
    cls === "phishing"
      ? "LinkGuard blocked navigation so you can read why this address looks unsafe."
      : "URLhaus or LinkGuard classified this destination as malware. Navigation was stopped before the page loaded."
  );

  if (result.llm?.reasoning) {
    const box = document.getElementById("reasoning");
    box.classList.remove("hidden");
    box.innerHTML = `<h2>Why this matters</h2><p>${escapeHtml(result.llm.reasoning)}</p>`;
  }

  const signals = document.getElementById("signals");
  signals.innerHTML = (result.signals || [])
    .map((item) => `<li>${escapeHtml(item)}</li>`)
    .join("");

  const intel = result.threat_intel || {};
  const rows = [
    ["Classification", cls],
    ["Decision stage", result.decision_stage || "—"],
    ["Confidence", result.confidence != null ? `${result.confidence}%` : "—"],
    ["Scan ID", result.scan_id || "—"],
    ["URLhaus match", intel.matched ? `${intel.match_kind || "yes"} ${intel.id || ""}` : "no"],
    ["Threat type", intel.threat_type || "—"],
    ["First seen", intel.first_seen || "—"],
    ["Policy", result.policy_version || "poc-flowchart-v1"],
  ];
  document.getElementById("tech").innerHTML = rows
    .map(([k, v]) => `<div><dt>${escapeHtml(k)}</dt><dd>${escapeHtml(v)}</dd></div>`)
    .join("");

  document.getElementById("go-back").addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "GO_BACK", url });
  });
  document.getElementById("continue").addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "CONTINUE_ANYWAY", url });
  });
});
