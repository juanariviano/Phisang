const { VERDICTS, renderBanana, renderPeel, escapeHtml } = self.Phisang;

const TITLES = {
  malware: "This address serves malware",
  phishing: "This address is shaped like a trap",
};

const SUMMARIES = {
  malware:
    "URLhaus or Phisang classified this destination as malware. The page was never fetched — everything below comes from reading the address itself.",
  phishing:
    "Phisang stopped the navigation so you can read why this address looks unsafe. The page was never fetched.",
};

function show(id, text) {
  document.getElementById(id).textContent = text || "";
}

chrome.runtime.sendMessage({ type: "GET_TAB_RESULT" }, (payload) => {
  const result = (payload && payload.result) || {};
  const url = (payload && payload.url) || result.normalized_url || "";
  const cls = result.classification === "phishing" ? "phishing" : "malware";
  const meta = VERDICTS[cls];
  renderBanana(document.getElementById("banana"), cls, 120);

  document.body.classList.remove("is-malware");
  document.body.classList.add("is-" + cls);

  show("verdict", meta.verdict);
  show("ripeness", meta.ripeness);
  show("eyebrow", "Navigation stopped");
  show("title", TITLES[cls]);
  show("summary", SUMMARIES[cls]);

  renderPeel(document.getElementById("peel"), url);

  if (result.page && result.page.reasoning) {
    const box = document.getElementById("reasoning");
    box.classList.remove("hidden");
    box.innerHTML = "<h2>Why this matters</h2><p>" + escapeHtml(result.page.reasoning) + "</p>";
  }

  const signals = result.signals || [];
  if (signals.length) {
    document.getElementById("signals").innerHTML = signals
      .map((item) => "<li>" + escapeHtml(item) + "</li>")
      .join("");
  } else {
    document.getElementById("signals-label").classList.add("hidden");
  }

  const intel = result.threat_intel || {};
  const rows = [
    ["Classification", cls],
    ["Decision stage", result.decision_stage || "—"],
    ["Confidence", result.confidence != null ? result.confidence + "%" : "—"],
    [
      "Risk level",
      result.risk_level ? result.risk_level + " (" + result.risk_score.toFixed(2) + ")" : "—",
    ],
    ["Scan ID", result.scan_id || "—"],
    ["URLhaus match", intel.matched ? (intel.match_kind || "yes") + " " + (intel.id || "") : "no"],
    ["Threat type", intel.threat_type || "—"],
    ["First seen", intel.first_seen || "—"],
    ["Policy", result.policy_version || "poc-flowchart-v1"],
  ];
  document.getElementById("tech").innerHTML = rows
    .map(([k, v]) => "<div><dt>" + escapeHtml(k) + "</dt><dd>" + escapeHtml(v) + "</dd></div>")
    .join("");

  document.getElementById("go-back").addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "GO_BACK", url });
  });
  document.getElementById("continue").addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "CONTINUE_ANYWAY", url });
  });
});
