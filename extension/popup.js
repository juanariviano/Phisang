const { VERDICTS, renderBanana, renderPeel, escapeHtml } = self.Phisang;

const el = {
  badge: document.getElementById("badge"),
  banana: document.getElementById("banana"),
  verdict: document.getElementById("verdict"),
  ripeness: document.getElementById("ripeness"),
  hint: document.getElementById("hint"),
  risk: document.getElementById("risk"),
  caveat: document.getElementById("caveat"),
  peel: document.getElementById("peel"),
  signals: document.getElementById("signals"),
  signalsLabel: document.getElementById("signals-label"),
  tech: document.getElementById("tech"),
  enabled: document.getElementById("enabled"),
};

chrome.storage.local.get({ protectionEnabled: true }, (stored) => {
  el.enabled.checked = stored.protectionEnabled !== false;
});
el.enabled.addEventListener("change", () => {
  chrome.storage.local.set({ protectionEnabled: el.enabled.checked });
});

function render(payload) {
  if (!payload || !payload.result) {
    renderBanana(el.banana, "unavailable", 92);
    renderPeel(el.peel, "");
    return;
  }

  const result = payload.result;
  const cls = VERDICTS[result.classification] ? result.classification : "unavailable";
  const meta = VERDICTS[cls];
  renderBanana(el.banana, cls, 92);

  document.body.className = "is-" + cls;

  el.badge.textContent = meta.badge;
  el.verdict.textContent = meta.verdict;
  el.ripeness.textContent = meta.ripeness;
  el.hint.textContent = meta.hint;

  if (result.risk_level) {
    el.risk.textContent = `Risk: ${result.risk_level} (${result.risk_score.toFixed(2)})`;
    el.risk.classList.remove("hidden");
  }

  if (meta.caveat) {
    el.caveat.textContent = meta.caveat;
    el.caveat.classList.remove("hidden");
  }

  renderPeel(el.peel, payload.url || result.normalized_url || "");

  const reasoning = result.page && result.page.reasoning ? [result.page.reasoning] : [];
  const lines = reasoning.concat(result.signals || []);
  if (lines.length) {
    el.signalsLabel.classList.remove("hidden");
    el.signals.innerHTML = lines.map((item) => "<li>" + escapeHtml(item) + "</li>").join("");
  }

  el.tech.textContent = JSON.stringify(
    {
      scan_id: result.scan_id,
      normalized_url: result.normalized_url,
      decision_stage: result.decision_stage,
      confidence: result.confidence,
      risk_score: result.risk_score,
      risk_level: result.risk_level,
      threat_intel: result.threat_intel,
      heuristic: result.heuristic,
      policy_version: result.policy_version,
    },
    null,
    2
  );
}

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const tabId = tabs[0] && tabs[0].id;
  chrome.runtime.sendMessage({ type: "GET_TAB_RESULT", tabId }, render);
});
