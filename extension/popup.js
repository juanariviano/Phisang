const {
  VERDICTS, verdictMeta, caveatFor, historyNotes, recordRows, pageRows, renderRows,
  renderBanana, renderPeel,
} = self.Phisang;

const el = {
  badge: document.getElementById("badge"),
  banana: document.getElementById("banana"),
  verdict: document.getElementById("verdict"),
  ripeness: document.getElementById("ripeness"),
  hint: document.getElementById("hint"),
  risk: document.getElementById("risk"),
  caveat: document.getElementById("caveat"),
  history: document.getElementById("history"),
  peel: document.getElementById("peel"),
  page: document.getElementById("page"),
  reasoning: document.getElementById("reasoning"),
  pageFacts: document.getElementById("page-facts"),
  signals: document.getElementById("signals"),
  signalsLabel: document.getElementById("signals-label"),
  rescan: document.getElementById("rescan"),
  rescanStatus: document.getElementById("rescan-status"),
  tech: document.getElementById("tech"),
  enabled: document.getElementById("enabled"),
};

let current = null;

chrome.storage.local.get({ protectionEnabled: true }, (stored) => {
  el.enabled.checked = stored.protectionEnabled !== false;
});
el.enabled.addEventListener("change", () => {
  chrome.storage.local.set({ protectionEnabled: el.enabled.checked });
});

function setText(node, text) {
  node.textContent = text || "";
  node.classList.toggle("hidden", !text);
}

function setList(node, items) {
  node.replaceChildren(...items.map((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    return li;
  }));
  node.classList.toggle("hidden", !items.length);
}

// Safe to call again after a rescan: every field is set or cleared, never appended to.
function render(payload) {
  current = payload;
  if (!payload || !payload.result) {
    renderBanana(el.banana, "unavailable", 92);
    renderPeel(el.peel, "");
    return;
  }

  const result = payload.result;
  const cls = VERDICTS[result.classification] ? result.classification : "unavailable";
  const meta = verdictMeta(result, cls);
  renderBanana(el.banana, cls, 92);

  document.body.className = "is-" + cls;

  el.badge.textContent = meta.badge;
  el.verdict.textContent = meta.verdict;
  el.ripeness.textContent = meta.ripeness;
  el.hint.textContent = meta.hint;
  setText(el.risk, meta.score != null ? `Risk score ${meta.score.toFixed(2)} of 1` : "");
  setText(el.caveat, caveatFor(result, cls));
  setList(el.history, historyNotes(result));

  renderPeel(el.peel, payload.url || result.normalized_url || "");

  const facts = pageRows(result);
  el.page.classList.toggle("hidden", !facts);
  if (facts) {
    setText(el.reasoning, result.page.reasoning);
    renderRows(el.pageFacts, facts);
  }

  const signals = result.signals || [];
  setList(el.signals, signals);
  el.signalsLabel.classList.toggle("hidden", !signals.length);

  // The backend-unreachable placeholder has no scan behind it to repeat.
  el.rescan.classList.toggle("hidden", !result.scan_id);

  renderRows(el.tech, recordRows(result, cls));
}

el.rescan.addEventListener("click", () => {
  if (!current) return;
  el.rescan.disabled = true;
  setText(el.rescanStatus, "Running the full check again…");
  chrome.runtime.sendMessage(
    { type: "RESCAN", tabId: current.tabId, url: current.url || current.result.normalized_url },
    (reply) => {
      el.rescan.disabled = false;
      if (!reply || !reply.ok) {
        setText(el.rescanStatus, "Could not reach the Phisang API. The result above is unchanged.");
        return;
      }
      setText(el.rescanStatus, "");
      render(Object.assign({ tabId: current.tabId }, reply.payload));
    }
  );
});

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const tabId = tabs[0] && tabs[0].id;
  chrome.runtime.sendMessage({ type: "GET_TAB_RESULT", tabId }, (payload) => {
    render(payload && Object.assign({ tabId }, payload));
  });
});
