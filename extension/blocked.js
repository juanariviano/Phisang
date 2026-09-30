const {
  verdictMeta, historyNotes, recordRows, pageRows, renderRows, renderBanana, renderPeel,
} = self.Phisang;

const TITLES = {
  malware: "This address serves malware",
  phishing: "This address is shaped like a trap",
};

// Whether the page was opened decides the second sentence: only the page stage
// fetched it, and then on Phisang's server, never in this tab.
function summaryFor(cls, result) {
  const lead = cls === "malware"
    ? "URLhaus or Phisang classified this destination as malware."
    : "Phisang stopped the navigation so you can read why this address looks unsafe.";
  const how = result.decision_stage === "page"
    ? "Phisang opened the page on its own server, in a locked-down browser — never in this tab."
    : "The page was never fetched — the verdict comes from the address and the threat feed.";
  return lead + " " + how;
}

function show(id, text) {
  document.getElementById(id).textContent = text || "";
}

chrome.runtime.sendMessage({ type: "GET_TAB_RESULT" }, (payload) => {
  const result = (payload && payload.result) || {};
  const url = (payload && payload.url) || result.normalized_url || "";
  const cls = result.classification === "phishing" ? "phishing" : "malware";
  const meta = verdictMeta(result, cls);
  renderBanana(document.getElementById("banana"), cls, 120);

  document.body.classList.remove("is-malware");
  document.body.classList.add("is-" + cls);

  show("verdict", meta.verdict);
  show("ripeness", meta.ripeness);
  show("eyebrow", "Navigation stopped");
  show("title", TITLES[cls]);
  show("summary", summaryFor(cls, result));

  const notes = historyNotes(result);
  const history = document.getElementById("history");
  history.replaceChildren(...notes.map((note) => {
    const li = document.createElement("li");
    li.textContent = note;
    return li;
  }));
  history.classList.toggle("hidden", !notes.length);

  renderPeel(document.getElementById("peel"), url);

  const facts = pageRows(result);
  if (facts) {
    document.getElementById("page").classList.remove("hidden");
    show("reasoning", result.page.reasoning);
    renderRows(document.getElementById("page-facts"), facts);
  }

  const signals = result.signals || [];
  if (signals.length) {
    document.getElementById("signals").replaceChildren(...signals.map((item) => {
      const li = document.createElement("li");
      li.textContent = item;
      return li;
    }));
  } else {
    document.getElementById("signals-label").classList.add("hidden");
  }

  const intel = result.threat_intel || {};
  renderRows(document.getElementById("tech"), recordRows(result, cls).concat([
    ["First seen", intel.first_seen || "—"],
  ]));

  document.getElementById("go-back").addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "GO_BACK", url });
  });
  document.getElementById("continue").addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "CONTINUE_ANYWAY", url });
  });
});
