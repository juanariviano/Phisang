/**
 * Verdict vocabulary, shared by the popup and the blocked page.
 * Mirrors web/src/lib/copy.js.
 *
 * `verdict` is the plain security word and always leads. `ripeness` is the
 * banana reading of the same state and never appears alone — a threat label
 * has to be unambiguous before it is charming.
 *
 * The banana itself carries the state — it peels open only when Phisang found
 * something — so this file is just the words the UI puts next to it. `tilt` is fixed per
 * state, so the same verdict always sits the same way — placement is identity.
 */
(function () {
  const VERDICTS = {
    malware: {
      verdict: "Malware",
      ripeness: "Rotten",
      hint: "Known or likely malware distribution. Do not open this address.",
      badge: "Blocked",
      caveat: "Navigation was stopped before the page loaded.",
      /** The one state that bruises the whole surface. */
      rots: true,
    },
    phishing: {
      verdict: "Phishing",
      ripeness: "Spotted",
      hint: "The peel looks ordinary. The spots do not. This address is shaped like a credential trap.",
      badge: "Blocked",
      caveat: "Navigation was stopped before the page loaded.",
      rots: false,
    },
    benign: {
      verdict: "Safe",
      ripeness: "Ripe",
      hint: "Nothing suspicious was found.",
      badge: "Checked",
      caveat: "A low risk score is not a guarantee of safety.",
      rots: false,
    },
    unavailable: {
      verdict: "Risk unknown",
      ripeness: "Unpeeled",
      hint: "A required check failed, so Phisang will not call this address clean.",
      badge: "Degraded",
      caveat: "Degraded result: a required check failed. This is not a clean verdict.",
      rots: false,
    },
    checking: {
      verdict: "Peeling",
      ripeness: "Ripening",
      hint: "Splitting the address apart and running the three gates.",
      badge: "Checking",
      caveat: "",
      rots: false,
    },
  };

  // The risk level the API attaches to every scored result. It replaces the
  // classification word in the headline; the classification still drives the
  // banana and whether navigation is blocked.
  const RISK_HINTS = {
    SAFE: "Nothing suspicious was found.",
    "POTENTIALLY UNSAFE": "Mixed signals. Be careful before entering any details.",
    MALICIOUS:
      "Scored as malicious, but nothing else backed the score up, so it was not blocked. Do not enter any details.",
    "High Risk":
      "Scored as high risk, but nothing else backed the score up, so it was not blocked. Do not enter any details.",
  };

  /** Headline for a result: the risk level when there is one, else the classification word. */
  function verdictMeta(result, cls) {
    const base = VERDICTS[cls] || VERDICTS.unavailable;
    const level = result && result.risk_level;
    if (!RISK_HINTS[level]) return base;
    const blocked = cls === "malware" || cls === "phishing";
    return Object.assign({}, base, {
      verdict: level,
      score: result.risk_score,
      // A blocked result keeps its specific reason; the risk hint covers the rest.
      hint: blocked ? base.hint : RISK_HINTS[level],
    });
  }

  // Everything below mirrors web/src/components/ResultPanel.jsx, so the scanner
  // and the extension describe the same result in the same words.

  /** The one-line note under the verdict, chosen by how the result was reached. */
  function caveatFor(result, cls) {
    if (cls === "malware" || cls === "phishing") return "Do not open this address in a normal tab.";
    if (cls === "unavailable") {
      return "Degraded result. A feed or model check failed, so Phisang will not call this address clean.";
    }
    if (result.served_from_history) return "";
    if (result.decision_stage === "page") {
      return "A low risk score is not a guarantee. Phisang opened this page on its own server and scored its markup with a demo-grade model that can misread ordinary pages.";
    }
    return "A low risk score is not a guarantee. Phisang did not visit this page — it cleared a well-known host on the address string alone.";
  }

  /** Notes that only apply to answers served from the scan archive. */
  function historyNotes(result) {
    const notes = [];
    if (result.served_from_history) {
      const last = result.prior && result.prior.last_scanned_at;
      notes.push("Saved result — this request did not fetch the page again." +
        (last ? " Last scan: " + last + "." : ""));
    }
    if (result.verdict === "potentially_unsafe") {
      notes.push("Potentially unsafe — review the scan history before proceeding.");
    }
    return notes;
  }

  function recordRows(result, cls) {
    const intel = result.threat_intel || {};
    const heuristic = result.heuristic || {};
    return [
      ["Classification", cls],
      ["Confidence", result.confidence != null ? result.confidence + "%" : "—"],
      ["Risk score", result.risk_score != null ? result.risk_score.toFixed(2) : "—"],
      ["Decision stage", result.decision_stage || "—"],
      ["Scan ID", result.scan_id || "—"],
      ["URLhaus", intel.feed_status === "skipped" ? "Not checked" : intel.matched ? "Match" : "No match"],
      ["Threat", intel.threat_type || intel.feed_status || "—"],
      ["Heuristic", (heuristic.label || "skipped") + " · " + (heuristic.confidence != null ? heuristic.confidence : "—") + "%"],
      ["Policy", result.policy_version || "—"],
    ];
  }

  /** Rows for "The page we opened", or null when the page was not fetched. */
  function pageRows(result) {
    const page = result.page;
    if (!page || page.status !== "ok") return null;
    const signals = page.page_signals || {};
    const rows = [
      // page_title comes from the fetched page: always set as text, never markup.
      ["Page title", page.page_title || "—"],
      ["HTTP status", page.http_status != null ? String(page.http_status) : "—"],
      ["Phishing score", (page.phishing_score != null ? page.phishing_score.toFixed(3) : "—") +
        " / " + (page.threshold != null ? page.threshold : "—")],
      ["Password fields", (signals.password_inputs != null ? signals.password_inputs : "—") +
        " in " + (signals.forms != null ? signals.forms : "—") + " form(s)"],
    ];
    if (page.final_url && page.final_url !== result.normalized_url) {
      rows.push(["Redirected to", page.final_url]);
    }
    rows.push(["Markup model", page.model_name || "—"]);
    return rows;
  }

  /** Fill a <dl> with label/value rows, as text only. */
  function renderRows(dl, rows) {
    dl.replaceChildren(...rows.map(([label, value]) => {
      const row = document.createElement("div");
      const dt = document.createElement("dt");
      const dd = document.createElement("dd");
      dt.textContent = label;
      dd.textContent = value;
      row.append(dt, dd);
      return row;
    }));
  }

  self.Phisang = Object.assign(self.Phisang || {}, {
    VERDICTS, verdictMeta, caveatFor, historyNotes, recordRows, pageRows, renderRows,
  });
})();
