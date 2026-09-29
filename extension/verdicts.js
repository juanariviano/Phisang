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

  self.Phisang = Object.assign(self.Phisang || {}, { VERDICTS, verdictMeta });
})();
