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
      verdict: "Not listed",
      ripeness: "Ripe",
      hint: "No URLhaus match and no strong lexical risk.",
      badge: "Checked",
      caveat:
        "Not listed is not safe. It only means Phisang found no URLhaus match and no strong lexical risk — the page itself was never opened.",
      rots: false,
    },
    unavailable: {
      verdict: "Unread",
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

  self.Phisang = Object.assign(self.Phisang || {}, { VERDICTS });
})();
