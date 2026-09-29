export const EXAMPLES = [
  { label: "Wikipedia", url: "https://www.wikipedia.org" },
  { label: "URLhaus sample", url: "http://77.73.133.113/lego/mine.exe" },
  {
    label: "Phishing-looking",
    url: "https://secure-login-paypal-verify.account-update.xyz/signin?session=unlock",
  },
];

/**
 * Verdict leads with the plain security word. `ripeness` is the banana reading
 * of the same state and never appears on its own — a threat label has to be
 * unambiguous before it is charming.
 *
 * The banana itself carries the state: it peels open only when Phisang found
 * something. `dot` is the miniature used in the recent-scans list, and every
 * state pairs its hue with a pattern or shape so colour never signals alone.
 */
export const CLASS_META = {
  malware: {
    verdict: "Malware",
    ripeness: "Rotten",
    hint: "Known or likely malware distribution. Do not open this address.",
    tone: "text-bruise",
    dot: "bg-bruise",
    /** Malware is the one state that darkens the whole panel. */
    rots: true,
  },
  phishing: {
    verdict: "Phishing",
    ripeness: "Spotted",
    hint: "The peel looks ordinary. The spots do not. This address is shaped like a credential trap.",
    tone: "text-rot",
    dot: "pat-speckle",
    rots: false,
  },
  benign: {
    verdict: "Safe",
    ripeness: "Ripe",
    hint: "Nothing suspicious was found. That is not a guarantee of safety.",
    tone: "text-forest",
    dot: "bg-peel",
    rots: false,
  },
  unavailable: {
    verdict: "Risk unknown",
    ripeness: "Unpeeled",
    hint: "A required check failed, so Phisang will not call this address clean.",
    tone: "text-leaf",
    dot: "pat-hatch",
    rots: false,
  },
  checking: {
    verdict: "Peeling",
    ripeness: "Ripening",
    hint: "Splitting the address apart and running the three gates.",
    tone: "text-leaf",
    dot: "bg-leaf",
    rots: false,
  },
};

/**
 * The risk level the API attaches to every scored result. It replaces the
 * classification word in the headline; the classification still drives the
 * banana and whether navigation is blocked.
 */
export const RISK_META = {
  SAFE: {
    tone: "text-forest",
    dot: "bg-peel",
    hint: "Nothing suspicious was found. That is not a guarantee of safety.",
  },
  "POTENTIALLY UNSAFE": {
    tone: "text-leaf",
    dot: "pat-hatch",
    hint: "Mixed signals. Be careful before entering any details.",
  },
  MALICIOUS: {
    tone: "text-rot",
    dot: "pat-speckle",
    hint: "Scored as malicious, but nothing else backed the score up, so it was not blocked. Do not enter any details.",
  },
  "High Risk": {
    tone: "text-bruise",
    dot: "bg-bruise",
    hint: "Scored as high risk, but nothing else backed the score up, so it was not blocked. Do not enter any details.",
  },
};

/** Headline for a result: the risk level when there is one, else the classification word. */
export function verdictMeta(result, cls) {
  const base = CLASS_META[cls] || CLASS_META.unavailable;
  const risk = result && RISK_META[result.risk_level];
  if (!risk) return base;
  const blocked = cls === "malware" || cls === "phishing";
  return {
    ...base,
    verdict: result.risk_level,
    score: result.risk_score,
    tone: risk.tone,
    dot: risk.dot,
    // A blocked result keeps its specific reason; the risk hint covers the rest.
    hint: blocked ? base.hint : risk.hint,
  };
}
