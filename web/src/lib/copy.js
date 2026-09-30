export const CLASS_META = {
  malware: { bananaState: "rotten", verdict: "High risk", hint: "This address appears in a threat database. Avoid opening it or downloading files.", tone: "text-bruise", dot: "bg-bruise", rots: true },
  phishing: { bananaState: "rotten", verdict: "High risk", hint: "The scan found signs associated with phishing. Avoid sharing passwords or payment details.", tone: "text-rot", dot: "pat-speckle" },
  benign: { bananaState: "benign", verdict: "No clear warning", hint: "These checks found no clear threat. This is not a guarantee of safety.", tone: "text-forest", dot: "bg-peel" },
  unavailable: { bananaState: "unavailable", verdict: "Couldn’t check this site", hint: "A required check could not finish, so the risk is unknown. Try scanning again later.", tone: "text-leaf", dot: "pat-hatch" },
  checking: { bananaState: "checking", verdict: "Checking the link", hint: "Checking for known threats and gathering information about the website.", tone: "text-leaf", dot: "bg-leaf" },
};

// Shared with the extension: the displayed high-risk verdict is also its stop rule.
export function isHighRisk(result, cls = result?.classification) {
  if (!result || cls === "unavailable") return false;
  return cls === "malware" || cls === "phishing" || result.verdict === "malicious"
    || (result.risk_score ?? 0) >= 0.6;
}

export function verdictMeta(result, cls) {
  const base = CLASS_META[cls] || CLASS_META.unavailable;
  if (!result || cls === "unavailable" || cls === "malware") return base;
  if (isHighRisk(result, cls)) {
    return { ...CLASS_META.phishing, hint: cls === "benign"
      ? "The page model flagged this site, while other checks found less evidence. Be cautious and avoid sharing sensitive details."
      : CLASS_META.phishing.hint };
  }
  if (result.verdict === "potentially_unsafe" || (result.risk_score ?? 0) >= 0.4) {
    return { ...base, verdict: "Be cautious", bananaState: "phishing", tone: "text-rot", dot: "pat-speckle",
      hint: result.prior?.ever_malicious ? "An earlier scan flagged this address. Verify it independently before sharing any details."
        : "The checks found mixed signals. Verify the website before sharing personal details." };
  }
  return base;
}
