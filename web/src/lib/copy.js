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
    verdict: "Not listed",
    ripeness: "Ripe",
    hint: "No URLhaus match and no strong lexical risk. Not listed is not the same as safe.",
    tone: "text-forest",
    dot: "bg-peel",
    rots: false,
  },
  unavailable: {
    verdict: "Unread",
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
