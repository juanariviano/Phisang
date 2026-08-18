export const EXAMPLES = [
  { label: "Wikipedia", url: "https://www.wikipedia.org" },
  { label: "URLhaus sample", url: "http://77.73.133.113/lego/mine.exe" },
  { label: "Phishing-looking", url: "https://secure-login-paypal-verify.account-update.xyz/signin?session=unlock" },
];

export const CLASS_META = {
  malware: {
    title: "Malware",
    hint: "Known or likely malware distribution URL.",
    tone: "text-malware",
    wash: "bg-malware/10",
  },
  phishing: {
    title: "Phishing",
    hint: "The URL string looks like a credential or brand trap.",
    tone: "text-phishing",
    wash: "bg-phishing/10",
  },
  benign: {
    title: "Benign · not listed",
    hint: "No URLhaus match and no strong lexical risk. This is not a guarantee of safety.",
    tone: "text-benign",
    wash: "bg-benign/10",
  },
  unavailable: {
    title: "Unavailable",
    hint: "A required check failed. This is a degraded result, not a clean one.",
    tone: "text-unavailable",
    wash: "bg-unavailable/10",
  },
  checking: {
    title: "Checking",
    hint: "Lookup and analysis in progress.",
    tone: "text-checking",
    wash: "bg-checking/10",
  },
};
