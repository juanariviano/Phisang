/**
 * Split a URL into its anatomical parts — the "peel".
 *
 * Notes attached to each strip are observations about the string, not verdicts.
 * The backend decides what a URL is; this only says what it is made of. Keeping
 * that line clear is why nothing here returns a risk score.
 */

const SHORTENERS = new Set([
  "bit.ly",
  "t.co",
  "goo.gl",
  "tinyurl.com",
  "ow.ly",
  "is.gd",
  "buff.ly",
  "cutt.ly",
  "rebrand.ly",
  "shorturl.at",
]);

const IP_LITERAL = /^(\d{1,3}\.){3}\d{1,3}$/;

function noteHost(host) {
  if (!host) return null;
  if (IP_LITERAL.test(host)) return "Bare IP address, no domain name";
  if (host.startsWith("xn--") || host.includes(".xn--")) return "Punycode — may render as another script";
  if (SHORTENERS.has(host.toLowerCase())) return "Known link shortener, destination hidden";
  // These describe the whole host, but the note renders on the registrable
  // domain strip — say so, or it reads as a claim about that strip alone.
  const labels = host.split(".");
  if (labels.length >= 5) return `Full host has ${labels.length} labels`;
  if (host.length > 40) return `Full host is ${host.length} characters`;
  return null;
}

function notePath(path) {
  if (!path || path === "/") return null;
  const file = path.split("/").pop() || "";
  const ext = file.includes(".") ? file.slice(file.lastIndexOf(".")).toLowerCase() : "";
  if ([".exe", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".jar", ".apk", ".dll", ".vbs"].includes(ext)) {
    return `Ends in ${ext} — an executable, not a page`;
  }
  if ([".zip", ".rar", ".7z", ".iso"].includes(ext)) return `Ends in ${ext} — an archive`;
  return null;
}

/**
 * @returns {{ valid: boolean, error?: string, parts: Array<{key:string,label:string,value:string,note:string|null}> }}
 */
export function peelUrl(raw) {
  const trimmed = (raw || "").trim();
  if (!trimmed) return { valid: false, parts: [] };

  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    // Give the strips something to show while the user is still typing.
    try {
      parsed = new URL(`https://${trimmed}`);
    } catch {
      return { valid: false, error: "Not a URL yet", parts: [] };
    }
  }

  const parts = [];

  parts.push({
    key: "scheme",
    label: "Scheme",
    value: `${parsed.protocol.replace(":", "")}://`,
    note: parsed.protocol === "http:" ? "Unencrypted" : null,
  });

  if (parsed.username || parsed.password) {
    parts.push({
      key: "userinfo",
      label: "Credentials",
      value: parsed.password ? `${parsed.username}:••••@` : `${parsed.username}@`,
      note: "Credentials in the address — often used to disguise the real host",
    });
  }

  const host = parsed.hostname;
  // An IP address has no subdomain or registrable domain — splitting 77.73.133.113
  // into "77.73." + "133.113" would invent a structure that is not there.
  const isIp = IP_LITERAL.test(host);
  const labels = host.split(".");
  const splittable = !isIp && labels.length > 2;
  const registrable = splittable ? labels.slice(-2).join(".") : host;
  const subdomain = splittable ? labels.slice(0, -2).join(".") : "";

  if (subdomain) {
    parts.push({
      key: "subdomain",
      label: "Subdomain",
      value: `${subdomain}.`,
      // "www" is a convention, not a claim about anything — no warning earned.
      note:
        subdomain === "www"
          ? "Conventional prefix"
          : "Anyone who owns the domain controls this — a brand name here proves nothing",
    });
  }

  parts.push({
    key: "host",
    label: isIp ? "Host (IP address)" : subdomain ? "Registrable domain" : "Host",
    value: registrable,
    note: noteHost(host),
  });

  if (parsed.port) {
    parts.push({ key: "port", label: "Port", value: `:${parsed.port}`, note: "Non-standard port" });
  }

  if (parsed.pathname && parsed.pathname !== "/") {
    parts.push({
      key: "path",
      label: "Path",
      value: parsed.pathname,
      note: notePath(parsed.pathname),
    });
  }

  if (parsed.search) {
    const count = [...new URLSearchParams(parsed.search).keys()].length;
    parts.push({
      key: "query",
      label: "Query",
      value: parsed.search,
      note: `${count} parameter${count === 1 ? "" : "s"}`,
    });
  }

  if (parsed.hash) {
    parts.push({ key: "fragment", label: "Fragment", value: parsed.hash, note: "Never sent to the server" });
  }

  return { valid: true, parts };
}
