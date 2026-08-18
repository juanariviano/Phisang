/**
 * Splits a URL into its anatomical parts — the "peel".
 *
 * Mirrors web/src/lib/peel.js. Notes are observations about the string, never
 * verdicts: the backend decides what a URL is, this only says what it is made
 * of. Loaded as a classic script by popup.html and blocked.html.
 */
(function () {
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
  const EXECUTABLE = [".exe", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".jar", ".apk", ".dll", ".vbs"];
  const ARCHIVE = [".zip", ".rar", ".7z", ".iso"];

  function noteHost(host) {
    if (!host) return null;
    if (IP_LITERAL.test(host)) return "Bare IP address, no domain name";
    if (host.startsWith("xn--") || host.includes(".xn--")) {
      return "Punycode — may render as another script";
    }
    if (SHORTENERS.has(host.toLowerCase())) return "Known link shortener, destination hidden";
    // These describe the whole host, but the note renders on the registrable
    // domain strip — say so, or it reads as a claim about that strip alone.
    const labels = host.split(".");
    if (labels.length >= 5) return "Full host has " + labels.length + " labels";
    if (host.length > 40) return "Full host is " + host.length + " characters";
    return null;
  }

  function notePath(path) {
    if (!path || path === "/") return null;
    const file = path.split("/").pop() || "";
    const ext = file.includes(".") ? file.slice(file.lastIndexOf(".")).toLowerCase() : "";
    if (EXECUTABLE.includes(ext)) return "Ends in " + ext + " — an executable, not a page";
    if (ARCHIVE.includes(ext)) return "Ends in " + ext + " — an archive";
    return null;
  }

  function peelUrl(raw) {
    const trimmed = (raw || "").trim();
    if (!trimmed) return { valid: false, parts: [] };

    let parsed;
    try {
      parsed = new URL(trimmed);
    } catch (_) {
      try {
        parsed = new URL("https://" + trimmed);
      } catch (_e) {
        return { valid: false, parts: [] };
      }
    }

    const parts = [];

    parts.push({
      key: "scheme",
      label: "Scheme",
      value: parsed.protocol.replace(":", "") + "://",
      note: parsed.protocol === "http:" ? "Unencrypted" : null,
    });

    if (parsed.username || parsed.password) {
      parts.push({
        key: "userinfo",
        label: "Credentials",
        value: parsed.password ? parsed.username + ":••••@" : parsed.username + "@",
        note: "Credentials in the address — often used to disguise the real host",
      });
    }

    const host = parsed.hostname;
    // An IP address has no subdomain or registrable domain — splitting
    // 77.73.133.113 into "77.73." + "133.113" invents structure that is not there.
    const isIp = IP_LITERAL.test(host);
    const labels = host.split(".");
    const splittable = !isIp && labels.length > 2;
    const registrable = splittable ? labels.slice(-2).join(".") : host;
    const subdomain = splittable ? labels.slice(0, -2).join(".") : "";

    if (subdomain) {
      parts.push({
        key: "subdomain",
        label: "Subdomain",
        value: subdomain + ".",
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
      parts.push({ key: "port", label: "Port", value: ":" + parsed.port, note: "Non-standard port" });
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
      const count = Array.from(new URLSearchParams(parsed.search).keys()).length;
      parts.push({
        key: "query",
        label: "Query",
        value: parsed.search,
        note: count + " parameter" + (count === 1 ? "" : "s"),
      });
    }

    if (parsed.hash) {
      parts.push({
        key: "fragment",
        label: "Fragment",
        value: parsed.hash,
        note: "Never sent to the server",
      });
    }

    return { valid: true, parts };
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;");
  }

  /** Renders the peel into `container`. Returns the number of strips drawn. */
  function renderPeel(container, url) {
    const { valid, parts } = peelUrl(url);
    if (!container) return 0;
    if (!valid || !parts.length) {
      container.innerHTML = '<li class="peel-empty">No address to peel yet</li>';
      return 0;
    }
    container.innerHTML = parts
      .map(
        (part, index) =>
          '<li class="peel-strip" style="animation-delay:' +
          index * 40 +
          'ms"><span class="peel-label">' +
          escapeHtml(part.label) +
          '</span><span class="peel-value">' +
          escapeHtml(part.value) +
          "</span>" +
          (part.note ? '<span class="peel-note">' + escapeHtml(part.note) + "</span>" : "") +
          "</li>"
      )
      .join("");
    return parts.length;
  }

  self.Phisang = { peelUrl, renderPeel, escapeHtml };
})();
