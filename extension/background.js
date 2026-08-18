const allowedRoots = new Set();
const continueAnywayHosts = new Set();
const skipOnce = new Map();
const lastByTab = new Map();
const lastSafeUrl = new Map();
let protectionEnabled = true;

chrome.storage.local.get({ protectionEnabled: true }, (stored) => {
  protectionEnabled = stored.protectionEnabled !== false;
});
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.protectionEnabled) {
    protectionEnabled = changes.protectionEnabled.newValue !== false;
  }
});

function rootHost(host) {
  if (!host) return "";
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(":")) return host;
  const parts = host.split(".");
  if (parts.length <= 2) return host;
  return parts.slice(-2).join(".");
}

function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

function isIgnored(url) {
  if (!url) return true;
  if (
    url.startsWith("chrome://") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("about:") ||
    url.startsWith("devtools://") ||
    url.startsWith("edge://")
  ) {
    return true;
  }
  try {
    const parsed = new URL(url);
    const local = parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
    return local && parsed.port === "8000";
  } catch {
    return true;
  }
}

function isAllowed(host) {
  if (!host) return false;
  if (continueAnywayHosts.has(host) || continueAnywayHosts.has(rootHost(host))) return true;
  const root = rootHost(host);
  return allowedRoots.has(root) || allowedRoots.has(host);
}

function setBadge(tabId, classification) {
  const map = {
    malware: { text: "BLK", color: "#e26156" },
    phishing: { text: "PHS", color: "#e39a3c" },
    benign: { text: "OK", color: "#6b7280" },
    unavailable: { text: "?", color: "#8b7cf6" },
    checking: { text: "..", color: "#6cb3d9" },
  };
  const spec = map[classification] || { text: "", color: "#6b7280" };
  chrome.action.setBadgeText({ tabId, text: spec.text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: spec.color });
}

async function remember(tabId, url, result) {
  lastByTab.set(tabId, { url, result, at: Date.now() });
  await chrome.storage.session.set({ [`tab:${tabId}`]: { url, result } });
}

function checkingUrl(url, tabId) {
  return chrome.runtime.getURL(
    `checking.html?url=${encodeURIComponent(url)}&tabId=${tabId}`
  );
}

function blockedUrl() {
  return chrome.runtime.getURL("blocked.html");
}

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  if (isIgnored(details.url)) return;
  if (isAllowed(hostOf(details.url))) {
    lastSafeUrl.set(details.tabId, details.url);
  }
});

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (!protectionEnabled) return;
  if (details.frameId !== 0) return;
  const { tabId, url } = details;
  if (isIgnored(url)) return;

  if (skipOnce.get(tabId) === url) {
    skipOnce.delete(tabId);
    return;
  }

  const host = hostOf(url);
  if (isAllowed(host)) return;

  setBadge(tabId, "checking");
  chrome.tabs.update(tabId, { url: checkingUrl(url, tabId) });
});

chrome.tabs.onRemoved.addListener((tabId) => {
  lastByTab.delete(tabId);
  skipOnce.delete(tabId);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = message.tabId || sender.tab?.id;
  const handle = async () => {
    if (message.type === "ANALYSIS_RESULT") {
      const result = message.result;
      const url = message.url;
      await remember(tabId, url, result);
      setBadge(tabId, result.classification);

      if (result.classification === "malware" || result.classification === "phishing") {
        skipOnce.set(tabId, blockedUrl());
        await chrome.tabs.update(tabId, { url: blockedUrl() });
        return { ok: true };
      }

      skipOnce.set(tabId, url);
      if (result.classification === "benign") {
        allowedRoots.add(rootHost(hostOf(url)));
      }
      await chrome.tabs.update(tabId, { url });
      return { ok: true };
    }

    if (message.type === "ANALYSIS_ERROR") {
      const url = message.url;
      const result = {
        classification: "unavailable",
        confidence: 0,
        decision_stage: "error",
        normalized_url: url,
        signals: ["LinkGuard backend was unreachable"],
        limitations: ["This is a degraded result, not a clean one"],
        error_code: "threat_intel_unavailable",
      };
      await remember(tabId, url, result);
      setBadge(tabId, "unavailable");
      skipOnce.set(tabId, url);
      await chrome.tabs.update(tabId, { url });
      return { ok: true };
    }

    if (message.type === "GET_TAB_RESULT") {
      const stored = await chrome.storage.session.get(`tab:${tabId}`);
      return stored[`tab:${tabId}`] || lastByTab.get(tabId) || null;
    }

    if (message.type === "CONTINUE_ANYWAY") {
      const host = hostOf(message.url);
      continueAnywayHosts.add(host);
      skipOnce.set(tabId, message.url);
      await chrome.tabs.update(tabId, { url: message.url });
      return { ok: true };
    }

    if (message.type === "GO_BACK") {
      const previous = lastSafeUrl.get(tabId) || "chrome://newtab/";
      skipOnce.set(tabId, previous);
      await chrome.tabs.update(tabId, { url: previous });
      return { ok: true };
    }

    return { ok: false };
  };

  handle().then(sendResponse);
  return true;
});
