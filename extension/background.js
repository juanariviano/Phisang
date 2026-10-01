importScripts('content-guard.js', 'stream.js', 'api.js', 'verdicts.js', 'cache.js');
const { API_BASE, analyzeUrl, savedExplanation, verdictMeta, isHighRisk, rememberResult } = self.Phisang;
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
    if (!["http:", "https:"].includes(parsed.protocol)) return true;
    // Exempt only the scanner's exact origin (and its HTTP-to-HTTPS entry point),
    // never sibling domains or a lookalike hostname containing the same text.
    if (parsed.origin === API_BASE || parsed.origin === API_BASE.replace(/^https:/, "http:")) return true;
    const local = parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
    return local && ["8000", "5173"].includes(parsed.port);
  } catch {
    return true;
  }
}

function setBadge(tabId, classification, result) {
  // Palette-native badges. The toolbar icon is 16px, so the word carries the
  // state and the colour only reinforces it.
  const map = {
    malware: { text: "STOP", color: "#FFBF00" },
    phishing: { text: "RISK", color: "#E0A526" },
    benign: { text: "OK", color: "#467235" },
    unavailable: { text: "?", color: "#8AA37E" },
    checking: { text: "..", color: "#6FA355" },
  };
  let spec = map[classification] || { text: "", color: "#467235" };
  if (isHighRisk(result)) {
    spec = { text: "STOP", color: "#FFBF00" };
  } else if (classification === "benign" && result && verdictMeta(result, classification).bananaState !== "benign") {
    spec = { text: "!", color: "#E0A526" };
  }
  return Promise.all([
    chrome.action.setBadgeText({ tabId, text: spec.text }),
    chrome.action.setBadgeBackgroundColor({ tabId, color: spec.color }),
  ]).catch(() => {}); // The tab may have closed while the scan was running.
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

chrome.webNavigation.onCommitted.addListener(async ({ tabId, frameId, url }) => {
  if (frameId !== 0) return;
  // Chrome resets tab-specific badge state when navigation commits. Restore it
  // from the stored observation, including after a service-worker restart.
  if (url.startsWith(chrome.runtime.getURL("checking.html?"))) {
    await setBadge(tabId, "checking");
    return;
  }
  try {
    const stored = await chrome.storage.session.get(`tab:${tabId}`);
    const payload = stored[`tab:${tabId}`];
    if (payload?.result && (url === blockedUrl() || url === payload.url)) {
      await setBadge(tabId, payload.result.classification, payload.result);
    }
  } catch { /* A closing tab has no badge to restore. */ }
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

  // A one-visit permission must not linger after navigating somewhere else.
  skipOnce.delete(tabId);

  setBadge(tabId, "checking");
  chrome.tabs.update(tabId, { url: checkingUrl(url, tabId) });
});

chrome.tabs.onRemoved.addListener((tabId) => {
  lastByTab.delete(tabId);
  skipOnce.delete(tabId);
  lastSafeUrl.delete(tabId);
  chrome.storage.session.remove(`tab:${tabId}`);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = message.tabId ?? sender.tab?.id;
  const handle = async () => {
    if (message.type === "ANALYSIS_UNSUPPORTED") {
      const result = {
        classification: "unavailable", normalized_url: message.url,
        error_code: "unsupported_content", signals: [self.Phisang.FILE_MESSAGE],
      };
      await remember(tabId, message.url, result);
      await setBadge(tabId, "unavailable", result);
      return { ok: true }; // Leave the checking screen paused; do not open a file.
    }
    if (message.type === "ANALYSIS_RESULT") {
      const result = message.result;
      const url = message.url;
      await remember(tabId, url, result);
      // A result that came back out of the local cache must not keep renewing its
      // own lifetime, or an address scanned once would never be checked again.
      if (!result.served_from_local_cache) await rememberResult(url, result);
      setBadge(tabId, result.classification, result);

      if (isHighRisk(result)) {
        skipOnce.set(tabId, blockedUrl());
        await chrome.tabs.update(tabId, { url: blockedUrl() });
        return { ok: true };
      }

      skipOnce.set(tabId, url);
      if (result.classification === "benign") {
        lastSafeUrl.set(tabId, url);
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
        signals: ["Phisang backend was unreachable"],
        limitations: ["This is a degraded result, not a clean one"],
        error_code: "threat_intel_unavailable",
      };
      await remember(tabId, url, result);
      // An address we can no longer check does not stay released locally.
      await rememberResult(url, result);
      setBadge(tabId, "unavailable");
      skipOnce.set(tabId, url);
      await chrome.tabs.update(tabId, { url });
      return { ok: true };
    }

    if (message.type === "RESCAN") {
      // Same as the web scanner's rescan: skip the scan archive and run every gate.
      const url = message.url;
      try {
        const result = await analyzeUrl(url, {
          rescan: true,
          onProgress: progress => {
            chrome.runtime.sendMessage({ type: "SCAN_PROGRESS", tabId, progress }).catch(() => {});
          },
        });
        await remember(tabId, url, result);
        // Rescan always asks the server and replaces the hostname's verdict.
        await rememberResult(url, result);
        setBadge(tabId, result.classification, result);
        // A page that now reads as a threat is taken away from the user, as on first visit.
        if (isHighRisk(result)) {
          const tab = await chrome.tabs.get(tabId);
          if (tab.url !== blockedUrl()) {
            skipOnce.set(tabId, blockedUrl());
            await chrome.tabs.update(tabId, { url: blockedUrl() });
          }
        }
        return { ok: true, payload: { url, result } };
      } catch (error) {
        // Keep the last result visible, but retry automatically on the next visit.
        await rememberResult(url, null);
        return { ok: false, message: error.message || "The scan could not finish. Try again." };
      }
    }

    if (message.type === "GET_TAB_RESULT") {
      const stored = await chrome.storage.session.get(`tab:${tabId}`);
      const payload = stored[`tab:${tabId}`] || lastByTab.get(tabId) || null;
      if (payload?.result?.scan_id) {
        try {
          payload.result.explanation = await savedExplanation(payload.result);
        } catch { /* The last result remains readable while the API is offline. */ }
      }
      return payload ? { ...payload, tabId } : null;
    }

    if (message.type === "CONTINUE_ANYWAY") {
      skipOnce.set(tabId, message.url);
      await chrome.tabs.update(tabId, { url: message.url });
      return { ok: true };
    }

    if (message.type === "GO_BACK") {
      // A rescan can flag the same page that was previously allowed through.
      const candidate = lastSafeUrl.get(tabId);
      const previous = candidate && candidate !== message.url ? candidate : "chrome://newtab/";
      skipOnce.set(tabId, previous);
      await chrome.tabs.update(tabId, { url: previous });
      return { ok: true };
    }

    return { ok: false };
  };

  handle().then(sendResponse).catch(() => sendResponse({ ok: false, message: "The request could not finish. Try again." }));
  return true;
});
