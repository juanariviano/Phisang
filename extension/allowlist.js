/* Addresses this person decided to open whatever the scan says.

   This is the only store that can switch protection off, so it is deliberately
   narrow: one exact address per entry, written only by a confirmed action on an
   extension page, listed and removable in the popup, and never written by a scan.

   chrome.storage.local rather than IndexedDB: the service worker is terminated
   between events, so a database connection would have to be reopened on every
   wake and a transaction could be cut short mid-write. A few dozen entries need
   none of that, and both stores are per-profile and never synced. */
(function () {
  const STORE = 'userAllowlist';
  const MAX_ENTRIES = 200;

  // Narrower than the verdict cache's hostname key on purpose: allowing one
  // address must not release the rest of the site.
  function allowKey(url) {
    try {
      const parsed = new URL(url);
      if (!['http:', 'https:'].includes(parsed.protocol)) return null;
      parsed.username = '';
      parsed.password = '';
      const path = parsed.pathname.replace(/\/{2,}/g, '/').replace(/(?!^)\/+$/, '');
      return `${parsed.protocol}//${parsed.host}${path}${parsed.search}`;
    } catch {
      return null;
    }
  }

  async function entries() {
    try {
      const stored = await chrome.storage.local.get(STORE);
      const value = stored[STORE];
      return value && typeof value === 'object' ? value : {};
    } catch {
      return {}; // An unreadable allowlist means every address is scanned.
    }
  }

  /* True only for an exact address the user added. */
  async function isAllowed(url) {
    const key = allowKey(url);
    return key ? key in await entries() : false;
  }

  async function allowUrl(url) {
    const key = allowKey(url);
    if (!key) return null;
    const stored = await entries();
    stored[key] = { at: Date.now(), url };
    const keys = Object.keys(stored);
    for (const stale of keys.sort((a, b) => stored[a].at - stored[b].at)
        .slice(0, Math.max(0, keys.length - MAX_ENTRIES))) {
      delete stored[stale];
    }
    await chrome.storage.local.set({ [STORE]: stored });
    return key;
  }

  async function forgetUrl(key) {
    const stored = await entries();
    if (!(key in stored)) return false;
    delete stored[key];
    await chrome.storage.local.set({ [STORE]: stored });
    return true;
  }

  /* Newest first, so the popup shows the most recent decision at the top. */
  async function listAllowed() {
    const stored = await entries();
    return Object.entries(stored)
      .map(([key, entry]) => ({ key, url: entry.url || key, at: entry.at || 0 }))
      .sort((a, b) => b.at - a.at);
  }

  async function clearAllowed() {
    await chrome.storage.local.remove(STORE);
  }

  Object.assign(self.Phisang ||= {}, {
    allowKey, isAllowed, allowUrl, forgetUrl, listAllowed, clearAllowed,
  });
})();
