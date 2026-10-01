/* Local verdict cache.

   An address this browser already saw cleared is answered from
   chrome.storage.local, so repeat browsing costs no scan request: no SQL read on
   the server and no round trip to wait for. Only results the shared verdict rules
   read as plainly safe are kept, every entry expires, and a scan that finds
   anything else removes it again. Nothing here can clear an address on its own —
   a cache hit only repeats a verdict the API already gave this browser. */
(function () {
  const STORE = 'safeCache';
  // Long enough to spare the API the repeat traffic of ordinary browsing, short
  // enough that a site compromised today is checked again today.
  const TTL_MS = 6 * 60 * 60 * 1000;
  // chrome.storage.local holds about 10 MB; a scan result is a few KB.
  const MAX_ENTRIES = 200;

  // Close enough to the API's own normalization that one link is one entry:
  // credentials, the default port and a trailing slash go, and the fragment stays
  // because the API treats it as part of the address it looked up.
  function cacheKey(url) {
    try {
      const parsed = new URL(url);
      if (!['http:', 'https:'].includes(parsed.protocol)) return null;
      parsed.username = '';
      parsed.password = '';
      const path = parsed.pathname.replace(/\/{2,}/g, '/').replace(/(?!^)\/+$/, '');
      return `${parsed.protocol}//${parsed.host}${path}${parsed.search}${parsed.hash}`;
    } catch {
      return null;
    }
  }

  function isSafeResult(result) {
    const { verdictMeta, isHighRisk } = self.Phisang;
    if (!result || result.classification !== 'benign') return false;
    // A degraded check is unknown, never clean, so it is never kept.
    if (result.error_code || result.page?.status === 'unavailable') return false;
    if (isHighRisk(result)) return false;
    // An address an earlier scan called malicious is never kept: the API's own
    // archive reports it as potentially unsafe on the next lookup, and this cache
    // must never be more permissive than the server it stands in for.
    if (result.prior?.ever_malicious) return false;
    // Mixed signals read as "Be cautious", which is not a safe result either.
    return verdictMeta(result, result.classification).bananaState === 'benign';
  }

  async function entries() {
    try {
      const stored = await chrome.storage.local.get(STORE);
      const value = stored[STORE];
      return value && typeof value === 'object' ? value : {};
    } catch {
      return {}; // An unreadable cache just means every address is scanned.
    }
  }

  /* The stored result for this address, or null when it must be scanned. */
  async function cachedResult(url) {
    const key = cacheKey(url);
    if (!key) return null;
    const stored = await entries();
    const entry = stored[key];
    if (!entry) return null;
    // Re-checked on the way out as well as in, so an entry written by an older
    // version of these rules cannot release an address today.
    if (Date.now() - entry.at >= TTL_MS || !isSafeResult(entry.result)) {
      delete stored[key];
      await chrome.storage.local.set({ [STORE]: stored });
      return null;
    }
    return { ...entry.result, served_from_local_cache: true };
  }

  /* Keep a safe result, or drop the address once it reads as anything else. */
  async function rememberResult(url, result) {
    const key = cacheKey(url);
    if (!key) return;
    const stored = await entries();
    if (isSafeResult(result)) {
      const saved = { ...result };
      delete saved.served_from_local_cache;
      stored[key] = { at: Date.now(), url, result: saved };
      const keys = Object.keys(stored);
      // Math.max matters: slice with a negative end counts back from the end and
      // would drop entries the cache is nowhere near needing to evict.
      const excess = Math.max(0, keys.length - MAX_ENTRIES);
      for (const stale of keys.sort((a, b) => stored[a].at - stored[b].at).slice(0, excess)) {
        delete stored[stale];
      }
    } else if (key in stored) {
      delete stored[key];
    } else {
      return; // Nothing safe to keep and nothing stale to drop.
    }
    await chrome.storage.local.set({ [STORE]: stored });
  }

  async function clearCache() {
    await chrome.storage.local.remove(STORE);
  }

  async function cacheSize() {
    return Object.keys(await entries()).length;
  }

  Object.assign(self.Phisang ||= {}, { cacheKey, cachedResult, rememberResult, clearCache, cacheSize });
})();
