/* Reuse completed verdicts across paths on the exact same hostname. Cached
   threats still block navigation; failed checks never become reusable verdicts.
   The original scanned URL and evidence ID remain attached to every result. */
(function () {
  // Separate from the old per-URL safeCache: old entries have a different scope.
  const STORE = 'hostVerdictCache';
  // Long enough to spare the API the repeat traffic of ordinary browsing, short
  // enough that a site compromised today is checked again today.
  const TTL_MS = 6 * 60 * 60 * 1000;
  // chrome.storage.local holds about 10 MB; a scan result is a few KB.
  const MAX_ENTRIES = 200;

  // Keep every subdomain distinct. Paths, queries, fragments, schemes and ports
  // share a verdict for this hostname; this does not change the API's URL key.
  function cacheKey(url) {
    try {
      const parsed = new URL(url);
      if (!['http:', 'https:'].includes(parsed.protocol)) return null;
      return parsed.hostname.toLowerCase().replace(/\.$/, '');
    } catch {
      return null;
    }
  }

  function isReusableResult(result) {
    if (!result || !['benign', 'phishing', 'malware'].includes(result.classification)) return false;
    if (self.Phisang.fileUrlMessage(result.normalized_url || '') ||
        self.Phisang.fileUrlMessage(result.page?.final_url || '')) return false;
    // A degraded check is unknown, never clean, so it is never kept.
    if (result.error_code || result.page?.status === 'unavailable') return false;
    return result.decision_stage !== 'error' && result.verdict !== 'unknown';
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
    if (self.Phisang.fileUrlMessage(url)) return null;
    const key = cacheKey(url);
    if (!key) return null;
    const stored = await entries();
    const entry = stored[key];
    if (!entry) return null;
    // Re-checked on the way out as well as in, so an entry written by an older
    // version of these rules cannot release an address today.
    if (!Number.isFinite(entry.at) || Date.now() - entry.at >= TTL_MS || !isReusableResult(entry.result)) {
      delete stored[key];
      await chrome.storage.local.set({ [STORE]: stored });
      return null;
    }
    return { ...entry.result, served_from_local_cache: true };
  }

  /* A fresh verdict replaces this hostname's entry; a failure invalidates it. */
  async function rememberResult(url, result) {
    if (self.Phisang.fileUrlMessage(url)) return;
    const key = cacheKey(url);
    if (!key) return;
    const stored = await entries();
    if (isReusableResult(result)) {
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
      return; // Nothing completed to keep and nothing stale to drop.
    }
    await chrome.storage.local.set({ [STORE]: stored });
  }

  async function clearCache() {
    await chrome.storage.local.remove(STORE);
    await chrome.storage.local.remove('safeCache');
  }

  async function cacheSize() {
    return Object.keys(await entries()).length;
  }

  Object.assign(self.Phisang ||= {}, { cacheKey, cachedResult, rememberResult, clearCache, cacheSize });
})();
