const params = new URLSearchParams(location.search);
const url = params.get('url') || '';
const tabId = Number(params.get('tabId'));
const { renderBanana, scanProgress, analyzeUrl, cachedResult } = self.Phisang;
renderBanana(document.getElementById('banana'), 'checking', 120);
document.getElementById('address').textContent = url;
const controller = new AbortController();
let progress = null;
window.addEventListener('pagehide', () => { controller.abort(); progress?.stop(); });
(async function () {
  try {
    // An address this browser already saw cleared is released from the local
    // cache, so ordinary repeat browsing never reaches the scanner.
    const cached = await cachedResult(url);
    if (cached) {
      await chrome.runtime.sendMessage({ type: 'ANALYSIS_RESULT', tabId, url, result: cached });
      return;
    }
    progress = scanProgress(document.getElementById('progress'));
    const result = await analyzeUrl(url, { onProgress: progress.update, signal: controller.signal });
    await chrome.runtime.sendMessage({ type: 'ANALYSIS_RESULT', tabId, url, result });
  } catch (error) {
    if (error.name === 'AbortError') return;
    document.getElementById('status').textContent = 'The scan could not finish. The risk is unknown.';
    await chrome.runtime.sendMessage({ type: 'ANALYSIS_ERROR', tabId, url });
  } finally { progress?.stop(); }
})();
