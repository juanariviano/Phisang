const params = new URLSearchParams(location.search);
const url = params.get('url') || '';
const tabId = Number(params.get('tabId'));
const { renderBanana, scanProgress, analyzeUrl, cachedResult, isHighRisk } = self.Phisang;
renderBanana(document.getElementById('banana'), 'checking', 120);
document.getElementById('address').textContent = url;
const controller = new AbortController();
let progress = null;
window.addEventListener('pagehide', () => { controller.abort(); progress?.stop(); });
(async function () {
  try {
    const message = self.Phisang.fileUrlMessage(url);
    if (message) throw Object.assign(new Error(message), { code: 'unsupported_content' });
    // Reuse the hostname's verdict across paths. The background worker still
    // blocks high-risk cached results through the same rules as fresh results.
    const cached = await cachedResult(url);
    // A cached threat still asks the server: an admin may have approved the address
    // since, and only the server knows. Answering from its archive costs no page fetch.
    if (cached && !isHighRisk(cached)) {
      await chrome.runtime.sendMessage({ type: 'ANALYSIS_RESULT', tabId, url, result: cached });
      return;
    }
    progress = scanProgress(document.getElementById('progress'));
    let result;
    try {
      result = await analyzeUrl(url, { onProgress: progress.update, signal: controller.signal });
    } catch (error) {
      // Unreachable server: keep blocking on the cached threat rather than degrade to unknown.
      if (!cached || error.name === 'AbortError') throw error;
      result = cached;
    }
    await chrome.runtime.sendMessage({ type: 'ANALYSIS_RESULT', tabId, url, result });
  } catch (error) {
    if (error.name === 'AbortError') return;
    if (error.code === 'unsupported_content') {
      document.querySelector('h1').textContent = 'File scanning is not supported';
      document.querySelector('.result-heading p').textContent = 'This link was not scanned or opened.';
      document.getElementById('status').textContent = error.message;
      renderBanana(document.getElementById('banana'), 'unavailable', 120);
      const back = document.getElementById('unsupported-back');
      back.hidden = false;
      back.onclick = () => chrome.runtime.sendMessage({ type: 'GO_BACK', tabId, url });
      await chrome.runtime.sendMessage({ type: 'ANALYSIS_UNSUPPORTED', tabId, url });
      return;
    }
    document.getElementById('status').textContent = 'The scan could not finish. The risk is unknown.';
    await chrome.runtime.sendMessage({ type: 'ANALYSIS_ERROR', tabId, url });
  } finally { progress?.stop(); }
})();
