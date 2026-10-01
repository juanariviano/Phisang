/* Popup and warning page share the same scan/evidence behavior. */
(async function () {
  const { resultView, scanProgress, renderBanana, clearCache, cacheSize } = self.Phisang;
  const container = document.getElementById('result');
  const status = document.getElementById('status');
  const rescan = document.getElementById('rescan');
  const progressEl = document.getElementById('progress');
  const scanning = document.getElementById('scanning');
  let current, dispose, progress;
  const enabled = document.getElementById('enabled');
  if (enabled) {
    chrome.storage.local.get({ protectionEnabled: true }, stored => { enabled.checked = stored.protectionEnabled !== false; });
    enabled.addEventListener('change', () => chrome.storage.local.set({ protectionEnabled: enabled.checked }));
  }
  // Popup only: the local cache is shared by every tab, so it is cleared from the
  // toolbar rather than from a page's own warning.
  const clear = document.getElementById('clear-cache');
  const cacheStatus = document.getElementById('cache-status');
  if (clear) {
    const showCount = async () => {
      const count = await cacheSize();
      clear.disabled = !count;
      cacheStatus.textContent = count === 0
        ? 'No addresses are saved on this device. Every website is scanned before it opens.'
        : count === 1
          ? '1 address is saved as safe on this device. Visiting it again needs no scan.'
          : `${count} addresses are saved as safe on this device. Visiting them again needs no scan.`;
    };
    clear.addEventListener('click', async () => {
      clear.disabled = true;
      try {
        await clearCache();
        cacheStatus.textContent = 'Local cache cleared. The next visit to each address is scanned again.';
      } catch {
        clear.disabled = false;
        cacheStatus.textContent = 'The local cache could not be cleared. Try again.';
      }
    });
    showCount();
  }
  function render(payload) {
    dispose?.();
    current = payload;
    container.hidden = false;
    if (!payload?.result) {
      container.textContent = 'No scan yet. Open a website with protection enabled to check it.';
      return;
    }
    dispose = resultView(container, payload.result);
    document.getElementById('address').textContent = payload.url || payload.result.normalized_url || '';
    rescan.hidden = !payload.url && !payload.result.normalized_url;
    document.getElementById('navigation-actions')?.removeAttribute('hidden');
  }
  const listener = message => {
    if (message.type === 'SCAN_PROGRESS' && message.tabId === current?.tabId) progress?.update(message.progress);
  };
  chrome.runtime.onMessage.addListener(listener);
  window.addEventListener('pagehide', () => { dispose?.(); progress?.stop(); chrome.runtime.onMessage.removeListener(listener); });
  rescan.addEventListener('click', async () => {
    if (!current || rescan.disabled) return;
    dispose?.();
    rescan.disabled = true;
    status.textContent = '';
    container.hidden = true;
    scanning.hidden = false;
    renderBanana(scanning, 'checking', 104);
    progress = scanProgress(progressEl);
    try {
      const reply = await chrome.runtime.sendMessage({ type: 'RESCAN', tabId: current.tabId,
        url: current.url || current.result.normalized_url });
      if (!reply?.ok) throw new Error(reply?.message || 'The scan could not finish. Try again.');
      render({ ...reply.payload, tabId: current.tabId });
    } catch (error) {
      status.textContent = `${error.message} The previous result is shown below.`;
      render(current);
    } finally {
      rescan.disabled = false; scanning.hidden = true; progress.stop(); progress = null;
    }
  });
  for (const [id, type] of [['go-back', 'GO_BACK'], ['continue', 'CONTINUE_ANYWAY']]) {
    document.getElementById(id)?.addEventListener('click', () => {
      if (current) chrome.runtime.sendMessage({ type, tabId: current.tabId, url: current.url || current.result.normalized_url });
    });
  }
  try {
    const tabId = enabled ? (await chrome.tabs.query({ active: true, currentWindow: true }))[0]?.id : undefined;
    render(await chrome.runtime.sendMessage({ type: 'GET_TAB_RESULT', tabId }));
  } catch { status.textContent = 'Could not load the last scan. Reopen Phisang to try again.'; }
})();
