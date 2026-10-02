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
        ? 'No website results are saved on this device.'
        : count === 1
          ? '1 hostname has a saved result. Other paths reuse it; subdomains are checked separately.'
          : `${count} hostnames have saved results. Other paths reuse them; subdomains are checked separately.`;
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
  // Popup only: what the user has allowed has to be visible and revocable, or the
  // allowlist becomes a setting nobody can audit.
  const allowList = document.getElementById('allow-list');
  const allowStatus = document.getElementById('allow-status');
  async function showAllowed() {
    const reply = await chrome.runtime.sendMessage({ type: 'LIST_ALLOWED' });
    const allowed = reply?.entries || [];
    allowStatus.textContent = allowed.length
      ? `${allowed.length} ${allowed.length === 1 ? 'address opens' : 'addresses open'} without any scan, by your choice.`
      : 'None. Every address is scanned before it opens.';
    allowList.replaceChildren(...allowed.map(entry => {
      const item = document.createElement('li');
      const label = document.createElement('span');
      label.textContent = entry.url;
      const remove = document.createElement('button');
      remove.type = 'button';
      remove.textContent = 'Remove';
      remove.addEventListener('click', async () => {
        remove.disabled = true;
        await chrome.runtime.sendMessage({ type: 'FORGET_ALLOWED', key: entry.key });
        await showAllowed();
      });
      item.append(label, remove);
      return item;
    }));
  }
  if (allowList) showAllowed();
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
