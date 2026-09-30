/* Shared, text-only result UI for the popup and navigation warning. */
(function () {
  const { API_BASE, readExplanationStream, renderBanana, verdictMeta } = self.Phisang;
  function node(tag, text, className) {
    const el = document.createElement(tag);
    if (text != null) el.textContent = text;
    if (className) el.className = className;
    return el;
  }
  function rows(items) {
    const dl = node('dl', null, 'info-rows');
    for (const [key, value] of items) {
      if (value == null || value === '') continue;
      dl.append(node('dt', key), node('dd', String(value)));
    }
    return dl;
  }
  function list(items) {
    const ul = node('ul');
    for (const item of items || []) ul.append(node('li', item));
    return ul;
  }
  function details(title, contents) {
    const el = node('details');
    el.append(node('summary', title), ...contents);
    return el;
  }
  function scanProgress(container) {
    container.hidden = false;
    const started = Date.now();
    const timerText = node('span', '0s elapsed');
    const header = node('div', null, 'progress-heading');
    header.append(node('span', 'Scan in progress'), timerText);
    const bar = node('div', null, 'progress-track');
    bar.setAttribute('role', 'progressbar');
    bar.setAttribute('aria-label', 'Scan in progress');
    bar.append(node('div', null, 'scan-progress-fill'));
    const stages = node('ul', null, 'progress-stages');
    stages.setAttribute('role', 'status');
    const waiting = node('p', 'Connecting to the scanner…', 'fine');
    container.replaceChildren(header, bar, waiting, stages);
    const entries = new Map();
    const timer = setInterval(() => { timerText.textContent = `${Math.floor((Date.now() - started) / 1000)}s elapsed`; }, 1000);
    function update(stage) {
      waiting.hidden = true;
      let item = entries.get(stage.stage);
      if (!item) { item = node('li'); entries.set(stage.stage, item); stages.append(item); }
      item.dataset.status = stage.status;
      item.replaceChildren(node('strong', `${stage.status === 'complete' ? '✓ ' : ''}${stage.label}${stage.status === 'unavailable' ? ' — unavailable' : ''}`));
      if (stage.status === 'running' && stage.detail) item.append(node('p', stage.detail));
    }
    return { update, stop() { clearInterval(timer); container.hidden = true; container.replaceChildren(); } };
  }
  function resultView(container, result) {
    const abort = new AbortController();
    container.replaceChildren();
    const meta = verdictMeta(result, result.classification);
    const heading = node('div', null, 'result-heading');
    const art = node('div', null, 'banana-slot');
    renderBanana(art, meta.bananaState, 104);
    const words = node('div');
    words.append(node('h1', meta.verdict), node('p', meta.hint));
    heading.append(art, words);
    container.append(heading);
    if (result.classification !== 'unavailable' && Number.isFinite(result.risk_score) && result.risk_score >= 0 && result.risk_score <= 1) {
      const percent = Math.round(result.risk_score * 100);
      const risk = node('div', null, 'risk-meter');
      risk.setAttribute('role', 'meter'); risk.setAttribute('aria-label', 'Estimated risk');
      risk.setAttribute('aria-valuemin', '0'); risk.setAttribute('aria-valuemax', '100'); risk.setAttribute('aria-valuenow', percent);
      risk.append(node('strong', `${percent}%`), node('span', ' Estimated risk · an estimate, not a guarantee'));
      container.append(risk);
    }
    if (result.served_from_history) container.append(node('p', 'Saved result. Rescan to check the website again.', 'fine'));
    if (result.classification === 'unavailable' || result.error_code || result.page?.status === 'unavailable') {
      container.append(node('p', 'This result will not be reused. Your next scan will try again.', 'fine'));
    }
    const id = encodeURIComponent(result.evidence_scan_id || result.scan_id || '');
    if (result.page?.preview_available && id) {
      const figure = node('figure', null, 'preview');
      const img = node('img');
      img.alt = 'Website preview captured during this scan';
      img.src = `${API_BASE}/api/v1/scans/${id}/preview`;
      img.addEventListener('error', () => figure.replaceChildren(node('p', 'Preview unavailable.', 'fine')), { once: true });
      figure.append(img, node('figcaption', 'Captured during the scan. The live page may look different.'));
      container.append(figure);
    }
    if (result.scan_id) {
      const box = node('div', null, 'explain');
      const button = node('button', 'Explain this result');
      button.type = 'button';
      const note = node('p', 'Explain sends these scan findings and any captured preview to the AI explanation provider.', 'fine');
      const error = node('p', null, 'error'); error.setAttribute('role', 'alert');
      const answer = node('section', null, 'explanation');
      answer.setAttribute('aria-label', 'Explanation'); answer.hidden = true;
      const draw = (data, completed) => {
        answer.hidden = false;
        answer.setAttribute('aria-busy', String(!completed));
        answer.replaceChildren(node('h2', 'Why this result?'), node('p', data.summary || ''), list(data.reasons));
        if (data.advice?.length) answer.append(node('h3', 'What you can do'), list(data.advice));
        answer.append(node('p', completed ? `AI-generated from this scan${data.included_screenshot ? ' and its preview' : ''}. It may make mistakes.` : 'Writing explanation…', 'fine'));
      };
      button.addEventListener('click', async () => {
        button.disabled = true; button.textContent = 'Starting explanation…'; error.textContent = ''; answer.hidden = true;
        try {
          const response = await fetch(`${API_BASE}/api/v1/scans/${id}/explain`, {
            method: 'POST', headers: { Accept: 'text/event-stream' }, signal: abort.signal,
          });
          await readExplanationStream(response, { onSnapshot: data => draw(data, false), onDone: data => {
            result.explanation = data; draw(data, true); button.hidden = true; note.hidden = true;
          } });
        } catch (err) {
          if (err.name !== 'AbortError') {
            error.textContent = err.message || 'The explanation could not finish. Try again.';
            if (!answer.hidden) error.textContent += ' The explanation below is incomplete.';
            button.textContent = 'Try Explain again';
          }
        } finally { button.disabled = false; answer.setAttribute('aria-busy', 'false'); }
      });
      if (result.explanation) { draw(result.explanation, true); button.hidden = true; note.hidden = true; }
      box.append(button, note, error, answer); container.append(box);
    }
    if (meta.bananaState === 'rotten' || meta.bananaState === 'phishing') {
      const report = node('button', 'Report false positive', 'secondary');
      report.type = 'button';
      // UI only: connect to the reporting flow when it is implemented.
      container.append(report);
    }
    const info = result.domain_info;
    container.append(details('About this domain', info?.status === 'ok' ? [rows([
      ['Domain', info.domain], ['Registered', formatDate(info.registered_at)], ['Expires', formatDate(info.expires_at)],
      ['Registrar', info.registrar], ['Name servers', info.nameservers?.join(', ')],
    ]), node('p', 'Registration details alone do not prove that a website is safe or harmful.', 'fine')] : [
      node('p', info?.status === 'not_applicable' ? 'No domain registration record applies to this address.' : 'Registration information was unavailable.')
    ]));
    container.append(details('Scan details', [rows([
      ['Address checked', result.normalized_url], ['Final address', result.page?.final_url], ['Page title', result.page?.page_title],
      ['Scanned', formatDate(result.scanned_at)], ['Page check', result.page?.status || 'skipped'],
      ['Scan ID', result.scan_id],
    ]), list(result.signals)]));
    return () => abort.abort();
  }
  function formatDate(value) {
    const date = value ? new Date(value) : null;
    return date && !Number.isNaN(date.getTime()) ? date.toLocaleString() : 'Not available';
  }
  Object.assign(self.Phisang, { node, resultView, scanProgress });
})();
