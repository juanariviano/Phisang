/* Shared, text-only result UI for the popup and navigation warning. */
(function () {
  const { API_BASE, readExplanationStream, renderBanana, riskBand, verdictMeta, reportFalsePositive } = self.Phisang;
  // Matches FalsePositiveReportRequest.reason on the API, so the field cannot
  // accept text the server would reject.
  const REASON_LIMIT = 1000;
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
      const band = riskBand(result.risk_score);
      const risk = node('div', null, 'risk-meter');
      risk.dataset.band = band.key;
      risk.setAttribute('role', 'meter'); risk.setAttribute('aria-label', 'Estimated risk');
      risk.setAttribute('aria-valuemin', '0'); risk.setAttribute('aria-valuemax', '100'); risk.setAttribute('aria-valuenow', percent);
      risk.setAttribute('aria-valuetext', `${percent}%, ${band.label.toLowerCase()} risk`);
      risk.append(node('strong', `${percent}%`), node('b', band.label, 'risk-band'),
        node('span', ' Estimated risk · an estimate, not a guarantee'));
      container.append(risk);
    }
    if (result.served_from_local_cache) {
      container.append(node('p', 'Using an earlier result for this hostname. This page was not scanned again. Rescan to check this address.', 'fine'));
      if (result.normalized_url) container.append(rows([['Previously scanned URL', result.normalized_url]]));
    } else if (result.served_from_history) {
      container.append(node('p', 'Saved result. Rescan to check the website again.', 'fine'));
    }
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
      // Switching protection off for an address is a decision, not a click, so it
      // takes a second deliberate press and says plainly what it gives up.
      const box = node('div', null, 'report');
      const allow = node('button', 'Mark this address as safe', 'secondary');
      allow.type = 'button';
      const note = node('p', 'Future visits to this exact address will open without any scan, even if a scan would call it malicious. Remove it any time from the Phisang popup.', 'fine');
      let armed = false;
      allow.addEventListener('click', async () => {
        if (!armed) {
          armed = true;
          allow.textContent = 'Confirm: always open this address';
          note.className = 'error';
          return;
        }
        allow.disabled = true;
        try {
          const reply = await chrome.runtime.sendMessage({ type: 'ALLOW_URL',
            url: result.normalized_url || location.href });
          if (!reply?.ok) throw new Error(reply?.message || 'This address could not be allowed.');
          allow.hidden = true;
          note.className = 'fine';
          note.textContent = 'Allowed. This address will open without a scan until you remove it in the popup.';
        } catch (error) {
          note.className = 'error';
          note.textContent = error.message || 'This address could not be allowed.';
          allow.textContent = 'Try again';
          armed = false;
        } finally { allow.disabled = false; }
      });
      box.append(allow, note);
      container.append(box);
    }
    if ((meta.bananaState === 'rotten' || meta.bananaState === 'phishing') && id) {
      // A report a human has to review is only worth filing with a reason, so the
      // button opens a note first rather than sending an empty one.
      const box = node('div', null, 'report');
      const open = node('button', 'Report false positive', 'secondary');
      open.type = 'button';
      const form = node('div', null, 'report-form');
      form.hidden = true;
      const label = node('label', 'Why do you believe this is wrong?', 'fine');
      const reason = node('textarea');
      reason.maxLength = REASON_LIMIT;
      reason.rows = 3;
      reason.placeholder = 'For example: this is our own company intranet, and the login page is expected.';
      label.htmlFor = reason.id = `report-reason-${result.scan_id || 'scan'}`;
      const send = node('button', 'Send report');
      send.type = 'button';
      send.disabled = true;
      const note = node('p', null, 'fine');
      reason.addEventListener('input', () => {
        send.disabled = !reason.value.trim();
        note.textContent = reason.value.length >= REASON_LIMIT ? `Limit of ${REASON_LIMIT} characters reached.` : '';
      });
      open.addEventListener('click', () => {
        open.hidden = true;
        form.hidden = false;
        reason.focus();
      });
      send.addEventListener('click', async () => {
        send.disabled = true;
        send.textContent = 'Sending report…';
        note.className = 'fine';
        note.textContent = '';
        try {
          await reportFalsePositive(result, reason.value.trim());
          // The verdict stands: a report is filed for review, not applied here.
          form.hidden = true;
          note.textContent = 'Thanks — your report was saved for review. The verdict above does not change.';
        } catch (error) {
          note.className = 'error';
          note.textContent = error.message || 'The report could not be saved. Try again.';
          send.textContent = 'Try sending again';
          send.disabled = false;
        }
      });
      form.append(label, reason, send);
      box.append(open, form, note);
      container.append(box);
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
