(function () {
  const API_BASE = 'https://phisang.kennethsunjaya.com';
  async function analyzeUrl(url, { rescan = false, onProgress = () => {}, signal } = {}) {
    const message = self.Phisang.fileUrlMessage(url);
    if (message) throw Object.assign(new Error(message), { code: 'unsupported_content' });
    const response = await fetch(`${API_BASE}/api/v1/analyze`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'text/event-stream' },
      body: JSON.stringify({ url, client: 'extension', rescan }), signal,
    });
    let result;
    await self.Phisang.readScanStream(response, { onProgress, onDone: value => { result = value; } });
    return result;
  }
  async function savedExplanation(result) {
    if (!result?.scan_id) return null;
    // Replays have transient request IDs; the evidence ID survives API restarts.
    const id = result.evidence_scan_id || result.scan_id;
    const response = await fetch(`${API_BASE}/api/v1/scans/${encodeURIComponent(id)}`);
    if (!response.ok) return result.explanation || null;
    return (await response.json()).explanation || null;
  }
  async function reportFalsePositive(result, reason = '') {
    // Reported against the durable evidence ID, so the report still points at the
    // observation the reporter saw after the request ID is gone.
    const id = result?.evidence_scan_id || result?.scan_id;
    if (!id) throw new Error('This result has no saved scan to report.');
    const response = await fetch(`${API_BASE}/api/v1/scans/${encodeURIComponent(id)}/report`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client: 'extension', reason }),
    });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.message || 'The report could not be saved. Try again.');
    }
    return response.json();
  }
  Object.assign(self.Phisang ||= {}, { API_BASE, analyzeUrl, savedExplanation, reportFalsePositive });
})();
