(function () {
  const API_BASE = 'http://localhost:8000';
  async function analyzeUrl(url, { rescan = false, onProgress = () => {}, signal } = {}) {
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
  Object.assign(self.Phisang ||= {}, { API_BASE, analyzeUrl, savedExplanation });
})();
