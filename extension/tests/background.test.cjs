const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');

function worker() {
  let handler, before;
  const stored = {}, local = {}, requests = [], navigations = [], events = [], badges = [];
  const tab = { id: 7, url: 'https://example.org/' };
  const chrome = {
    storage: {
      local: {
        get: (query, callback) => {
          if (callback) return callback(query);
          const key = typeof query === 'string' ? query : Object.keys(query)[0];
          return Promise.resolve(key in local ? { [key]: local[key] } : {});
        },
        set: async value => Object.assign(local, structuredClone(value)),
        remove: async key => { delete local[key]; },
      }, onChanged: { addListener() {} },
      session: { set: async value => Object.assign(stored, value), get: async () => stored, remove: async () => {} },
    },
    runtime: { getURL: file => 'chrome-extension://test/' + file,
      onMessage: { addListener: callback => { handler = callback; } },
      sendMessage: async message => events.push(message),
    },
    action: { setBadgeText: spec => badges.push(spec), setBadgeBackgroundColor() {} },
    tabs: { get: async () => tab, update: async (tabId, spec) => { navigations.push(spec.url); tab.url = spec.url; }, onRemoved: { addListener() {} } },
    webNavigation: { onCommitted: { addListener() {} }, onBeforeNavigate: { addListener: callback => { before = callback; } } },
  };
  let response = () => new Response('{}');
  const context = vm.createContext({ chrome, URL, Response, TextDecoder, console, structuredClone,
    fetch: async (url, options) => { requests.push({ url, options }); return response(url, options); } });
  context.self = context;
  context.importScripts = (...files) => files.forEach(file => vm.runInContext(fs.readFileSync(path.join(root, file), 'utf8'), context));
  context.importScripts('background.js');
  return { stored, local, requests, navigations, events, badges, tab, context,
    respond: callback => { response = callback; }, navigate: (url, tabId = 7) => before({ tabId, frameId: 0, url }),
    message: message => new Promise(resolve => handler(message, { tab: { id: 7 } }, resolve)),
  };
}
const result = (changes = {}) => ({ scan_id: 'request', evidence_scan_id: 'original', normalized_url: 'https://example.org/',
  classification: 'benign', verdict: 'safe', risk_score: .1, page: { status: 'ok' }, ...changes });

test('every website High risk verdict blocks the initial navigation, even with a benign classification', async () => {
  for (const changes of [
    { risk_score: .994 }, { risk_score: .6 }, { verdict: 'malicious', risk_score: null },
    { classification: 'malware' }, { classification: 'phishing' },
  ]) {
    const w = worker();
    await w.message({ type: 'ANALYSIS_RESULT', tabId: 7, url: 'https://example.org/', result: result(changes) });
    assert.equal(w.navigations.at(-1), 'chrome-extension://test/blocked.html', JSON.stringify(changes));
    assert.equal(w.badges.at(-1).text, 'STOP');
  }
});

test('Continue anyway releases only this visit, not future visits or sibling paths', async () => {
  const w = worker();
  await w.message({ type: 'CONTINUE_ANYWAY', tabId: 7, url: 'https://example.org/' });
  const count = w.navigations.length;
  w.navigate('https://example.org/');
  assert.equal(w.navigations.length, count);
  w.navigate('https://example.org/');
  assert.match(w.navigations.at(-1), /checking.html/);
  w.navigate('https://example.org/other');
  assert.match(w.navigations.at(-1), /checking.html/);
});

test('well-known domains are checked before being released instead of silently loading', () => {
  const w = worker();
  w.navigate('https://github.com/example/suspicious');
  assert.match(w.navigations.at(-1), /checking.html/);
  assert.equal(w.requests.length, 0); // The checking screen owns the scan.
});

test('a one-visit override cannot leak to another tab or survive a different destination', async () => {
  const w = worker();
  await w.message({ type: 'CONTINUE_ANYWAY', tabId: 7, url: 'https://example.org/' });
  w.navigate('https://example.org/', 8);
  assert.match(w.navigations.at(-1), /checking.html/);
  w.navigate('https://other.example/', 7);
  w.navigate('https://example.org/', 7);
  assert.match(w.navigations.at(-1), /checking.html/);
});

test('caution and unknown remain distinct from the high-risk stop rule', async () => {
  for (const changes of [
    { risk_score: .5999, verdict: 'potentially_unsafe' },
    { classification: 'unavailable', risk_score: null, verdict: 'unknown' },
  ]) {
    const w = worker();
    await w.message({ type: 'ANALYSIS_RESULT', tabId: 7, url: 'https://example.org/', result: result(changes) });
    assert.equal(w.navigations.at(-1), 'https://example.org/');
    assert.notEqual(w.badges.at(-1).text, 'STOP');
  }
});

test('popup reload retrieves the SQL-backed explanation using the durable evidence ID', async () => {
  const w = worker();
  const answer = { summary: 'Saved in SQL', reasons: ['Evidence'], advice: ['Be careful'] };
  w.stored['tab:7'] = { url: 'https://example.org/', result: result() };
  w.respond(() => Response.json({ explanation: answer }));
  const loaded = await w.message({ type: 'GET_TAB_RESULT' });
  assert.deepEqual(loaded.result.explanation, answer);
  assert.equal(w.requests[0].url, 'https://phisang.kennethsunjaya.com/api/v1/scans/original');
  assert.equal(w.requests.length, 1);
});

test('Rescan streams real progress, sends rescan true, and replaces an old explanation', async () => {
  const w = worker();
  w.stored['tab:7'] = { url: 'https://example.org/', result: result({ explanation: { summary: 'old' } }) };
  const fresh = result({ scan_id: 'fresh', evidence_scan_id: 'fresh', explanation: null, risk_score: .94 });
  w.respond(() => new Response('event: progress\ndata: {"stage":"page","label":"Inspecting the website","status":"running"}\n\nevent: done\ndata: ' + JSON.stringify(fresh) + '\n\n', { headers: { 'content-type': 'text/event-stream' } }));
  const reply = await w.message({ type: 'RESCAN', tabId: 7, url: 'https://example.org/' });
  assert.equal(reply.ok, true);
  assert.equal(reply.payload.result.explanation, null);
  assert.equal(w.events[0].type, 'SCAN_PROGRESS');
  assert.equal(w.events[0].progress.stage, 'page');
  assert.equal(w.requests[0].url, 'https://phisang.kennethsunjaya.com/api/v1/analyze');
  assert.deepEqual(JSON.parse(w.requests[0].options.body), { url: 'https://example.org/', client: 'extension', rescan: true });
  assert.equal(w.badges.at(-1).text, 'STOP');
  assert.equal(w.navigations.at(-1), 'chrome-extension://test/blocked.html');
});

test('a failed Rescan keeps the previous result and can be retried', async () => {
  const w = worker();
  const previous = { url: 'https://example.org/', result: result() };
  w.stored['tab:7'] = previous;
  w.respond(() => new Response('event: error\ndata: {"message":"Scanner unavailable"}\n\n', { headers: { 'content-type': 'text/event-stream' } }));
  const reply = await w.message({ type: 'RESCAN', tabId: 7, url: previous.url });
  assert.equal(reply.ok, false);
  assert.equal(reply.message, 'Scanner unavailable');
  assert.equal(w.stored['tab:7'], previous);
});

test('benign and unavailable results do not bypass later scans of a URL or its sibling path', async () => {
  for (const classification of ['benign', 'unavailable']) {
    const w = worker();
    await w.message({ type: 'ANALYSIS_RESULT', tabId: 7, url: 'https://example.org/', result: result({ classification }) });
    w.navigate('https://example.org/'); // One navigation released by checking.html.
    const before = w.navigations.length;
    w.navigate('https://example.org/'); // Explicitly visiting it again checks the archive.
    w.navigate('https://example.org/other');
    assert.equal(w.navigations.length, before + 2);
    assert.match(w.navigations.at(-1), /checking.html/);
  }
});

test('rescanning a blocked tab does not reload it before the new result can render', async () => {
  const w = worker();
  w.tab.url = 'chrome-extension://test/blocked.html';
  w.respond(() => Response.json(result({ classification: 'phishing' })));
  assert.equal((await w.message({ type: 'RESCAN', tabId: 7, url: 'https://example.org/' })).ok, true);
  assert.equal(w.navigations.length, 0);
});

test('non-web pages and the local scanner are not intercepted', () => {
  const w = worker();
  for (const url of ['file:///test', 'http://localhost:5173/', 'http://localhost:8000/', 'chrome://extensions/']) w.navigate(url);
  assert.equal(w.navigations.length, 0);
});

test('the public scanner is exempt, without exempting lookalikes or sibling hosts', () => {
  const w = worker();
  for (const url of ['https://phisang.kennethsunjaya.com/', 'https://phisang.kennethsunjaya.com/api/v1/health',
    'http://phisang.kennethsunjaya.com/']) w.navigate(url);
  assert.equal(w.navigations.length, 0);
  for (const url of ['https://phisang.kennethsunjaya.com.evil.example/',
    'https://kennethsunjaya.com/', 'https://other.kennethsunjaya.com/']) {
    w.navigate(url);
    assert.match(w.navigations.at(-1), /checking.html/);
  }
});

test('Go back never releases the same address after a rescan flags it', async () => {
  const w = worker();
  const url = 'https://example.org/';
  await w.message({ type: 'ANALYSIS_RESULT', tabId: 7, url, result: result() });
  w.respond(() => Response.json(result({ classification: 'phishing' })));
  await w.message({ type: 'RESCAN', tabId: 7, url });
  await w.message({ type: 'GO_BACK', tabId: 7, url });
  assert.equal(w.navigations.at(-1), 'chrome://newtab/');
});

test('extension uses the website verdict and artwork state even when classification is benign', () => {
  const w = worker();
  assert.equal(w.context.Phisang.verdictMeta(result({ risk_score: .94 }), 'benign').bananaState, 'rotten');
  assert.equal(w.context.Phisang.verdictMeta(result({ risk_score: .45 }), 'benign').verdict, 'Be cautious');
  assert.equal(w.context.Phisang.verdictMeta(result({ risk_score: .99 }), 'unavailable').bananaState, 'unavailable');
});

/* --- Local verdict cache ------------------------------------------------- */

const safeEntries = w => w.local.safeCache || {};

test('a safe result is kept locally so the same address needs no second scan', async () => {
  const w = worker();
  const url = 'https://example.org/';
  await w.message({ type: 'ANALYSIS_RESULT', tabId: 7, url, result: result() });
  assert.deepEqual(Object.keys(safeEntries(w)), [url]);
  // The next visit answers from storage: the tab still waits on the checking
  // screen, but no scan request reaches the API.
  const cached = await w.context.Phisang.cachedResult(url);
  assert.equal(cached.classification, 'benign');
  assert.equal(cached.served_from_local_cache, true);
  assert.equal(w.requests.length, 0);
});

test('only a plainly safe verdict is cached', async () => {
  for (const changes of [
    { classification: 'phishing' }, { classification: 'malware' }, { risk_score: .994 },
    { classification: 'unavailable', risk_score: null }, { verdict: 'malicious', risk_score: null },
    { risk_score: .45 },                                        // "Be cautious".
    { classification: 'benign', error_code: 'page_unavailable' },
    { classification: 'benign', page: { status: 'unavailable' } },
    { prior: { ever_malicious: true } },                        // Flagged before.
  ]) {
    const w = worker();
    await w.message({ type: 'ANALYSIS_RESULT', tabId: 7, url: 'https://example.org/', result: result(changes) });
    assert.deepEqual(safeEntries(w), {}, JSON.stringify(changes));
    assert.equal(await w.context.Phisang.cachedResult('https://example.org/'), null);
  }
});

test('one address is one entry, and a sibling path is still its own scan', async () => {
  const w = worker();
  const { cacheKey } = w.context.Phisang;
  assert.equal(cacheKey('https://example.org'), cacheKey('https://EXAMPLE.org:443/'));
  assert.equal(cacheKey('https://example.org/a/'), cacheKey('https://user:pw@example.org/a'));
  assert.notEqual(cacheKey('https://example.org/a'), cacheKey('https://example.org/b'));
  assert.notEqual(cacheKey('https://example.org/'), cacheKey('http://example.org/'));
  assert.equal(cacheKey('file:///test'), null);
  await w.message({ type: 'ANALYSIS_RESULT', tabId: 7, url: 'https://example.org/', result: result() });
  assert.equal(await w.context.Phisang.cachedResult('https://example.org/other'), null);
});

test('a cache hit does not renew its own lifetime', async () => {
  const w = worker();
  const url = 'https://example.org/';
  await w.message({ type: 'ANALYSIS_RESULT', tabId: 7, url, result: result() });
  const first = safeEntries(w)[url].at;
  const cached = await w.context.Phisang.cachedResult(url);
  await w.message({ type: 'ANALYSIS_RESULT', tabId: 7, url, result: cached });
  assert.equal(safeEntries(w)[url].at, first);
});

test('an entry past its lifetime is dropped instead of released', async () => {
  const w = worker();
  const url = 'https://example.org/';
  await w.message({ type: 'ANALYSIS_RESULT', tabId: 7, url, result: result() });
  safeEntries(w)[url].at = Date.now() - 7 * 60 * 60 * 1000;
  assert.equal(await w.context.Phisang.cachedResult(url), null);
  assert.deepEqual(safeEntries(w), {});
});

test('a rescan that flags the page removes it from the local cache', async () => {
  const w = worker();
  const url = 'https://example.org/';
  await w.message({ type: 'ANALYSIS_RESULT', tabId: 7, url, result: result() });
  assert.deepEqual(Object.keys(safeEntries(w)), [url]);
  w.respond(() => Response.json(result({ classification: 'phishing' })));
  await w.message({ type: 'RESCAN', tabId: 7, url });
  assert.deepEqual(safeEntries(w), {});
  assert.equal(w.navigations.at(-1), 'chrome-extension://test/blocked.html');
});

test('an unreachable scanner clears any earlier release of that address', async () => {
  const w = worker();
  const url = 'https://example.org/';
  await w.message({ type: 'ANALYSIS_RESULT', tabId: 7, url, result: result() });
  await w.message({ type: 'ANALYSIS_ERROR', tabId: 7, url });
  assert.deepEqual(safeEntries(w), {});
});

test('the cache holds a bounded number of addresses and evicts the oldest first', async () => {
  const w = worker();
  const url = i => `https://example.org/page-${i}`;
  for (let i = 0; i < 150; i += 1) await w.context.Phisang.rememberResult(url(i), result());
  assert.equal(await w.context.Phisang.cacheSize(), 150); // Well under the cap: nothing evicted.
  for (let i = 150; i < 205; i += 1) await w.context.Phisang.rememberResult(url(i), result());
  assert.equal(await w.context.Phisang.cacheSize(), 200);
  assert.equal(await w.context.Phisang.cachedResult(url(0)), null);
  assert.ok(await w.context.Phisang.cachedResult(url(204)));
});

test('clearing the cache sends every address back to the scanner', async () => {
  const w = worker();
  const url = 'https://example.org/';
  await w.message({ type: 'ANALYSIS_RESULT', tabId: 7, url, result: result() });
  assert.equal(await w.context.Phisang.cacheSize(), 1);
  await w.context.Phisang.clearCache();
  assert.equal(await w.context.Phisang.cacheSize(), 0);
  assert.equal(await w.context.Phisang.cachedResult(url), null);
});

test('a false positive report is filed against the durable evidence ID', async () => {
  const w = worker();
  w.respond(() => Response.json({ status: 'recorded', report_id: 3, scan_id: 'original' }));
  const reply = await w.context.Phisang.reportFalsePositive(result({ classification: 'phishing' }));
  assert.equal(reply.report_id, 3);
  assert.equal(w.requests[0].url, 'https://phisang.kennethsunjaya.com/api/v1/scans/original/report');
  assert.deepEqual(JSON.parse(w.requests[0].options.body), { client: 'extension', reason: '' });
});

test('a report the server rejects reports its own message', async () => {
  const w = worker();
  w.respond(() => Response.json({ message: 'Reports are unavailable.' }, { status: 503 }));
  await assert.rejects(() => w.context.Phisang.reportFalsePositive(result({ classification: 'phishing' })),
    /Reports are unavailable\./);
});
