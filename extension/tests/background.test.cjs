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
    message: message => new Promise(resolve =>
      handler(message, { tab: { id: 7 }, url: 'chrome-extension://test/popup.html' }, resolve)),
    messageFromPage: message => new Promise(resolve =>
      handler(message, { tab: { id: 7 }, url: 'https://evil.example/' }, resolve)),
  };
}
const result = (changes = {}) => ({ scan_id: 'request', evidence_scan_id: 'original', normalized_url: 'https://example.org/',
  classification: 'benign', verdict: 'safe', risk_score: .1, page: { status: 'ok' }, ...changes });

async function checkNavigation(w, url) {
  const context = vm.createContext({
    URLSearchParams, AbortController,
    location: { search: '?' + new URLSearchParams({ url, tabId: 7 }) },
    window: { addEventListener() {} }, document: { getElementById: () => ({}), querySelector: () => ({}) },
    chrome: { runtime: { sendMessage: w.message } },
    self: { Phisang: { ...w.context.Phisang, renderBanana() {},
      scanProgress: () => ({ update() {}, stop() {} }) } },
  });
  await vm.runInContext(fs.readFileSync(path.join(root, 'checking.js'), 'utf8'), context);
}

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
  await w.context.Phisang.rememberResult(previous.url, previous.result);
  w.respond(() => new Response('event: error\ndata: {"message":"Scanner unavailable"}\n\n', { headers: { 'content-type': 'text/event-stream' } }));
  const reply = await w.message({ type: 'RESCAN', tabId: 7, url: previous.url });
  assert.equal(reply.ok, false);
  assert.equal(reply.message, 'Scanner unavailable');
  assert.equal(w.stored['tab:7'], previous);
  assert.equal(await w.context.Phisang.cachedResult('https://example.org/other'), null);
});

test('later visits still enter the checking screen to resolve cached or fresh results', async () => {
  for (const classification of ['benign', 'unavailable']) {
    const w = worker();
    await w.message({ type: 'ANALYSIS_RESULT', tabId: 7, url: 'https://example.org/', result: result({ classification }) });
    w.navigate('https://example.org/'); // One navigation released by checking.html.
    const before = w.navigations.length;
    w.navigate('https://example.org/'); // The checking screen resolves local reuse.
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

const hostEntries = w => w.local.hostVerdictCache || {};

test('file URLs cannot inherit a hostname verdict or call the scanner', async () => {
  const w = worker();
  await w.context.Phisang.rememberResult('https://example.org/home', result());
  for (const path of ['SETUP.EXE?token=abc', 'report%2Epdf', '%FFreport%2Epdf', 'data.zip', 'music.mp3', 'picture.png']) {
    const url = `https://example.org/${path}`;
    assert.equal(await w.context.Phisang.cachedResult(url), null);
    await checkNavigation(w, url);
    assert.equal(w.stored['tab:7'].result.error_code, 'unsupported_content');
    await assert.rejects(() => w.context.Phisang.analyzeUrl(url, { rescan: true }), /webpages, not files/);
  }
  assert.equal(w.requests.length, 0);
  assert.equal(w.navigations.length, 0); // Do not automatically open/download it.
  assert.ok(await w.context.Phisang.cachedResult('https://example.org/login'));
});

test('a backend file-destination error keeps navigation paused and never caches a verdict', async () => {
  for (const streaming of [false, true]) {
    const w = worker();
    const error = { error_code: 'unsupported_content', message: 'Phisang scans webpages, not files.' };
    w.respond(() => streaming
      ? new Response('event: error\ndata: ' + JSON.stringify(error) + '\n\n', { headers: { 'content-type': 'text/event-stream' } })
      : Response.json(error, { status: 400 }));
    await checkNavigation(w, 'https://example.org/download');
    assert.equal(w.requests.length, 1);
    assert.equal(w.navigations.length, 0);
    assert.deepEqual(hostEntries(w), {});
    assert.equal(w.stored['tab:7'].result.error_code, 'unsupported_content');
  }
});

test('page extensions and dots outside the final path are not mistaken for files', () => {
  const w = worker();
  for (const url of ['https://example.com', 'https://example.zip/', 'example.org/index.html',
    'https://example.org/login.php', 'https://example.org/login.aspx',
    'https://example.org/file.pdf/view', 'https://example.org/?next=file.exe#report.pdf']) {
    assert.equal(w.context.Phisang.fileUrlMessage(url), '', url);
  }
});

test('older cached results pointing to file destinations cannot release a page', async () => {
  const w = worker();
  await w.context.Phisang.rememberResult('https://example.org/home', result());
  hostEntries(w)['example.org'].result.page.final_url = 'https://example.org/file.pdf';
  assert.equal(await w.context.Phisang.cachedResult('https://example.org/home'), null);
});

test('navigation scans the hostname once across paths and scans a different subdomain separately', async () => {
  const w = worker();
  w.respond((_, options) => Response.json(result({ normalized_url: JSON.parse(options.body).url })));
  for (const pathname of ['home', 'login', 'inventory']) {
    const url = `https://test.com/${pathname}`;
    await checkNavigation(w, url);
    assert.equal(w.navigations.at(-1), url);
    assert.equal(w.stored['tab:7'].url, url);
    assert.equal(w.stored['tab:7'].result.normalized_url, 'https://test.com/home');
  }
  assert.equal(w.requests.length, 1);
  await checkNavigation(w, 'https://dev.test.com/home');
  assert.equal(w.requests.length, 2);
  await checkNavigation(w, 'https://dev.test.com/login');
  assert.equal(w.requests.length, 2);
});

test('cached threats block sibling paths without another API request', async () => {
  const w = worker();
  w.respond(() => Response.json(result({ classification: 'phishing' })));
  await checkNavigation(w, 'https://example.org/home');
  await checkNavigation(w, 'https://example.org/login');
  assert.equal(w.requests.length, 1);
  assert.equal(w.navigations.at(-1), 'chrome-extension://test/blocked.html');
  assert.equal(w.badges.at(-1).text, 'STOP');
});

test('failed or incomplete checks are never reused across paths', async () => {
  for (const changes of [
    { classification: 'unavailable' }, { error_code: 'page_unavailable' },
    { page: { status: 'unavailable' } }, { verdict: 'unknown' }, { decision_stage: 'error' },
  ]) {
    const w = worker();
    w.respond(() => Response.json(result(changes)));
    await checkNavigation(w, 'https://example.org/home');
    await checkNavigation(w, 'https://example.org/login');
    assert.equal(w.requests.length, 2);
    assert.deepEqual(hostEntries(w), {});
  }
});

test('a safe result is kept locally so the same address needs no second scan', async () => {
  const w = worker();
  const url = 'https://example.org/';
  await w.message({ type: 'ANALYSIS_RESULT', tabId: 7, url, result: result() });
  assert.deepEqual(Object.keys(hostEntries(w)), ['example.org']);
  // The next visit answers from storage: the tab still waits on the checking
  // screen, but no scan request reaches the API.
  const cached = await w.context.Phisang.cachedResult(url);
  assert.equal(cached.classification, 'benign');
  assert.equal(cached.served_from_local_cache, true);
  assert.equal(w.requests.length, 0);
});

test('completed verdicts are cached without changing their risk or evidence', async () => {
  for (const changes of [
    { classification: 'phishing' }, { classification: 'malware' }, { risk_score: .994 },
    { verdict: 'malicious', risk_score: null },
    { risk_score: .45 },                                        // "Be cautious".
    { prior: { ever_malicious: true } },                        // Flagged before.
  ]) {
    const w = worker();
    await w.message({ type: 'ANALYSIS_RESULT', tabId: 7, url: 'https://example.org/', result: result(changes) });
    const cached = await w.context.Phisang.cachedResult('https://example.org/another');
    assert.equal(cached.classification, result(changes).classification);
    assert.equal(cached.risk_score, result(changes).risk_score);
    assert.equal(cached.evidence_scan_id, 'original');
    assert.equal(cached.normalized_url, 'https://example.org/');
  }
});

test('paths share a hostname entry while every subdomain stays separate', async () => {
  const w = worker();
  const { cacheKey } = w.context.Phisang;
  assert.equal(cacheKey('https://example.org'), cacheKey('https://EXAMPLE.org:443/'));
  assert.equal(cacheKey('https://example.org/a/'), cacheKey('https://user:pw@example.org/a'));
  assert.equal(cacheKey('https://example.org/a'), cacheKey('https://example.org/b?x=1#part'));
  assert.equal(cacheKey('https://example.org/'), cacheKey('http://example.org:8080/'));
  assert.equal(cacheKey('https://example.org./'), cacheKey('https://example.org/'));
  for (const host of ['dev.example.org', 'www.example.org', 'example.org.evil.test']) {
    assert.notEqual(cacheKey(`https://${host}/`), cacheKey('https://example.org/'));
  }
  assert.equal(cacheKey('file:///test'), null);
  await w.message({ type: 'ANALYSIS_RESULT', tabId: 7, url: 'https://example.org/', result: result() });
  assert.ok(await w.context.Phisang.cachedResult('https://example.org/other'));
  assert.equal(await w.context.Phisang.cachedResult('https://dev.example.org/other'), null);
});

test('a cache hit does not renew its own lifetime', async () => {
  const w = worker();
  const url = 'https://example.org/';
  await w.message({ type: 'ANALYSIS_RESULT', tabId: 7, url, result: result() });
  const first = hostEntries(w)['example.org'].at;
  const cached = await w.context.Phisang.cachedResult(url);
  await w.message({ type: 'ANALYSIS_RESULT', tabId: 7, url, result: cached });
  assert.equal(hostEntries(w)['example.org'].at, first);
});

test('an entry past its lifetime is dropped instead of released', async () => {
  const w = worker();
  const url = 'https://example.org/';
  await w.message({ type: 'ANALYSIS_RESULT', tabId: 7, url, result: result() });
  hostEntries(w)['example.org'].at = Date.now() - 7 * 60 * 60 * 1000;
  assert.equal(await w.context.Phisang.cachedResult(url), null);
  assert.deepEqual(hostEntries(w), {});
});

test('a rescan that flags a sibling path replaces the hostname verdict and blocks later visits', async () => {
  const w = worker();
  const url = 'https://example.org/';
  await w.message({ type: 'ANALYSIS_RESULT', tabId: 7, url, result: result() });
  assert.deepEqual(Object.keys(hostEntries(w)), ['example.org']);
  w.respond(() => Response.json(result({ classification: 'phishing' })));
  await w.message({ type: 'RESCAN', tabId: 7, url: 'https://example.org/login' });
  const cached = await w.context.Phisang.cachedResult('https://example.org/inventory');
  assert.equal(cached.classification, 'phishing');
  await w.message({ type: 'ANALYSIS_RESULT', tabId: 7, url: 'https://example.org/inventory', result: cached });
  assert.equal(w.requests.length, 1);
  assert.equal(w.navigations.at(-1), 'chrome-extension://test/blocked.html');
});

test('an unreachable scanner clears any earlier release of that address', async () => {
  const w = worker();
  const url = 'https://example.org/';
  await w.message({ type: 'ANALYSIS_RESULT', tabId: 7, url, result: result() });
  await w.message({ type: 'ANALYSIS_ERROR', tabId: 7, url });
  assert.deepEqual(hostEntries(w), {});
});

test('the cache holds a bounded number of addresses and evicts the oldest first', async () => {
  const w = worker();
  const url = i => `https://host-${i}.example.org/page`;
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

/* --- User allowlist ------------------------------------------------------- */

const allowed = w => w.local.userAllowlist || {};

test('an allowed address opens without a scan, and the badge says the check was skipped', async () => {
  const w = worker();
  const url = 'https://intranet.example/report';
  const reply = await w.message({ type: 'ALLOW_URL', url });
  assert.equal(reply.ok, true);
  assert.deepEqual(Object.keys(allowed(w)), [url]);
  const before = w.navigations.length;
  w.navigate(url);
  assert.equal(w.navigations.length, before); // No holding screen, no scan.
  assert.equal(w.badges.at(-1).text, 'SKIP');
  assert.equal(w.requests.length, 0);
});

test('allowing one address does not release the rest of the site', async () => {
  const w = worker();
  await w.message({ type: 'ALLOW_URL', url: 'https://intranet.example/report' });
  w.navigate('https://intranet.example/other');
  assert.match(w.navigations.at(-1), /checking.html/);
  w.navigate('https://intranet.example/');
  assert.match(w.navigations.at(-1), /checking.html/);
});

test('a page cannot allow itself: only an extension page may write to the allowlist', async () => {
  const w = worker();
  const url = 'https://evil.example/';
  const reply = await w.messageFromPage({ type: 'ALLOW_URL', url });
  assert.equal(reply.ok, false);
  assert.deepEqual(allowed(w), {});
  w.navigate(url);
  assert.match(w.navigations.at(-1), /checking.html/); // Still scanned.
  assert.equal((await w.messageFromPage({ type: 'FORGET_ALLOWED', key: url })).ok, false);
  assert.equal((await w.messageFromPage({ type: 'LIST_ALLOWED' })).entries.length, 0);
});

test('an allowed address is scanned again once the user removes it', async () => {
  const w = worker();
  const url = 'https://intranet.example/report';
  await w.message({ type: 'ALLOW_URL', url });
  const listed = await w.message({ type: 'LIST_ALLOWED' });
  assert.deepEqual(Array.from(listed.entries, entry => entry.url), [url]);
  assert.equal((await w.message({ type: 'FORGET_ALLOWED', key: listed.entries[0].key })).ok, true);
  w.navigate(url);
  assert.match(w.navigations.at(-1), /checking.html/);
});

test('clearing the verdict cache leaves the user allowlist alone', async () => {
  const w = worker();
  const url = 'https://intranet.example/report';
  await w.message({ type: 'ALLOW_URL', url });
  await w.message({ type: 'ANALYSIS_RESULT', tabId: 7, url: 'https://example.org/', result: result() });
  await w.context.Phisang.clearCache();
  assert.equal(await w.context.Phisang.cacheSize(), 0);
  assert.deepEqual(Object.keys(allowed(w)), [url]); // A decision, not a cache.
  w.navigate(url);
  assert.equal(w.badges.at(-1).text, 'SKIP');
});

test('a malicious verdict is still overridden, which is the whole point and the whole risk', async () => {
  const w = worker();
  const url = 'https://known-bad.example/login';
  await w.message({ type: 'ANALYSIS_RESULT', tabId: 7, url, result: result({ classification: 'malware' }) });
  assert.equal(w.navigations.at(-1), 'chrome-extension://test/blocked.html');
  await w.message({ type: 'ALLOW_URL', url });
  const before = w.navigations.length;
  w.navigate(url);
  assert.equal(w.navigations.length, before);
  assert.equal(w.badges.at(-1).text, 'SKIP');
});
