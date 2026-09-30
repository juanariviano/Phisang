const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');

function worker() {
  let handler, before;
  const stored = {}, requests = [], navigations = [], events = [], badges = [];
  const tab = { id: 7, url: 'https://example.org/' };
  const chrome = {
    storage: {
      local: { get: (defaults, callback) => callback(defaults) }, onChanged: { addListener() {} },
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
  const context = vm.createContext({ chrome, URL, Response, TextDecoder, console,
    fetch: async (url, options) => { requests.push({ url, options }); return response(url, options); } });
  context.self = context;
  context.importScripts = (...files) => files.forEach(file => vm.runInContext(fs.readFileSync(path.join(root, file), 'utf8'), context));
  context.importScripts('background.js');
  return { stored, requests, navigations, events, badges, tab, context,
    respond: callback => { response = callback; }, navigate: url => before({ tabId: 7, frameId: 0, url }),
    message: message => new Promise(resolve => handler(message, { tab: { id: 7 } }, resolve)),
  };
}
const result = (changes = {}) => ({ scan_id: 'request', evidence_scan_id: 'original', normalized_url: 'https://example.org/',
  classification: 'benign', verdict: 'safe', risk_score: .1, page: { status: 'ok' }, ...changes });

test('popup reload retrieves the SQL-backed explanation using the durable evidence ID', async () => {
  const w = worker();
  const answer = { summary: 'Saved in SQL', reasons: ['Evidence'], advice: ['Be careful'] };
  w.stored['tab:7'] = { url: 'https://example.org/', result: result() };
  w.respond(() => Response.json({ explanation: answer }));
  const loaded = await w.message({ type: 'GET_TAB_RESULT' });
  assert.deepEqual(loaded.result.explanation, answer);
  assert.equal(w.requests[0].url, 'http://localhost:8000/api/v1/scans/original');
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
  assert.deepEqual(JSON.parse(w.requests[0].options.body), { url: 'https://example.org/', client: 'extension', rescan: true });
  assert.equal(w.badges.at(-1).text, '!');
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
