'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const { MessageChannel } = require('node:worker_threads');

const script = fs.readFileSync(path.join(__dirname, '../docs/logic.js'), 'utf8');

function startPage(t, { search = '', trending, kev = {}, indexError = false }) {
  const elements = new Map();
  const calls = [];
  const document = {
    addEventListener() {},
    querySelectorAll: () => [],
    querySelector(selector) {
      if (!elements.has(selector)) elements.set(selector, {
        value: '',
        innerHTML: selector === '[data-trend-rows]' ? '<a href="/CVE-2026-1234">Prerendered PoC</a>' : '',
        addEventListener() {}, setAttribute() {}, querySelectorAll: () => []
      });
      return elements.get(selector);
    }
  };
  const context = vm.createContext({
    console: { warn() {} }, document, performance, MessageChannel, URLSearchParams, URL,
    location: { pathname: '/', search },
    window: { matchMedia: () => ({ matches: false }) },
    setTimeout() {}, clearTimeout() {},
    async fetch(url) {
      calls.push(url);
      if (url === '/CVE_list.json' && indexError) throw new Error('Index unavailable');
      const data = url === '/trending_poc.json' ? await trending
        : url === '/kev.json' ? await kev
        : url === '/CVE_list.json' ? [{ cve: 'CVE-2026-1234', desc: 'widget', poc: ['https://github.com/owner/poc'] }]
          : {};
      return { ok: true, json: async () => data };
    }
  });
  vm.runInContext(script, context);
  t.after(() => vm.runInContext('yieldPort.port1.close(); yieldPort.port2.close();', context));
  return { elements, calls, context };
}

test('repository security advisories have GHSA filtering without repository stars or dates', async t => {
  const { context } = startPage(t, { trending: new Promise(() => {}) });
  await new Promise(setImmediate);
  const url = 'https://github.com/vendor/project/security/advisories/GHSA-1234';
  vm.runInContext('repoMeta = { "vendor/project": [5000, "2026-10-06"] };', context);
  const row = vm.runInContext(`pocRow(${JSON.stringify(url)})`, context);
  assert.match(row, /GHSA-1234/);
  assert.doesNotMatch(row, /★|5\.0k/);
  assert.equal(vm.runInContext(`entrySources({poc: [${JSON.stringify(url)}]}).has('GHSA')`, context), true);
  assert.equal(vm.runInContext(`repoFromUrl(${JSON.stringify(url)})`, context), null);
});

test('a stalled trending feed does not block a bookmarked search', async t => {
  const { elements, calls } = startPage(t, { search: '?q=widget', trending: new Promise(() => {}) });
  await new Promise(setImmediate);
  assert.ok(calls.includes('/CVE_list.json'));
  assert.equal(elements.get('[data-search]').value, 'widget');
  assert.match(elements.get('[data-results]').innerHTML, /href="\/CVE-2026-1234"/);
});

test('a bookmarked typo is corrected when indexing finishes without changing filters', async t => {
  const { elements, context } = startPage(t, {
    search: '?q=wdiget&src=github&kev=1&sort=newest',
    trending: new Promise(() => {}),
    kev: { 'CVE-2026-1234': ['2026-10-06', false] }
  });
  await new Promise(setImmediate);
  assert.equal(vm.runInContext('wordIndex.ready', context), true);
  assert.match(elements.get('[data-results]').innerHTML, /href="\/CVE-2026-1234"/);
  assert.match(elements.get('[data-status]').textContent, /widget for wdiget/);
  assert.equal(elements.get('[data-search]').value, 'wdiget');
  assert.equal(vm.runInContext('state.query', context), 'wdiget');
  assert.equal(vm.runInContext('state.sort', context), 'NEWEST');
  assert.equal(vm.runInContext('state.kevOnly', context), true);
  assert.equal(vm.runInContext("[...state.filters.source].join(',')", context), 'GITHUB');
});

test('a failed trending feed preserves the published homepage rows', async t => {
  const { elements } = startPage(t, { trending: Promise.reject(new Error('Feed unavailable')) });
  await new Promise(setImmediate);
  assert.match(elements.get('[data-trend-rows]').innerHTML, /Prerendered PoC/);
});

test('an empty successful feed replaces stale homepage rows', async t => {
  const { elements } = startPage(t, { trending: { items: [], total_cves: 1, with_pocs: 1, generated: '2026-10-06' } });
  await new Promise(setImmediate);
  assert.match(elements.get('[data-trend-rows]').innerHTML, /No recent PoCs/);
});

test('an index failure stays visible when the optional trending feed arrives later', async t => {
  let finishTrending;
  const trending = new Promise(resolve => { finishTrending = resolve; });
  const { elements } = startPage(t, { search: '?q=widget', trending, indexError: true });
  await new Promise(setImmediate);
  assert.match(elements.get('[data-results]').innerHTML, /could not be loaded/);
  assert.equal(elements.get('[data-results]').hidden, false);
  finishTrending({ items: [], total_cves: 1, with_pocs: 1, generated: '2026-10-06' });
  await new Promise(setImmediate);
  assert.match(elements.get('[data-results]').innerHTML, /could not be loaded/);
  assert.equal(elements.get('[data-results]').hidden, false);
  assert.equal(elements.get('[data-status]').textContent, 'index unavailable');
});

test('late KEV data cannot hide a bookmarked search failure', async t => {
  let finishKev;
  const kev = new Promise(resolve => { finishKev = resolve; });
  const { elements } = startPage(t, {
    search: '?q=widget', trending: new Promise(() => {}), kev, indexError: true
  });
  await new Promise(setImmediate);
  finishKev({ 'CVE-2026-1234': ['2026-10-06', false] });
  await new Promise(setImmediate);
  assert.match(elements.get('[data-results]').innerHTML, /could not be loaded/);
  assert.equal(elements.get('[data-results]').hidden, false);
  assert.equal(elements.get('[data-trending]').hidden, true);
});

for (const sort of ['relevance', 'newest']) {
  test(`late EPSS data refreshes results while respecting ${sort} sort`, async t => {
    const elements = new Map();
    const document = {
      addEventListener() {},
      querySelectorAll: () => [],
      querySelector(selector) {
        if (!elements.has(selector)) {
          elements.set(selector, {
            value: '',
            innerHTML: '',
            addEventListener() {},
            setAttribute() {},
            querySelectorAll: () => []
          });
        }
        return elements.get(selector);
      }
    };
    let finishEpss;
    const pendingEpss = new Promise(resolve => { finishEpss = resolve; });
    const records = ['CVE-2025-1234', 'CVE-2024-1234'].map(cve => ({
      cve,
      desc: 'widget remote execution',
      poc: [`https://github.com/owner/${cve}`]
    }));
    const context = vm.createContext({
      console,
      document,
      performance,
      MessageChannel,
      URLSearchParams,
      location: { pathname: '/', search: `?q=widget&sort=${sort}` },
      window: { matchMedia: () => ({ matches: false }) },
      setTimeout() {},
      clearTimeout() {},
      async fetch(url) {
        const data = url === '/epss.json' ? await pendingEpss
          : url === '/CVE_list.json' ? records
          : url === '/trending_poc.json'
            ? { items: [], generated: '2026-10-06', total_cves: 2, with_pocs: 2 }
            : {};
        return { ok: true, json: async () => data };
      }
    });
    vm.runInContext(script, context);
    t.after(() => vm.runInContext('yieldPort.port1.close(); yieldPort.port2.close();', context));
    const resultIds = () => [...elements.get('[data-results]').innerHTML
      .matchAll(/class="result-id" href="\/([^"]+)"/g)].map(match => match[1]);

    await new Promise(setImmediate);
    assert.deepEqual(resultIds(), ['CVE-2025-1234', 'CVE-2024-1234']);

    finishEpss({ 'CVE-2025-1234': [0.01, 0.1], 'CVE-2024-1234': [0.99, 0.999] });
    await new Promise(setImmediate);
    assert.deepEqual(resultIds(), sort === 'relevance'
      ? ['CVE-2024-1234', 'CVE-2025-1234']
      : ['CVE-2025-1234', 'CVE-2024-1234']);
    assert.match(elements.get('[data-results]').innerHTML, /EPSS 99%/);
  });
}
