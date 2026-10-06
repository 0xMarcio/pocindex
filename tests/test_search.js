'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const { MessageChannel } = require('node:worker_threads');

const script = fs.readFileSync(path.join(__dirname, '../docs/logic.js'), 'utf8');

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
