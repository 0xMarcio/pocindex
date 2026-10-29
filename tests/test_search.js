'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const { MessageChannel } = require('node:worker_threads');

const script = fs.readFileSync(path.join(__dirname, '../docs/logic.js'), 'utf8');

function startPage(t, { search = '', trending, kev = {}, repositories = {}, archives = {}, published = [],
                        indexError = false, cvssError = false, archivesError = false, entries }) {
  const elements = new Map();
  const calls = [];
  const document = {
    addEventListener() {},
    querySelectorAll: () => [],
    querySelector(selector) {
      if (!elements.has(selector)) elements.set(selector, {
        value: '',
        innerHTML: selector === '[data-trend-rows]' ? '<a href="/CVE-2026-1234">Prerendered PoC</a>' : '',
        addEventListener() {}, setAttribute() {},
        // The snapshot links a prerendered homepage carries.
        querySelectorAll: () => selector === '[data-trend-rows]' ? published : []
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
      if (url === '/cvss.json' && cvssError) throw new Error('CVSS unavailable');
      if (url === '/archives.json' && archivesError) throw new Error('Archive index unavailable');
      const data = url === '/trending_poc.json' ? await trending
        : url === '/kev.json' ? await kev
        : url === '/repo_meta.json' ? await repositories
        : url === '/archives.json' ? await archives
        : url === '/CVE_list.json' ? entries || [{ cve: 'CVE-2026-1234', desc: 'widget', poc: ['https://github.com/owner/poc'] }]
          : {};
      return { ok: true, json: async () => data };
    }
  });
  vm.runInContext(script, context);
  t.after(() => vm.runInContext('yieldPort.port1.close(); yieldPort.port2.close();', context));
  return { elements, calls, context };
}

async function searchFixture(t, entries, options = {}) {
  const { context } = startPage(t, { entries, trending: new Promise(() => {}), ...options });
  while (!vm.runInContext('wordIndex.ready', context)) await new Promise(setImmediate);
  return (query, scan = false) => {
    context.query = query;
    return Array.from(vm.runInContext(`runSearch(query, ${scan})`, context), row => row.cve);
  };
}

// A source file saved at a pinned commit, as archives.json lists it under its page.
const COMMIT = '0123456789abcdef0123456789abcdef01234567';
const rawFile = (path, repository = 'owner/poc', commit = COMMIT) =>
  `https://raw.githubusercontent.com/${repository}/${commit}/${path}`;
const savedFile = (original, stamp = '20261022161013') =>
  ({ original, url: `https://web.archive.org/web/${stamp}/${original}`, timestamp: stamp });

test('repository name prefixes beat incidental prose without joining numbered filenames', async t => {
  const search = await searchFixture(t, [
    { cve: 'CVE-2004-0660', desc: 'XSS in (1) show_archives.php, (2) show_news.php', edb: ['https://www.exploit-db.com/exploits/24238'] },
    { cve: 'CVE-2026-109618', desc: 'RCE via OOM corruption', poc: ['https://github.com/researcher/php2shell-poc'] },
    { cve: 'CVE-2026-1000', desc: 'A report mentions php2shell in passing.', poc: ['https://github.com/researcher/unrelated'] },
    { cve: 'CVE-2026-2000', desc: 'Unrelated', poc: ['https://github.com/myphp2shell/unrelated'] }
  ]);
  for (const query of ['php2sh', 'php2shell']) {
    assert.deepEqual(search(query), ['CVE-2026-109618', 'CVE-2026-1000']);
    assert.deepEqual(search(query), search(query, true));
  }
});

test('separator variants have complete indexed results even when more than five records match', async t => {
  const entries = Array.from({ length: 8 }, (_, i) => ({ cve: `CVE-2026-${1000 + i}`,
    desc: `${i < 6 ? 'PANOS' : 'PAN-OS'} vulnerability`, poc: [`https://github.com/owner/poc-${i}`] }));
  entries.push({ cve: 'CVE-2026-2000', desc: 'Pending details', poc: ['https://github.com/owner/lab-pan_os-poc'] });
  const search = await searchFixture(t, entries);
  for (const query of ['panos', 'pan-os', 'pan_os', 'pan.os']) {
    assert.equal(search(query).length, 9);
    assert.deepEqual(search(query), search(query, true));
    assert.deepEqual(search(query), search('panos'));
  }
});

test('an exact CVE beats a longer numeric prefix and supports pasted identifier spellings', async t => {
  const entries = ['CVE-2026-1234', 'CVE-2026-12345', 'CVE-2026-9876'].map(cve => ({
    cve, desc: 'Related issue CVE-2026-1234', poc: ['https://github.com/owner/CVE-2026-1234']
  }));
  const search = await searchFixture(t, entries, { kev: { 'CVE-2026-12345': ['2026-10-21', false] } });
  for (const query of ['CVE-2026-1234', 'cve20261234', 'CVE 2026 1234', 'cve_2026_1234']) {
    assert.equal(search(query)[0], 'CVE-2026-1234');
    assert.deepEqual(search(query), search(query, true));
  }
});

test('multiword identifier names outrank scattered terms and respect exclusions', async t => {
  const search = await searchFixture(t, [
    { cve: 'CVE-2026-1000', desc: 'PHP 2 allows users to execute shell commands', poc: ['https://github.com/owner/unrelated'] },
    { cve: 'CVE-2026-109618', desc: 'RCE via OOM corruption', poc: ['https://github.com/owner/php2shell-poc'] },
    { cve: 'CVE-2026-109619', desc: 'RCE via stale global state', poc: ['https://github.com/owner/lab-php-2-shell'] }
  ]);
  assert.deepEqual(new Set(search('php 2 shell').slice(0, 2)), new Set(['CVE-2026-109618', 'CVE-2026-109619']));
  assert.deepEqual(search('php 2 shell'), search('php 2 shell', true));
  assert.deepEqual(search('php 2 shell -oom'), ['CVE-2026-109619', 'CVE-2026-1000']);
  assert.deepEqual(search('php 2 shell -"stale global"'), ['CVE-2026-109618', 'CVE-2026-1000']);
  assert.deepEqual(search('"php 2 shell"'), ['CVE-2026-109619']);
});

test('repository and file names outrank matching owners and GitHub routing segments', async t => {
  const search = await searchFixture(t, [
    { cve: 'CVE-2026-1000', desc: 'Pending details', poc: ['https://github.com/owner/project/blob/main/issue.py'] },
    { cve: 'CVE-2026-2000', desc: 'An issue in the main component', poc: ['https://github.com/owner/unrelated'] },
    { cve: 'CVE-2026-3000', desc: 'Pending details', poc: ['https://github.com/owner/main-poc'] },
    { cve: 'CVE-2026-4000', desc: 'Pending details', poc: ['https://github.com/owner/project/blob/ref/main.py'] },
    { cve: 'CVE-2026-5000', desc: 'Pending details', poc: ['https://github.com/main/unrelated'] }
  ]);
  assert.deepEqual(new Set(search('main').slice(0, 2)), new Set(['CVE-2026-3000', 'CVE-2026-4000']));
  assert.equal(search('main')[2], 'CVE-2026-2000');
  assert.deepEqual(search('main'), search('main', true));
});

test('collection routing and category folders stay searchable without outranking the subject', async t => {
  const search = await searchFixture(t, [
    { cve: 'CVE-2026-1000', desc: 'Pending details', nuclei: ['https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/example.yaml'] },
    { cve: 'CVE-2026-2000', desc: 'HTTP request smuggling', poc: ['https://github.com/owner/poc'] },
    { cve: 'CVE-2026-3000', desc: 'Pending details', nuclei: ['https://github.com/projectdiscovery/nuclei-templates/blob/main/misc/http-smuggling.yaml'] }
  ]);
  assert.deepEqual(search('http'), ['CVE-2026-3000', 'CVE-2026-2000', 'CVE-2026-1000']);
  assert.deepEqual(search('http'), search('http', true));
  assert.equal(search('nuclei').length, 2);
});

test('aliases, phrases, negatives, named vulnerabilities and typo correction remain usable', async t => {
  const search = await searchFixture(t, [
    { cve: 'CVE-2026-1000', desc: 'WordPress SQL injection', poc: ['https://github.com/owner/wp-poc'] },
    { cve: 'CVE-2026-2000', desc: 'Widget SQL injection', poc: ['https://github.com/owner/widget-poc'] },
    { cve: 'CVE-2026-3000', desc: 'SQL database error with command injection', poc: ['https://github.com/owner/mixed'] },
    { cve: 'CVE-2021-44228', desc: 'Apache Log4j remote code execution', poc: ['https://github.com/owner/log4j-poc'] }
  ]);
  assert.deepEqual(search('"sql injection" -wordpress'), ['CVE-2026-2000']);
  assert.deepEqual(new Set(search('sqli')), new Set(['CVE-2026-1000', 'CVE-2026-2000']));
  assert.deepEqual(search('rce'), ['CVE-2021-44228']);
  assert.deepEqual(search('wordprss'), ['CVE-2026-1000']);
  for (const query of ['"sql injection" -wordpress', 'sqli', 'rce', 'log4shell', 'log-4j']) {
    assert.deepEqual(search(query), search(query, true));
  }
});

test('homepage relative ages advance without refreshing or changing the active search', async t => {
  const { context } = startPage(t, { trending: new Promise(() => {}) });
  await new Promise(setImmediate);
  vm.runInContext("state.query = 'php2shell'; Date.now = () => Date.parse('2026-10-21T20:00:00Z')", context);
  let writes = 0, markup = '';
  const cell = { getAttribute: () => '2026-10-21T19:00:00Z',
    get outerHTML() { return markup; }, set outerHTML(value) { markup = value; writes++; } };
  context.document.querySelectorAll = selector => selector === 'time.trend-age' ? [cell] : [];
  vm.runInContext('refreshTrendAges()', context);
  assert.match(cell.outerHTML, />1 hour ago<\/time>/);
  vm.runInContext('refreshTrendAges()', context);
  assert.equal(writes, 1);
  vm.runInContext("Date.now = () => Date.parse('2026-10-21T21:00:00Z'); refreshTrendAges()", context);
  assert.match(cell.outerHTML, />2 hours ago<\/time>/);
  assert.equal(vm.runInContext('state.query', context), 'php2shell');
});

test('pending CVEs are searchable by identifier and PoC name without NVD metadata', async t => {
  const entries = ['CVE-2026-109618', 'CVE-2026-109619'].map(cve => ({
    cve, desc: 'Official CVE details are pending.', metadata_pending: true,
    poc: ['https://github.com/example/php2shell-poc']
  }));
  for (const query of ['CVE-2026-109618', 'CVE-2026-109619', 'php2shell']) {
    const { elements } = startPage(t, { search: `?q=${query}`, entries, trending: new Promise(() => {}) });
    await new Promise(setImmediate);
    const html = elements.get('[data-results]').innerHTML;
    assert.match(html, /CVE metadata pending/);
    assert.match(html, /https:\/\/github.com\/example\/php2shell-poc/);
    assert.match(html, new RegExp(query === 'php2shell' ? 'CVE-2026-109618' : query));
  }
});

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

test('repository and artifact rows distinguish zero, missing metadata and non-repository links', async t => {
  const { context } = startPage(t, { trending: new Promise(() => {}) });
  await new Promise(setImmediate);
  vm.runInContext('repoMeta = { "owner/poc": [0, "2026-10-21"] };', context);
  for (const suffix of ['', '/blob/main/reproduce.py']) {
    const row = vm.runInContext(`pocRow('https://github.com/Owner/PoC${suffix}', true)`, context);
    assert.match(row, /0 <span class="star">★<\/span>/);
    assert.match(row, /Repository stars: owner\/poc/);
    assert.match(row, /Repository last push: 2026-10-21 UTC/);
  }
  const missing = vm.runInContext("pocRow('https://github.com/owner/missing')", context);
  assert.match(missing, /Repository stars: owner\/missing \(unavailable\)/);
  assert.match(missing, />N\/A<\/span>/);
  assert.doesNotMatch(missing, /★/);
  const external = vm.runInContext("trendRow({url:'https://www.exploit-db.com/exploits/12345', stars:5000, artifact:true}, true)", context);
  assert.match(external, /No GitHub repository/);
  assert.doesNotMatch(external, /★|5\.0k/);
  const today = new Date().toISOString().slice(0, 10);
  vm.runInContext(`repoMeta['owner/poc'][1] = '${today}'`, context);
  assert.match(vm.runInContext("repositoryCells('https://github.com/owner/poc')", context), />today<\/span>/);
});

test('late repository metadata reorders a long PoC list by stars regardless of CVE spelling', async t => {
  let finishMetadata;
  const repositories = new Promise(resolve => { finishMetadata = resolve; });
  const named = 'https://github.com/owner/CVE-2021-1675';
  const alias = 'https://github.com/nemo-wq/PrintNightmare-CVE-2021-34527';
  const unknown = 'https://github.com/owner/unknown';
  const entries = [{ cve: 'CVE-2021-1675', desc: 'PrintNightmare',
    poc: [named, unknown, ...Array.from({length: 25}, (_, i) => `https://github.com/owner/CVE-2021-1675-${i}`), alias] }];
  const { context, elements } = startPage(t, { search: '?q=CVE-2021-1675', entries, repositories,
                                              trending: new Promise(() => {}) });
  await new Promise(setImmediate);
  vm.runInContext("state.pocOpen.add('CVE-2021-1675'); renderResults(null)", context);
  finishMetadata({ 'owner/cve-2021-1675': [0, '2026-10-21'], 'nemo-wq/printnightmare-cve-2021-34527': [177, '2021-06-29'] });
  await new Promise(setImmediate);
  const links = Array.from(vm.runInContext('rankedLinks(dataset[0])', context));
  assert.equal(links.length, 28);
  assert.deepEqual(links.slice(0, 2), [alias, named]);
  assert.ok(links.indexOf(unknown) > 1);
  const html = elements.get('[data-results]').innerHTML;
  assert.ok(html.indexOf(`href="${alias}"`) < html.indexOf(`href="${named}"`));
  assert.match(html, /177 <span class="star">★/);
  assert.equal(vm.runInContext("state.pocOpen.has('CVE-2021-1675')", context), true);
});

test('an open tab refreshes one complete data snapshot without losing its search or expansion', async t => {
  let finishOldMetadata;
  const repositories = new Promise(resolve => { finishOldMetadata = resolve; });
  const original = { generated: '2026-10-21T10:00:00Z', with_pocs: 1, total_cves: 1, items: [], landed: [] };
  const { context, elements } = startPage(t, { search: '?q=widget&src=github&sort=newest', repositories, trending: original });
  await new Promise(setImmediate);
  vm.runInContext("state.pocOpen.add('CVE-2026-1234')", context);
  const feed = { ...original, generated: '2026-10-21T12:00:00Z' };
  const entries = [{ cve: 'CVE-2026-1234', desc: 'widget', poc: ['https://github.com/owner/current'] }];
  const data = { '/trending_poc.json': feed, '/CVE_list.json': entries,
    '/repo_meta.json': { 'owner/current': [42, '2026-10-21'] }, '/cvss.json': {},
    '/advisories.json': {}, '/nuclei.json': {}, '/kev.json': {}, '/epss.json': {} };
  context.fetch = async url => ({ ok: true, json: async () => data[url.split('?')[0]] });
  assert.equal(await vm.runInContext('refreshData(true)', context), true);
  finishOldMetadata({ 'owner/current': [1, '2020-01-01'] });
  await new Promise(setImmediate);
  assert.equal(vm.runInContext('state.query', context), 'widget');
  assert.equal(vm.runInContext('state.sort', context), 'NEWEST');
  assert.equal(vm.runInContext("[...state.filters.source].join(',')", context), 'GITHUB');
  assert.equal(vm.runInContext("state.pocOpen.has('CVE-2026-1234')", context), true);
  assert.equal(vm.runInContext("repoMeta['owner/current'][0]", context), 42);
  assert.match(elements.get('[data-results]').innerHTML, /42 <span class="star">★/);
  assert.doesNotMatch(elements.get('[data-results]').innerHTML, /href="https:\/\/github.com\/owner\/poc"/);
  assert.equal(await vm.runInContext('refreshData(true)', context), false);
});

test('failed or mixed-generation refreshes keep the previous searchable data', async t => {
  const original = { generated: '2026-10-21T10:00:00Z', with_pocs: 1, total_cves: 1, items: [], landed: [] };
  const { context } = startPage(t, { search: '?q=widget', trending: original });
  await new Promise(setImmediate);
  for (const failure of ['download', 'changed']) {
    let feeds = 0;
    context.fetch = async url => {
      const file = url.split('?')[0];
      if (failure === 'download' && file === '/repo_meta.json') throw new Error('Unavailable');
      const payload = file === '/trending_poc.json'
        ? { ...original, generated: ++feeds > 1 && failure === 'changed' ? 'newer' : 'new' }
        : file === '/CVE_list.json' ? [{ cve: 'CVE-2026-1234', desc: 'changed', poc: [] }] : {};
      return { ok: true, json: async () => payload };
    };
    assert.equal(await vm.runInContext('refreshData(true)', context), false);
    assert.equal(vm.runInContext('dataset[0].desc', context), 'widget');
    assert.equal(vm.runInContext('indexMeta.generated', context), original.generated);
  }
});

test('failed enrichment cannot silently apply bookmarked filters against empty data', async t => {
  const { context, elements } = startPage(t, {
    search: '?q=widget&kev=1&sev=critical', cvssError: true,
    kev: Promise.reject(new Error('KEV unavailable')), trending: new Promise(() => {})
  });
  await new Promise(setImmediate);
  assert.equal(vm.runInContext('state.kevOnly', context), true);
  assert.equal(vm.runInContext('state.filters.severity.size', context), 1);
  assert.match(elements.get('[data-results]').innerHTML, /href="\/CVE-2026-1234"/);
  assert.match(elements.get('[data-notices]').textContent, /KEV filter unavailable/);
  assert.match(elements.get('[data-notices]').textContent, /severity filter unavailable/);
  assert.equal(elements.get('[data-notices]').hidden, false);
});

test('requested filters recover after an outage without losing the bookmark or ignoring a clear', async t => {
  for (const cleared of [false, true]) {
    const entries = ['CVE-2026-1234', 'CVE-2026-1235'].map(cve => ({ cve, desc: 'widget', poc: ['https://github.com/owner/' + cve] }));
    const feed = { generated: '2026-10-21T10:00:00Z', with_pocs: 2, total_cves: 2, items: [], landed: [] };
    const { context, elements } = startPage(t, { search: '?q=widget&kev=1&sev=critical', entries, cvssError: true,
      kev: Promise.reject(new Error('Unavailable')), trending: feed });
    await new Promise(setImmediate);
    assert.match(elements.get('[data-results]').innerHTML, /href="\/CVE-2026-1235"/);
    if (cleared) vm.runInContext('state.kevOnly = false; state.filters.severity = new Set(FILTER_OPTIONS.severity.map(([value]) => value))', context);
    context.fetch = async url => ({ ok: true, json: async () => {
      const file = url.split('?')[0];
      return file === '/trending_poc.json' ? feed : file === '/CVE_list.json' ? entries
        : file === '/kev.json' ? { 'CVE-2026-1234': ['2026-10-21', false] }
        : file === '/cvss.json' ? { 'CVE-2026-1234': [['3.1', 9.8, 'CRITICAL', '', 'nvd', 'Primary']] } : {};
    }});
    assert.equal(await vm.runInContext('refreshData(true)', context), true);
    assert.equal(vm.runInContext('state.kevOnly', context), !cleared);
    assert.equal(vm.runInContext('state.filters.severity.size', context), cleared ? 4 : 1);
    assert.equal(elements.get('[data-results]').innerHTML.includes('href="/CVE-2026-1235"'), cleared);
    assert.equal(elements.get('[data-notices]').hidden, true);
  }
});

test('equal-star links use the same code-point ordering as static CVE pages', async t => {
  const urls = ['poc_1', 'poc1', 'poc-1'].map(name => 'https://github.com/owner/' + name);
  const entries = [{ cve: 'CVE-2026-1234', desc: 'widget', poc: urls }];
  const repositories = Object.fromEntries(urls.map(url => [url.slice('https://github.com/'.length), [10, '2026-10-21']]));
  const { context } = startPage(t, { entries, repositories, trending: new Promise(() => {}) });
  await new Promise(setImmediate);
  assert.deepEqual(Array.from(vm.runInContext('rankedLinks(dataset[0])', context)), [...urls].sort());
});

test('missing repository metadata is visible and retried even without a newer publication', async t => {
  const feed = { generated: '2026-10-21T10:00:00Z', with_pocs: 1, total_cves: 1, items: [], landed: [] };
  const entries = [{ cve: 'CVE-2026-1234', desc: 'widget', poc: ['https://github.com/owner/poc'] }];
  const { context, elements } = startPage(t, { search: '?q=widget', entries, trending: feed,
    repositories: Promise.reject(new Error('Metadata temporarily unavailable')) });
  await new Promise(setImmediate);
  assert.match(elements.get('[data-notices]').textContent, /repository metadata unavailable/);
  context.fetch = async url => ({ ok: true, json: async () => {
    const file = url.split('?')[0];
    return file === '/trending_poc.json' ? feed : file === '/CVE_list.json' ? entries
      : file === '/repo_meta.json' ? { 'owner/poc': [0, '2026-10-21'] } : {};
  }});
  assert.equal(await vm.runInContext('refreshData(true)', context), true);
  assert.match(elements.get('[data-results]').innerHTML, /0 <span class="star">★/);
  assert.doesNotMatch(elements.get('[data-notices]').textContent, /repository metadata unavailable/);
});

test('curated artifact paths survive search rendering without duplicate repository roots', async t => {
  const { context } = startPage(t, { trending: new Promise(() => {}) });
  await new Promise(setImmediate);
  const base = 'https://github.com/google/security-research';
  const variants = ['lts', 'mitigation'].map(kind => `${base}/tree/master/pocs/linux/kernelctf/CVE-2024-26642_${kind}`);
  const template = 'https://github.com/projectdiscovery/nuclei-templates/blob/main/http/Test.yaml?version=One#Request';
  const entry = { cve: 'CVE-2024-26642', poc: [base, 'https://github.com/example/poc', 'https://github.com/EXAMPLE/POC/blob/main/exploit.py'],
    collections: [...variants, variants[0].replace('google/security-research', 'GOOGLE/Security-Research')],
    nuclei: [template, template.replace('Test.yaml', 'test.yaml')] };
  context.variantEntry = entry;
  vm.runInContext(`metadata = { 'CVE-2024-26642': { advisories: [[${JSON.stringify(base)}, ['Exploit']]] } };`, context);
  for (const fn of ['entryLinks', 'rankedLinks']) {
    const links = Array.from(vm.runInContext(`${fn}(variantEntry)`, context));
    assert.equal(links.length, 5);
    for (const url of [...variants, template, template.replace('Test.yaml', 'test.yaml')]) assert.ok(links.includes(url), url);
    assert.ok(!links.includes(base));
  }
  const html = vm.runInContext('resultRow(variantEntry)', context);
  for (const url of variants) assert.ok(html.includes(`href="${url}"`));
  assert.match(html, /CVE REFERENCES <span>1<\/span>/);
  assert.ok(html.includes(`<a class="plain" href="${base}"`));
  assert.equal(vm.runInContext(`normalizedLink(${JSON.stringify(variants[0])}) === normalizedLink(${JSON.stringify(base)})`, context), true);
});

test('advisories from a PoC repository are hidden only when they repeat a listed PoC URL', async t => {
  const { context } = startPage(t, { trending: new Promise(() => {}) });
  await new Promise(setImmediate);
  const repo = 'https://github.com/owner/poc';
  const template = 'https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-1234.yaml';
  const distinct = [`${repo}/commit/0123abc`, `${repo}/issues/7`, `${repo}/releases/tag/v1.2.3`, `${repo}/blob/main/exploit.py`,
    template.replace('CVE-2026-1234', 'cve-2026-1234'), `${template}?plain=1`, `${template}#L10`];
  const duplicates = [repo, 'https://github.com/OWNER/PoC', template,
    template.replace('projectdiscovery/nuclei-templates', 'ProjectDiscovery/Nuclei-Templates')];
  context.advisoryEntry = { cve: 'CVE-2026-1234', poc: [repo, `${repo}/blob/main/exploit.py`], nuclei: [template] };
  context.advisoryRows = [...duplicates, ...distinct].map(url => [url, ['Patch']]);
  vm.runInContext("metadata = { 'CVE-2026-1234': { advisories: advisoryRows } }; state.advisoryOpen.add('CVE-2026-1234')", context);
  const html = vm.runInContext('resultRow(advisoryEntry)', context);
  assert.match(html, /2 linked PoCs/);
  const advisories = html.slice(html.indexOf('<div class="advisory-list">'));
  assert.match(advisories, /CVE REFERENCES <span>7<\/span>/);
  assert.deepEqual([...advisories.matchAll(/class="plain" href="([^"]+)"/g)].map(match => match[1]), distinct);
});

test('CVE references label neutral and Exploit-only links as nofollow references below VENDOR, PATCH and ADVISORY', async t => {
  const { context } = startPage(t, { trending: new Promise(() => {}) });
  await new Promise(setImmediate);
  const rows = [
    ['https://vendor.example/advisory', ['Vendor Advisory', 'Patch', 'Exploit'], 'VENDOR', 'noopener'],
    ['https://github.com/vendor/project/commit/0123abc', ['Patch', 'Exploit'], 'PATCH', 'noopener'],
    ['https://lists.example/thread', ['Third Party Advisory', 'Exploit'], 'ADVISORY', 'noopener'],
    ['https://research.example/report', ['Third Party Advisory', 'CVE Record'], 'ADVISORY', 'noopener'],
    ['https://github.com/advisories/GHSA-2345-6789-abcd', ['GitHub Advisory'], 'ADVISORY', 'noopener'],
    ['https://vendor.example/workaround', ['Mitigation'], 'ADVISORY', 'noopener'],
    ['https://cert.example/notes/1234', ['Advisory'], 'ADVISORY', 'noopener'],
    ['https://github.com/vendor/project', ['Product', 'CVE Record'], 'REFERENCE', 'nofollow noopener'],
    ['https://github.com/vendor/project/issues/7', ['Issue Tracking'], 'REFERENCE', 'nofollow noopener'],
    ['https://github.com/vendor/project/releases/tag/v1.2.3', ['Release Notes'], 'REFERENCE', 'nofollow noopener'],
    ['https://blog.example/analysis', ['Reference'], 'REFERENCE', 'nofollow noopener'],
    ['https://cna.example/record', ['CVE Record'], 'REFERENCE', 'nofollow noopener'],
    ['https://research.example/reproduction', ['Exploit', 'CVE Record'], 'REFERENCE', 'nofollow noopener'],
    ['https://github.com/user-attachments/files/24473682/environment_newline_injection.sh', ['Exploit'], 'REFERENCE', 'nofollow noopener'],
    ['https://www.rfc-editor.org/rfc/rfc9110', ['Exploit'], 'REFERENCE', 'nofollow noopener'],
    ['https://archive.example/untagged', [], 'REFERENCE', 'nofollow noopener']
  ];
  context.referenceEntry = { cve: 'CVE-2026-1234', poc: ['https://github.com/owner/poc'] };
  context.referenceRows = rows.map(([url, tags]) => [url, tags]);
  vm.runInContext("metadata = { 'CVE-2026-1234': { advisories: referenceRows } }; state.advisoryOpen.add('CVE-2026-1234')", context);
  const html = vm.runInContext('resultRow(referenceEntry)', context);
  assert.match(html, /1 linked PoC</);
  assert.doesNotMatch(html, /CREDIBLE ADVISORIES/);
  const references = html.slice(html.indexOf('<div class="advisory-list">'));
  assert.match(references, /CVE REFERENCES <span>16<\/span>/);
  const pattern = /title="([^"]*)">([A-Z]+)<\/span><a class="plain" href="([^"]+)" target="_blank" rel="([^"]+)"/g;
  assert.deepEqual([...references.matchAll(pattern)].map(([, title, tag, url, rel]) => [url, title, tag, rel]),
    rows.map(([url, tags, tag, rel]) => [url, tags.join(', ') || 'Reference', tag, rel]));
});

test('PoC rows link a confirmed Wayback snapshot and otherwise offer a labelled lookup', async t => {
  const archived = 'https://github.com/owner/archived-poc';
  const other = 'https://www.exploit-db.com/exploits/50592';
  const snapshot = `https://web.archive.org/web/20251021093000/${archived}`;
  const entries = [{ cve: 'CVE-2026-1234', desc: 'widget', poc: [archived], edb: [other] }];
  const { elements } = startPage(t, { search: '?q=widget', entries, trending: new Promise(() => {}),
    archives: { [archived]: { url: snapshot, timestamp: '20251021093000' } } });
  await new Promise(setImmediate);
  const html = elements.get('[data-results]').innerHTML;
  assert.ok(html.includes(`<a class="wayback is-snapshot" href="${snapshot}" target="_blank" rel="nofollow noopener" ` +
    'title="Wayback Machine page snapshot, captured 2025-10-21 09:30 UTC" ' +
    'aria-label="snapshot of owner/archived-poc on the Wayback Machine, captured 2025-10-21 09:30 UTC">snapshot</a>'));
  assert.ok(html.includes(`<a class="wayback is-lookup" href="https://web.archive.org/web/*/${other}" target="_blank" rel="nofollow noopener" ` +
    'title="Search the Wayback Machine for captures; none confirmed" ' +
    'aria-label="find archive of exploit-db.com/50592 on the Wayback Machine">find archive</a>'));
  assert.equal(html.match(/class="wayback /g).length, 2);
  // The original stays the PoC link and the count is unchanged.
  assert.ok(html.includes(`<a href="${archived}" target="_blank" rel="nofollow noopener">archived-poc</a>`));
  assert.match(html, /2 linked PoCs/);
  assert.doesNotMatch(html, /web\.archive\.org\/save/);
});

test('malformed or untrusted snapshot records fall back to a lookup and links are escaped', async t => {
  const { context } = startPage(t, { trending: new Promise(() => {}) });
  await new Promise(setImmediate);
  const url = 'https://github.com/owner/poc';
  const stamp = '20251021093000';
  const snapshot = `https://web.archive.org/web/${stamp}/${url}`;
  const untrusted = [
    { url: `http://web.archive.org/web/${stamp}/${url}`, timestamp: stamp },
    { url: `https://web.archive.org.example/web/${stamp}/${url}`, timestamp: stamp },
    { url: `https://example.com/web.archive.org/web/${stamp}/${url}`, timestamp: stamp },
    { url: `https://user@web.archive.org/web/${stamp}/${url}`, timestamp: stamp },
    { url: `https://web.archive.org/save/${url}`, timestamp: stamp },
    { url: `https://web.archive.org/web/*/${url}`, timestamp: stamp },
    { url: `https://web.archive.org/web/${stamp}id_/${url}`, timestamp: stamp },
    { url: `https://web.archive.org/web/2025102109300/${url}`, timestamp: '2025102109300' },
    { url: `https://web.archive.org/web/20250230093000/${url}`, timestamp: '20250230093000' },
    { url: `https://web.archive.org/web/20251021240000/${url}`, timestamp: '20251021240000' },
    { url: `https://web.archive.org/web/19951021093000/${url}`, timestamp: '19951021093000' },
    { url: snapshot, timestamp: '20251021093001' },
    { url: snapshot, timestamp: Number(stamp) },
    { url: snapshot },
    { url: `https://web.archive.org/web/${stamp}/javascript:alert(1)`, timestamp: stamp },
    { url: `https://web.archive.org/web/${stamp}/https://example.com/poc`, timestamp: stamp },
    { url: `${snapshot}"><script>alert(1)</script>`, timestamp: stamp },
    { url: `${snapshot} onmouseover=alert(1)`, timestamp: stamp },
    snapshot, null, [snapshot, stamp]
  ];
  for (const record of untrusted) {
    context.record = record;
    const row = vm.runInContext(`archives = { ${JSON.stringify(url)}: record }; pocRow(${JSON.stringify(url)})`, context);
    assert.ok(row.includes(`<a class="wayback is-lookup" href="https://web.archive.org/web/*/${url}"`), JSON.stringify(record));
    assert.doesNotMatch(row, /is-snapshot|<script|onmouseover/);
  }
  // The Wayback Machine may record the scheme, www. or default port differently.
  context.record = { url: `https://web.archive.org/web/${stamp}/http://www.github.com:80/owner/poc`, timestamp: stamp };
  assert.match(vm.runInContext(`archives = { ${JSON.stringify(url)}: record }; pocRow(${JSON.stringify(url)})`, context),
    /class="wayback is-snapshot"/);
  const query = "https://example.com/exploit?id=1&name='x'";
  context.record = { url: `https://web.archive.org/web/${stamp}/${query}`, timestamp: stamp };
  const linked = vm.runInContext(`archives = { ${JSON.stringify(query)}: record }; archiveLink(${JSON.stringify(query)}, '<b>"label"</b>')`, context);
  assert.ok(linked.includes(`href="https://web.archive.org/web/${stamp}/https://example.com/exploit?id=1&amp;name=&#39;x&#39;"`));
  assert.ok(linked.includes('aria-label="snapshot of &lt;b&gt;&quot;label&quot;&lt;/b&gt; on the Wayback Machine, captured 2025-10-21 09:30 UTC"'));
  const lookup = vm.runInContext(`archives = {}; archiveLink(${JSON.stringify(query)}, 'label')`, context);
  assert.ok(lookup.includes('href="https://web.archive.org/web/*/https://example.com/exploit?id=1&amp;name=&#39;x&#39;"'));
});

test('an archived fallback stands in for its original without a second archive link', async t => {
  const original = 'https://github.com/owner/php2shell-poc';
  const fallback = `https://web.archive.org/web/20240101120000/${original}`;
  const live = 'https://github.com/owner/live';
  const entries = [
    { cve: 'CVE-2026-1000', desc: 'Pending details', poc: [live, fallback] },
    { cve: 'CVE-2026-2000', desc: 'A report mentions php2shell in passing.', poc: ['https://github.com/owner/unrelated'] }
  ];
  const { context, elements } = startPage(t, { search: '?q=php2shell', entries, trending: new Promise(() => {}),
    repositories: { 'owner/php2shell-poc': [50, '2024-01-01'], 'owner/live': [10, '2026-10-01'] },
    archives: { [original]: { url: fallback, timestamp: '20240101120000' } } });
  while (!vm.runInContext('wordIndex.ready', context)) await new Promise(setImmediate);
  await new Promise(setImmediate);
  const search = (query, scan = false) => {
    context.query = query;
    return Array.from(vm.runInContext(`runSearch(query, ${scan})`, context), row => row.cve);
  };
  // Matched, filtered and ranked as the original would be, not as web.archive.org.
  assert.deepEqual(search('php2shell'), ['CVE-2026-1000', 'CVE-2026-2000']);
  assert.deepEqual(search('php2shell'), search('php2shell', true));
  assert.deepEqual(search('archive'), []);
  assert.deepEqual([...vm.runInContext('entrySources(dataset[0])', context)], ['GITHUB']);
  assert.deepEqual(Array.from(vm.runInContext('rankedLinks(dataset[0])', context)), [fallback, live]);
  const html = elements.get('[data-results]').innerHTML;
  assert.match(html, /2 linked PoCs/);
  assert.ok(html.includes(`owner<span class="poc-sep"> / </span><a href="${fallback}" ` +
    'aria-label="php2shell-poc, archived page snapshot captured 2024-01-01 12:00 UTC" target="_blank" rel="nofollow noopener">php2shell-poc</a>'));
  assert.ok(html.includes('<span class="wayback is-archived" title="Wayback Machine page snapshot captured 2024-01-01 12:00 UTC, ' +
    'linked in place of the original" aria-hidden="true">ARCHIVED</span>'));
  // The lost original is never linked, and the snapshot gets no archive link of its own.
  assert.ok(!html.includes(`href="${original}"`));
  assert.ok(!html.includes(`/web/*/${fallback}`));
  assert.equal(html.match(/class="wayback is-lookup"/g).length, 2);
  const template = 'https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44228.yaml';
  assert.match(vm.runInContext(`pocRow('https://web.archive.org/web/20240101120000/${template}', true)`, context),
    /<span class="poc-tag is-nuclei"[^>]*>NUCLEI<\/span><a href="https:\/\/web\.archive\.org\/web\/20240101120000\/https:[^"]+" aria-label="CVE-2021-44228\.yaml, archived page snapshot captured 2024-01-01 12:00 UTC"[^>]*>CVE-2021-44228\.yaml<\/a>/);
  // Other archive links, readable or not, get no Wayback control at all.
  for (const url of ['https://web.archive.org/web/2011/https://example.com/old', 'https://archive.org/details/exploit-kit']) {
    assert.doesNotMatch(vm.runInContext(`pocRow(${JSON.stringify(url)})`, context), /class="wayback/);
  }
});

test('saved files are disclosed beside a snapshot or a lookup without counting as PoCs', async t => {
  const repo = 'https://github.com/owner/poc';
  const pending = 'https://github.com/Owner/Other-PoC';
  const report = 'https://hackerone.com/reports/123456';
  const live = 'https://github.com/owner/live';
  const page = `https://web.archive.org/web/20261022160913/${repo}`;
  const newest = savedFile(rawFile('poc.py'));
  const spaced = savedFile(rawFile('src/exploit%20one.py'));
  const json = savedFile(`${report}.json`);
  const entries = [{ cve: 'CVE-2026-1234', desc: 'widget', poc: [repo, pending, report, live] }];
  const archives = {
    // One capture per file, the latest, however often the record lists it.
    [repo]: { url: page, timestamp: '20261022160913',
      files: [spaced, savedFile(rawFile('poc.py'), '20261021120000'), newest, newest] },
    // A page whose own snapshot is still pending.
    [pending]: { files: [savedFile(rawFile('run.sh', 'owner/other-poc'))] },
    [report]: { files: [json] },
    // Each file is also listed under its own original, which is no row.
    [newest.original]: { url: newest.url, timestamp: newest.timestamp }
  };
  const { elements } = startPage(t, { search: '?q=widget', entries, archives, trending: new Promise(() => {}),
    repositories: { 'owner/live': [90, '2026-10-01'], 'owner/poc': [50, '2026-10-01'], 'owner/other-poc': [10, '2026-10-01'] } });
  await new Promise(setImmediate);
  const html = elements.get('[data-results]').innerHTML;
  // Rows keep their star order and count, and each keeps one Wayback control.
  const order = [live, repo, pending, report].map(url => html.indexOf(`href="${url}"`));
  assert.ok(order[0] >= 0);
  assert.deepEqual([...order].sort((a, b) => a - b), order);
  assert.match(html, /4 linked PoCs/);
  assert.equal(html.match(/class="wayback /g).length, 4);
  assert.equal(html.match(/<details /g).length, 3);
  assert.ok(html.includes(`<div class="poc-archive"><a class="wayback is-snapshot" href="${page}"`));
  assert.ok(html.includes('snapshot</a><details class="sources" style="--files:2" data-sources="https://github.com/owner/poc">' +
    '<summary title="Wayback Machine captures of individual files at pinned commits, not a copy of the whole repository" ' +
    'aria-label="2 files saved from owner/poc">2 files</summary><div class="sources-list">' +
    `<a href="${newest.url}" target="_blank" rel="nofollow noopener" ` +
    'title="Wayback Machine capture of poc.py at commit 0123456, 2026-10-22 16:10 UTC" ' +
    'aria-label="poc.py at commit 0123456 of owner/poc, Wayback Machine capture 2026-10-22 16:10 UTC">poc.py</a>' +
    `<a href="${spaced.url}" target="_blank" rel="nofollow noopener" ` +
    'title="Wayback Machine capture of src/exploit one.py at commit 0123456, 2026-10-22 16:10 UTC" ' +
    'aria-label="src/exploit one.py at commit 0123456 of owner/poc, Wayback Machine capture 2026-10-22 16:10 UTC">' +
    'src/exploit one.py</a></div></details></div>'));
  assert.ok(!html.includes('20261021120000'));
  assert.ok(html.includes(`find archive</a><details class="sources" style="--files:1" data-sources="${pending}">` +
    '<summary title="Wayback Machine captures of individual files at pinned commits, not a copy of the whole repository" ' +
    'aria-label="1 file saved from Owner/Other-PoC">1 file</summary>'));
  assert.ok(html.includes(`find archive</a><details class="sources" style="--files:1" data-sources="${report}">` +
    '<summary title="Wayback Machine capture of the report JSON" aria-label="1 file saved from hackerone.com/reports/123456">' +
    `1 file</summary><div class="sources-list"><a href="${json.url}" target="_blank" rel="nofollow noopener" ` +
    'title="Wayback Machine capture of 123456.json, the report JSON, 2026-10-22 16:10 UTC" ' +
    'aria-label="123456.json, the report JSON of hackerone.com/reports/123456, Wayback Machine capture 2026-10-22 16:10 UTC">' +
    '123456.json</a></div></details>'));
  // No saved file or snapshot is looked up again.
  assert.doesNotMatch(html, /\/web\/\*\/https:\/\/(?:web\.archive\.org|raw\.githubusercontent\.com|hackerone\.com\/reports\/123456\.json)/);
});

test('saved files must be captures of the linked page\'s own files', async t => {
  const { context } = startPage(t, { trending: new Promise(() => {}) });
  await new Promise(setImmediate);
  const disclosed = (parent, files) => {
    context.record = { files };
    return vm.runInContext(`archives = { ${JSON.stringify(parent)}: record }; sourceFiles(${JSON.stringify(parent)}, 'label')`, context);
  };
  const repo = 'https://github.com/owner/poc';
  const good = savedFile(rawFile('poc.py'));
  const stamp = good.timestamp;
  // GitHub names repositories without regard to case or a .git suffix.
  for (const parent of [repo, 'https://github.com/Owner/POC.git', 'https://www.github.com/owner/poc/blob/main/README.md']) {
    assert.match(disclosed(parent, [good]), /1 file<\/summary>/, parent);
  }
  for (const file of [
    savedFile(rawFile('poc.py', 'owner/other')),
    savedFile(rawFile('poc.py', 'other/poc')),
    savedFile(rawFile('poc.py', 'owner/poc', 'main')),
    savedFile(rawFile('poc.py', 'owner/poc', COMMIT.slice(1))),
    savedFile(rawFile('poc.py', 'owner/poc', COMMIT.toUpperCase())),
    // A dot segment would open another repository's file.
    savedFile(rawFile(`../../other/poc/${COMMIT}/poc.py`)),
    savedFile(rawFile('%2e%2E/poc.py')),
    savedFile(rawFile('./poc.py')),
    savedFile(rawFile('src//poc.py')),
    savedFile(rawFile('poc.py?token=1')),
    savedFile(rawFile('poc.py#L1')),
    savedFile(`http://raw.githubusercontent.com/owner/poc/${COMMIT}/poc.py`),
    savedFile(`https://raw.githubusercontent.com.example/owner/poc/${COMMIT}/poc.py`),
    savedFile(`https://gist.githubusercontent.com/owner/poc/raw/${COMMIT}/poc.py`),
    savedFile(`https://github.com/owner/poc/blob/${COMMIT}/poc.py`),
    savedFile(`https://example.com/owner/poc/${COMMIT}/poc.py`),
    savedFile('https://hackerone.com/reports/123456.json'),
    // An archive link is never saved again.
    savedFile(good.url),
    { ...good, url: savedFile(rawFile('other.py')).url },
    { ...good, url: `https://web.archive.org/web/${stamp}/https://example.com/owner/poc/${COMMIT}/poc.py` },
    { ...good, timestamp: '20261022161014' },
    { ...good, timestamp: Number(stamp) },
    { ...good, url: `https://web.archive.org/web/${stamp}id_/${good.original}` },
    { ...good, url: `https://web.archive.org/web/*/${good.original}` },
    { ...good, url: `http://web.archive.org/web/${stamp}/${good.original}` },
    { ...good, url: `https://web.archive.org/web/20250230093000/${good.original}`, timestamp: '20250230093000' },
    { url: good.url, timestamp: stamp },
    good.url, null, [good]
  ]) {
    assert.equal(disclosed(repo, [file]), '', JSON.stringify(file));
  }
  for (const files of [good, 'files', null, {}]) assert.equal(disclosed(repo, files), '', JSON.stringify(files));
  // Advisories, gists, other hosts and files themselves hold no repository files.
  for (const parent of ['https://github.com/owner/poc/security/advisories/GHSA-1234-5678-9abc', 'https://gist.github.com/owner/0123',
    'https://example.com/owner/poc', rawFile('poc.py', 'owner/poc', 'main'), rawFile(`../../other/poc/${COMMIT}/poc.py`)]) {
    assert.equal(disclosed(parent, [good]), '', parent);
  }
  // A HackerOne report holds its own report JSON and nothing else.
  const json = savedFile('https://hackerone.com/reports/123456.json');
  for (const parent of ['https://hackerone.com/reports/123456', 'https://www.hackerone.com/reports/123456/',
    'https://hackerone.com/reports/123456?subject=x']) {
    assert.match(disclosed(parent, [json]), /1 file<\/summary>/, parent);
  }
  for (const [parent, file] of [
    ['https://hackerone.com/reports/123456', savedFile('https://hackerone.com/reports/654321.json')],
    ['https://hackerone.com/reports/123456', savedFile('https://hackerone.example/reports/123456.json')],
    ['https://hackerone.com/reports/123456', savedFile('https://hackerone.com/reports/123456')],
    ['https://hackerone.com/reports/123456', savedFile('https://hackerone.com/reports/123456.json?x=1')],
    ['https://hackerone.com/reports/123456', good],
    ['https://hackerone.com/reports/123456.json', json],
    ['https://hackerone.com/bugs?report_id=123456', json],
    ['https://example.com/reports/123456', json]
  ]) {
    assert.equal(disclosed(parent, [file]), '', `${parent} ${JSON.stringify(file)}`);
  }
});

test('saved file names, links and labels are escaped', async t => {
  const { context } = startPage(t, { trending: new Promise(() => {}) });
  await new Promise(setImmediate);
  const repo = 'https://github.com/owner/poc';
  const odd = savedFile(rawFile("x%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E/it's.py"));
  context.record = { files: [odd, savedFile(rawFile('100%.py'))] };
  const html = vm.runInContext(`archives = { ${JSON.stringify(repo)}: record }; sourceFiles(${JSON.stringify(repo)}, '<b>"label"</b>')`, context);
  assert.ok(html.includes(`<a href="${odd.url.replace("'", '&#39;')}" target="_blank"`));
  assert.ok(html.includes('aria-label="x&quot;&gt;&lt;img src=x onerror=alert(1)&gt;/it&#39;s.py at commit 0123456 of ' +
    '&lt;b&gt;&quot;label&quot;&lt;/b&gt;, Wayback Machine capture 2026-10-22 16:10 UTC">' +
    'x&quot;&gt;&lt;img src=x onerror=alert(1)&gt;/it&#39;s.py</a>'));
  assert.ok(html.includes('aria-label="2 files saved from &lt;b&gt;&quot;label&quot;&lt;/b&gt;"'));
  // A malformed escape is shown as written.
  assert.ok(html.includes('>100%.py</a>'));
  assert.doesNotMatch(html, /<img|<b>|"label"/);
});

test('an archived fallback discloses its original\'s saved files and no file repeats a row', async t => {
  const original = 'https://github.com/owner/gone-poc';
  const fallback = `https://web.archive.org/web/20240101120000/${original}`;
  const exploit = savedFile(rawFile('exploit.c', 'owner/gone-poc'));
  const repo = 'https://github.com/owner/poc';
  const listed = savedFile(rawFile('poc.py'));
  const helper = savedFile(rawFile('helper.py'));
  const entries = [{ cve: 'CVE-2026-1000', desc: 'widget', poc: [fallback, repo, listed.original] }];
  const archives = {
    [original]: { url: fallback, timestamp: '20240101120000', files: [exploit] },
    [repo]: { files: [listed, helper] },
    [listed.original]: { url: listed.url, timestamp: listed.timestamp }
  };
  const { elements } = startPage(t, { search: '?q=widget', entries, archives, trending: new Promise(() => {}) });
  await new Promise(setImmediate);
  const html = elements.get('[data-results]').innerHTML;
  assert.match(html, /3 linked PoCs/);
  assert.ok(html.includes('<div class="poc-archive"><span class="wayback is-archived" title="Wayback Machine page snapshot captured ' +
    '2024-01-01 12:00 UTC, linked in place of the original" aria-hidden="true">ARCHIVED</span>' +
    `<details class="sources" style="--files:1" data-sources="${fallback}"><summary`));
  assert.ok(html.includes(`<a href="${exploit.url}" target="_blank" rel="nofollow noopener" ` +
    'title="Wayback Machine capture of exploit.c at commit 0123456, 2026-10-22 16:10 UTC" ' +
    'aria-label="exploit.c at commit 0123456 of owner/gone-poc, Wayback Machine capture 2026-10-22 16:10 UTC">exploit.c</a>'));
  // The lost original is never linked, and no capture is looked up again.
  assert.ok(!html.includes(`href="${original}"`));
  assert.doesNotMatch(html, /\/web\/\*\/https:\/\/(?:web\.archive\.org|raw\.githubusercontent\.com)/);
  // poc.py has a row and a snapshot of its own, so its page discloses only helper.py.
  assert.ok(html.includes('aria-label="1 file saved from owner/poc">1 file</summary>'));
  assert.ok(html.includes(`<a href="${helper.url}"`));
  assert.ok(html.includes(`<a class="wayback is-snapshot" href="${listed.url}"`));
  assert.equal(html.split(`href="${listed.url}"`).length, 2);
});

test('a pinned raw fallback discloses its sibling files once and stays one PoC', async t => {
  const primary = savedFile(rawFile('poc.py'));
  const helper = savedFile(rawFile('helper.py'));
  const readme = savedFile(rawFile('README.md'));
  const unrelated = savedFile(rawFile('helper.py', 'other/poc'));
  const traversal = savedFile(rawFile(`../../other/poc/${COMMIT}/poc.py`));
  const archives = { [primary.original]: { url: primary.url, timestamp: primary.timestamp,
    files: [primary, helper, readme, unrelated, traversal] } };
  for (const poc of [primary.original, primary.url]) {
    const entries = [{ cve: 'CVE-2026-1234', desc: 'widget', poc: [poc] }];
    const { elements } = startPage(t, { search: '?q=widget', entries, archives, trending: new Promise(() => {}) });
    await new Promise(setImmediate);
    const html = elements.get('[data-results]').innerHTML;
    assert.match(html, /1 linked PoC</, poc);
    assert.ok(html.includes(`<details class="sources" style="--files:2" data-sources="${poc}"><summary`), poc);
    for (const file of [helper, readme]) assert.ok(html.includes(`<a href="${file.url}" target="_blank"`), poc);
    assert.equal(html.split(`href="${primary.url}"`).length, 2, poc);
    for (const file of [unrelated, traversal]) assert.ok(!html.includes(file.url), poc);
  }
});

test('an open saved-files list stays open while results re-render', async t => {
  const repo = 'https://github.com/owner/poc';
  const entries = [{ cve: 'CVE-2026-1234', desc: 'widget', poc: [repo] }];
  const { context, elements } = startPage(t, { search: '?q=widget', entries, trending: new Promise(() => {}),
    archives: { [repo]: { files: [savedFile(rawFile('poc.py'))] } } });
  await new Promise(setImmediate);
  const results = () => elements.get('[data-results]').innerHTML;
  const toggle = (open, matches = true) => vm.runInContext('rememberSources({ target: { matches: () => ' + matches +
    `, open: ${open}, dataset: { sources: ${JSON.stringify(repo)} } } }); renderResults(null);`, context);
  assert.ok(results().includes(`data-sources="${repo}"><summary`));
  toggle(true);
  assert.ok(results().includes(`data-sources="${repo}" open><summary`));
  // A toggle elsewhere changes nothing.
  toggle(false, false);
  assert.ok(results().includes(`data-sources="${repo}" open><summary`));
  toggle(false);
  assert.ok(results().includes(`data-sources="${repo}"><summary`));
});

test('late or failed archive data never blocks search, reorders results or drops snapshots', async t => {
  let finishArchives;
  const archives = new Promise(resolve => { finishArchives = resolve; });
  const entries = ['CVE-2025-1234', 'CVE-2024-1234'].map(cve => ({ cve, desc: 'widget', poc: [`https://github.com/owner/${cve}`] }));
  const { context, elements } = startPage(t, { search: '?q=widget', entries, archives, trending: new Promise(() => {}) });
  await new Promise(setImmediate);
  const results = () => elements.get('[data-results]').innerHTML;
  const ids = () => [...results().matchAll(/class="result-id" href="\/([^"]+)"/g)].map(match => match[1]);
  assert.deepEqual(ids(), ['CVE-2025-1234', 'CVE-2024-1234']);
  assert.equal(results().match(/class="wayback is-lookup"/g).length, 2);
  const status = elements.get('[data-status]').textContent;
  const original = 'https://github.com/owner/CVE-2024-1234';
  const snapshot = `https://web.archive.org/web/20251021093000/${original}`;
  const saved = savedFile(rawFile('poc.py', 'owner/CVE-2024-1234'));
  finishArchives({ [original]: { url: snapshot, timestamp: '20251021093000', files: [saved] } });
  await new Promise(setImmediate);
  assert.deepEqual(ids(), ['CVE-2025-1234', 'CVE-2024-1234']);
  assert.ok(results().includes(`class="wayback is-snapshot" href="${snapshot}"`));
  assert.ok(results().includes(`<a href="${saved.url}"`));
  assert.equal(elements.get('[data-status]').textContent, status);
  // A refresh whose archive download fails or is unusable keeps the snapshot and saved file shown.
  for (const [at, failure] of ['error', 'malformed'].entries()) {
    const feed = { generated: `2026-10-21T1${at}:00:00Z`, with_pocs: 2, total_cves: 2, items: [], landed: [] };
    context.fetch = async url => {
      const file = url.split('?')[0];
      if (file === '/archives.json' && failure === 'error') throw new Error('Unavailable');
      return { ok: true, json: async () => file === '/trending_poc.json' ? feed : file === '/CVE_list.json' ? entries
        : file === '/archives.json' ? [] : {} };
    };
    assert.equal(await vm.runInContext('refreshData(true)', context), true);
    await new Promise(setImmediate);
    assert.deepEqual(ids(), ['CVE-2025-1234', 'CVE-2024-1234']);
    assert.ok(results().includes(`class="wayback is-snapshot" href="${snapshot}"`), failure);
    assert.ok(results().includes(`<a href="${saved.url}"`), failure);
    assert.equal(elements.get('[data-notices]').hidden, true);
  }
});

test('snapshots and saved files published with the homepage survive a failed archive download', async t => {
  const original = 'https://github.com/owner/poc';
  const snapshot = `https://web.archive.org/web/20251021093000/${original}`;
  const file = savedFile(rawFile('poc.py'));
  const name = { getAttribute: () => original };
  const row = { querySelector: () => name };
  const sources = { getAttribute: attribute => attribute === 'data-sources' ? original : null };
  const published = [
    { getAttribute: () => snapshot, closest: selector => selector === '.trend-row' ? row : null },
    { getAttribute: () => file.url, closest: selector => selector === 'details.sources' ? sources : row }
  ];
  const feed = { generated: '2026-10-21T10:00:00Z', with_pocs: 1, total_cves: 1, items: [], landed: [
    { cve: 'CVE-2026-1234', url: original, name: 'poc', stars: 1, released: '2026-10-21T09:00:00Z', page: '/CVE-2026-1234' }] };
  const { elements, calls } = startPage(t, { trending: feed, published, archivesError: true });
  await new Promise(setImmediate);
  assert.ok(calls.includes('/archives.json'));
  const rows = elements.get('[data-trend-rows]').innerHTML;
  assert.ok(rows.includes('<div class="trend-sub"><a class="trend-detail" href="/CVE-2026-1234">CVE-2026-1234 details</a>' +
    `<a class="wayback is-snapshot" href="${snapshot}"`));
  assert.ok(rows.includes(`<details class="sources" style="--files:1" data-sources="${original}"><summary`));
  assert.ok(rows.includes(`<a href="${file.url}"`));
  assert.doesNotMatch(rows, /is-lookup/);
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

test('newest sorts by publication date rather than identifier allocation order', async t => {
  const entries = [
    { cve: 'CVE-2026-99999', published: '2026-01-01', poc_observed: '2026-10-23' },
    { cve: 'CVE-2025-1234', published: '2026-10-21' },
    { cve: 'CVE-2026-88888', published: '2026-10-20' },
    { cve: 'CVE-2026-99998' },
    { cve: 'CVE-2026-1234', metadata_pending: true, poc_observed: '2026-10-22' }
  ].map(row => ({ ...row, desc: 'widget', poc: ['https://github.com/owner/' + row.cve] }));
  const { elements } = startPage(t, { search: '?q=widget&sort=newest', entries, trending: new Promise(() => {}) });
  await new Promise(setImmediate);
  const ids = [...elements.get('[data-results]').innerHTML.matchAll(/class="result-id" href="\/([^"]+)"/g)].map(match => match[1]);
  assert.deepEqual(ids, ['CVE-2026-1234', 'CVE-2025-1234', 'CVE-2026-88888', 'CVE-2026-99999', 'CVE-2026-99998']);
  assert.match(elements.get('[data-results]').innerHTML, /PoC observed 2026-10-22/);
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
      URL,
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
