'use strict';

const REPLACE_STRINGS = ['HackTheBox - ', 'VulnHub - ', 'UHC - '];
const PAGE_SIZE = 50;
const POC_PREVIEW = 5;
const ADVISORY_PREVIEW = 3;
const TREND_ROWS = 20;
const MIN_QUERY = 2;
const POC_FIELDS = ['poc', 'nuclei', 'msf', 'edb', 'vulhub', 'collections'];
const ADVISORY_TAGS = new Set(['Third Party Advisory', 'GitHub Advisory', 'Mitigation', 'Advisory']);
const FILTER_OPTIONS = {
  severity: [
    ['CRITICAL', 'CRITICAL'], ['HIGH', 'HIGH'], ['MEDIUM', 'MEDIUM'],
    ['LOW', 'LOW']
  ],
  source: [
    ['GITHUB', 'GITHUB'], ['GHSA', 'GHSA'], ['REFERENCE', 'REFERENCE'],
    ['NUCLEI', 'NUCLEI'], ['MSF', 'METASPLOIT'], ['EDB', 'EXPLOITDB'],
    ['VULHUB', 'VULHUB'], ['COLLECTIONS', 'COLLECTIONS']
  ]
};

const state = {
  query: '',
  mode: 'LANDED',
  sort: 'RELEVANCE',
  shown: PAGE_SIZE,
  descOpen: new Set(),
  pocOpen: new Set(),
  advisoryOpen: new Set(),
  sourcesOpen: new Set(),
  kevOnly: false,
  filters: {
    severity: new Set(FILTER_OPTIONS.severity.map(([value]) => value)),
    source: new Set(FILTER_OPTIONS.source.map(([value]) => value))
  },
  ready: false,
  loadFailed: false,
  results: []
};

let dataset = [];
let repoMeta = {};
let kev = {};
let ratings = {};
let metadata = {};
let epss = {};
// Original PoC URL to its confirmed Wayback Machine capture, from archives.json.
let archives = {};
let indexMeta = null;
let dataEpoch = 0;
const enrichmentNotices = new Set();

/* ---- formatting -------------------------------------------------------- */

function escapeHTML(value) {
  return String(value == null ? '' : value).replace(/[&<>"']/g, ch => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[ch]));
}

function formatCount(n) {
  return n.toLocaleString('en-US');
}

/** 1st, 2nd, 3rd, 4th. A hard-coded "th" printed 51th on 21,100 CVEs. */
function ordinal(n) {
  const tens = n % 100;
  if (tens >= 11 && tens <= 13) return `${n}th`;
  return `${n}${['th', 'st', 'nd', 'rd'][n % 10] || 'th'}`;
}

function formatStars(n) {
  return n >= 1000 ? (n / 1000).toFixed(1) + 'k' : String(n);
}

function hoursSince(iso) {
  if (!iso) return null;
  const then = Date.parse(iso.length === 10 ? iso + 'T00:00:00Z' : iso);
  if (Number.isNaN(then)) return null;
  return Math.max(0, (Date.now() - then) / 36e5);
}

/** UTC date of an ISO date or timestamp, read as build_pages.py reads it: a
 *  time without a zone is UTC. Empty when there is no readable date. */
function utcDay(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}/.test(value)) return '';
  const calendar = Date.parse(value.slice(0, 10) + 'T00:00:00Z');
  if (Number.isNaN(calendar) || new Date(calendar).toISOString().slice(0, 10) !== value.slice(0, 10)) return '';
  const time = Date.parse(/[T ][\d:.]+$/.test(value) ? value.replace(' ', 'T') + 'Z' : value);
  return Number.isNaN(time) ? '' : new Date(time).toISOString().slice(0, 10);
}

/** Keep day-only sources honest: they cannot tell us how many hours ago. */
function trendAge(value, now = Date.now()) {
  if (!utcDay(value)) return '<span class="trend-age">N/A</span>';
  const dayOnly = value.length === 10;
  const time = Date.parse(/[T ][\d:.]+$/.test(value) ? value.replace(' ', 'T') + 'Z' : value);
  const age = Math.max(0, now - time);
  let count, unit, label;
  if (dayOnly) {
    count = Math.max(0, Math.floor(now / 864e5) - Math.floor(time / 864e5));
    unit = 'day';
    if (!count) label = 'today';
  } else if (age < 6e4) label = 'just now';
  else if (age < 36e5) { count = Math.floor(age / 6e4); unit = 'minute'; }
  else if (age < 864e5) { count = Math.floor(age / 36e5); unit = 'hour'; }
  else { count = Math.floor(age / 864e5); unit = 'day'; }
  if (!label) label = `${formatCount(count)} ${unit}${count === 1 ? '' : 's'} ago`;
  const iso = dayOnly ? value : new Date(time).toISOString();
  const title = dayOnly ? `${value} UTC (time unavailable)` : iso.replace('T', ' ').replace('Z', ' UTC');
  return `<time class="trend-age" datetime="${iso}" title="${title}">${label}</time>`;
}

function refreshTrendAges() {
  if (document.hidden) return;
  for (const cell of document.querySelectorAll('time.trend-age')) {
    const next = trendAge(cell.getAttribute('datetime'));
    if (next !== cell.outerHTML) cell.outerHTML = next;
  }
}

function tickTrendAges() {
  refreshTrendAges();
  setTimeout(tickTrendAges, 60000);
}
setTimeout(tickTrendAges, 0);
document.addEventListener('visibilitychange', refreshTrendAges);

/** Compact age for the PoC columns: 3h, 3d, 2w, 5mo, 2y. */
function shortAge(hours) {
  if (hours == null) return '';
  if (hours < 24) return Math.max(1, Math.round(hours)) + 'h';
  const days = hours / 24;
  if (days < 14) return Math.round(days) + 'd';
  if (days < 60) return Math.round(days / 7) + 'w';
  if (days < 730) return Math.round(days / 30) + 'mo';
  return Math.round(days / 365) + 'y';
}

// github.com serves more than repositories; an attachment or an advisory has
// no owner and no stars, and reads as nonsense in an owner / repo row.
const NOT_A_REPO = new Set(['user-attachments', 'advisories', 'security', 'orgs',
  'apps', 'marketplace', 'sponsors', 'topics', 'collections', 'settings', 'notifications']);

function repoFromUrl(url) {
  const match = /^https?:\/\/(?:www\.)?github\.com\/([^/#?]+)\/([^/#?]+)/i.exec(url || '');
  if (!match || NOT_A_REPO.has(match[1].toLowerCase()) ||
      /^\/security\/advisories(?:\/|$)/i.test(url.slice(match[0].length))) return null;
  return { owner: match[1], repo: match[2].replace(/\.git$/i, '') };
}

/** Everything after the host, for links that are not GitHub repositories. */
function plainLinkLabel(url) {
  try {
    const parsed = new URL(url);
    return parsed.host.replace(/^www\./, '') + parsed.pathname.replace(/\/$/, '');
  } catch (err) {
    return url;
  }
}

/* ---- wayback machine --------------------------------------------------- */

const WAYBACK = 'https://web.archive.org/web/';
// A page snapshot: https on web.archive.org, a 14-digit UTC capture time and
// the http(s) page captured. A save request or a history search is not one.
const CAPTURE = /^https:\/\/web\.archive\.org\/web\/([0-9]{14})\/(https?:\/\/[^\x00-\x20\x7f"<>\\]+)$/;

/** The capture a snapshot URL names, or null. Its time has to be a real one
 *  from 1996 on, when the Wayback Machine began. build_pages.py reads it alike. */
function waybackCapture(url) {
  const match = typeof url === 'string' ? CAPTURE.exec(url) : null;
  if (!match) return null;
  const stamp = match[1];
  const iso = stamp.replace(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/, '$1-$2-$3T$4:$5:$6.000Z');
  const time = Date.parse(iso);
  if (stamp < '1996' || Number.isNaN(time) || new Date(time).toISOString() !== iso) return null;
  return { url, stamp, original: match[2] };
}

/** Lower-cased host of an http(s) link, without www. or a port. Empty for
 *  anything else, a link carrying credentials included. */
function linkHost(url) {
  const match = /^https?:\/\/([^/?#@\x00-\x20\x7f\\]*)(?=[/?#]|$)/.exec(String(url || ''));
  return match ? match[1].toLowerCase().replace(/:[0-9]*$/, '').replace(/^www\./, '') : '';
}

/** The page a link stands for. A snapshot published in place of a lost
 *  original stands for that original. */
function linkTarget(url) {
  const capture = waybackCapture(url);
  return capture ? capture.original : url;
}

/** The capture archives.json confirms for this exact link: a valid snapshot,
 *  stamped as recorded, of a page on the link's own host. */
function confirmedSnapshot(url) {
  const record = archives[url];
  const capture = record && typeof record === 'object' ? waybackCapture(record.url) : null;
  if (!capture || capture.stamp !== record.timestamp) return null;
  const host = linkHost(url);
  return host && linkHost(capture.original) === host ? capture : null;
}

function captureDate(stamp) {
  return `${stamp.slice(0, 4)}-${stamp.slice(4, 6)}-${stamp.slice(6, 8)} ${stamp.slice(8, 10)}:${stamp.slice(10, 12)} UTC`;
}

/** The accessible name of a link that opens a snapshot in place of its original. */
function archivedName(label, capture) {
  return capture
    ? ` aria-label="${escapeHTML(`${label}, archived page snapshot captured ${captureDate(capture.stamp)}`)}"`
    : '';
}

/** The Wayback Machine beside a PoC link: its confirmed snapshot, or a lookup
 *  that claims nothing. A snapshot is one captured page, not a copy of the
 *  whole source. A link that is itself a snapshot is stamped instead, and any
 *  other link into the archive gets nothing. */
function archiveLink(url, label) {
  const capture = waybackCapture(url);
  if (capture) {
    return `<span class="wayback is-archived" title="Wayback Machine page snapshot captured ${captureDate(capture.stamp)}, ` +
      'linked in place of the original" aria-hidden="true">ARCHIVED</span>';
  }
  const host = linkHost(url);
  if (!host || /(?:^|\.)archive\.org$/.test(host)) return '';
  const snapshot = confirmedSnapshot(url);
  if (snapshot) {
    const date = captureDate(snapshot.stamp);
    return `<a class="wayback is-snapshot" href="${escapeHTML(snapshot.url)}" target="_blank" rel="nofollow noopener" ` +
      `title="Wayback Machine page snapshot, captured ${date}" ` +
      `aria-label="${escapeHTML(`snapshot of ${label} on the Wayback Machine, captured ${date}`)}">snapshot</a>`;
  }
  return `<a class="wayback is-lookup" href="${escapeHTML(WAYBACK + '*/' + url)}" target="_blank" rel="nofollow noopener" ` +
    'title="Search the Wayback Machine for captures; none confirmed" ' +
    `aria-label="${escapeHTML(`find archive of ${label} on the Wayback Machine`)}">find archive</a>`;
}

/* ---- saved source files ------------------------------------------------ */

// archives.json may list, under a page, captures of files that page holds:
// the raw bytes of one file at a pinned commit of the page's own GitHub
// repository, or the JSON of the page's own HackerOne report. Nothing else is
// that page's file. build_pages.py reads them alike.
const RAW_FILE = /^https:\/\/raw\.githubusercontent\.com\/([^/?#]+)\/([^/?#]+)\/([0-9a-f]{40})\/([^?#]+)$/;
const REPORT_PAGE = /^https?:\/\/[^/?#]*\/reports\/([0-9]+)\/?(?:[?#]|$)/;
const REPORT_JSON = /^https:\/\/(?:www\.)?hackerone\.com\/reports\/([0-9]+)\.json$/;

/** What follows a link's host: its path, query and fragment. */
function linkPath(url) {
  return url.replace(/^https?:\/\/[^/?#]*/, '');
}

/** The page a link stands for, whatever scheme, www. or port it carries. */
function linkIdentity(url) {
  const target = linkTarget(url);
  const host = linkHost(target);
  return host ? host + linkPath(target) : target;
}

/** The file a saved original is, when it belongs to the page at parent. */
function sourceFile(parent, original) {
  const pinned = RAW_FILE.exec(parent);
  const repo = repoFromUrl(parent) || (pinned && { owner: pinned[1], repo: pinned[2] });
  const raw = repo && RAW_FILE.exec(original);
  if (raw) {
    const checked = pinned ? `${pinned[1]}/${pinned[2]}/${pinned[4]}/${raw[4]}` : raw[4];
    // A dot segment would resolve into another repository's files.
    if (`${raw[1]}/${raw[2]}`.toLowerCase() !== `${repo.owner}/${repo.repo}`.toLowerCase() ||
        checked.split('/').some(part => !part || /^(?:\.|%2e){1,2}$/i.test(part))) return null;
    let name = raw[4];
    try {
      name = decodeURIComponent(name);
    } catch (err) {
      // A malformed escape is shown as written.
    }
    return { key: `${raw[3]}/${raw[4]}`, name, commit: raw[3] };
  }
  const report = linkHost(parent) === 'hackerone.com' ? REPORT_PAGE.exec(parent) : null;
  const json = report && REPORT_JSON.exec(original);
  return json && json[1] === report[1] ? { key: json[1], name: `${json[1]}.json`, commit: '' } : null;
}

/** The saved files archives.json confirms for this exact link: valid
 *  captures, stamped as recorded, of files that belong to it. One capture per
 *  file, the latest, in a stable order. */
function savedFiles(url) {
  const record = archives[url];
  const files = record && typeof record === 'object' && Array.isArray(record.files) ? record.files : [];
  const found = new Map();
  for (const file of files) {
    const capture = file && typeof file === 'object' ? waybackCapture(file.url) : null;
    const original = capture && typeof file.original === 'string' ? file.original : '';
    if (!original || capture.stamp !== file.timestamp || linkHost(original) !== linkHost(capture.original) ||
        linkPath(original) !== linkPath(capture.original)) continue;
    const source = sourceFile(url, original);
    const kept = source && found.get(source.key);
    if (source && (!kept || kept.capture.stamp < capture.stamp)) found.set(source.key, { ...source, original, capture });
  }
  return [...found.values()].sort((a, b) => (a.original < b.original ? -1 : a.original > b.original ? 1 : 0));
}

/** A link's saved files, disclosed beside its Wayback control. Each opens the
 *  capture of one file's bytes, so none stands for the whole source and none
 *  gets an archive control of its own. A snapshot in place of a lost original
 *  discloses that original's files; a file listed in a row of its own is not
 *  repeated. */
function sourceFiles(url, label, listed = new Set()) {
  const files = savedFiles(linkTarget(url)).filter(file => !listed.has(linkIdentity(file.original)));
  if (!files.length) return '';
  const count = `${files.length} file${files.length === 1 ? '' : 's'}`;
  const title = files[0].commit
    ? 'Wayback Machine captures of individual files at pinned commits, not a copy of the whole repository'
    : 'Wayback Machine capture of the report JSON';
  const links = files.map(file => {
    const date = captureDate(file.capture.stamp);
    const what = file.commit ? `${file.name} at commit ${file.commit.slice(0, 7)}` : `${file.name}, the report JSON`;
    return `<a href="${escapeHTML(file.capture.url)}" target="_blank" rel="nofollow noopener" ` +
      `title="${escapeHTML(`Wayback Machine capture of ${what}, ${date}`)}" ` +
      `aria-label="${escapeHTML(`${what} of ${label}, Wayback Machine capture ${date}`)}">${escapeHTML(file.name)}</a>`;
  }).join('');
  // The count sizes the room the open list takes, so nothing beside it moves.
  return `<details class="sources" style="--files:${files.length}" data-sources="${escapeHTML(url)}"` +
    `${state.sourcesOpen.has(url) ? ' open' : ''}><summary title="${title}" ` +
    `aria-label="${escapeHTML(`${count} saved from ${label}`)}">${count}</summary>` +
    `<div class="sources-list">${links}</div></details>`;
}

/* ---- matching ---------------------------------------------------------- */

function normalizeToSpaces(value) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
}

function buildLooseRegex(value) {
  const compact = value.toLowerCase().replace(/[^a-z0-9]+/g, '');
  if (compact.length < 4) return null;
  const escaped = compact.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // Identifier separators may vary; unrelated prose must not join up into a
  // name. In particular, "php, (2) show" is not a match for "php2sh".
  return new RegExp('(?:^|[^a-z0-9])' + escaped.split('').join('[-_.]*'));
}

function buildMatcher(term) {
  const raw = term.toLowerCase().trim();
  if (!raw) return null;
  const isPhrase = /\s/.test(raw);
  const normalized = raw.replace(/[^a-z0-9]+/g, '');
  return {
    raw,
    compact: normalized,
    isPhrase,
    phrase: isPhrase ? normalizeToSpaces(raw) : '',
    loose: !isPhrase && normalized.length >= 4 ? buildLooseRegex(raw) : null
  };
}

// Plain substring matching made "rce" hit "open source" and "sudo" hit
// "pseudo". Require the term to start a word; matching into the end of one is
// still allowed so that "word" finds "wordpress".
function wordStart(text, term) {
  let at = text.indexOf(term);
  while (at > 0) {
    const code = text.charCodeAt(at - 1);
    if (!((code > 96 && code < 123) || (code > 47 && code < 58))) return at;
    at = text.indexOf(term, at + 1);
  }
  return at;
}

// A term in the opening of an advisory is what it is about; one buried deep in
// the prose is usually incidental. Coarse buckets so that a few characters of
// difference never outweighs the newest-first tie-break.
function leadBonus(index) {
  if (index < 0) return 0;
  if (index < 80) return 80;
  if (index < 300) return 40;
  return 0;
}

function pocText(entry) {
  if (entry._pocText === undefined) {
    // An archived source matches as its original would, not as web.archive.org.
    entry._pocText = entryLinks(entry).map(linkTarget).join(' ').toLowerCase();
  }
  return entry._pocText;
}

function entryLinks(entry) {
  if (entry._allLinks === undefined) {
    entry._allLinks = uniqueSourceLinks(
      POC_FIELDS.flatMap(field => entry[field] || []),
      POC_FIELDS.slice(1).flatMap(field => entry[field] || []));
  }
  return entry._allLinks;
}

function pocSpace(entry) {
  if (entry._pocSpace === undefined) {
    entry._pocSpace = normalizeToSpaces(pocText(entry));
  }
  return entry._pocSpace;
}

function descSpace(entry) {
  if (entry._descSpace === undefined) {
    entry._descSpace = normalizeToSpaces(entry._descText);
  }
  return entry._descSpace;
}

function identityText(entry) {
  if (entry._identityText === undefined) {
    const artifacts = new Set(POC_FIELDS.slice(1).flatMap(field => entry[field] || []));
    entry._identityText = entryLinks(entry).map(url => {
      const source = linkTarget(url);
      const repo = repoFromUrl(source);
      if (!repo) return '';
      // Repository and artifact names identify the PoC; its owner and host
      // and GitHub's routing/ref segments stay in the lower URL tier.
      const path = source.replace(/^https?:\/\/(?:www\.)?github\.com\/[^/]+\/[^/?#]+/i, '').split(/[?#]/)[0];
      const artifact = /^\/(?:blob|tree)\/[^/]+\/(.+)/i.exec(path);
      const leaf = artifact ? artifact[1].replace(/\/$/, '').split('/').pop() : '';
      // A collection's repository and category folders describe the catalogue,
      // not this exploit. They are still searchable through the full URL.
      return artifacts.has(url) ? leaf : [repo.repo, leaf].filter(Boolean).join('\n');
    }).join('\n').toLowerCase();
  }
  return entry._identityText;
}

function identitySpace(entry) {
  if (entry._identitySpace === undefined) {
    // A quoted phrase cannot run from the end of one repository name into the next.
    entry._identitySpace = identityText(entry).split('\n').map(normalizeToSpaces).join('\n');
  }
  return entry._identitySpace;
}

function matchAt(text, matcher) {
  const at = wordStart(matcher.isPhrase ? normalizeToSpaces(text) : text,
    matcher.isPhrase ? matcher.phrase : matcher.raw);
  if (at >= 0 || !matcher.loose) return at;
  const loose = matcher.loose.exec(text);
  return loose ? loose.index : -1;
}

function scoreEntry(entry, matcher) {
  if (!matcher || !matcher.raw) return 0;

  if (matcher.isPhrase) {
    const phrase = matcher.phrase;
    if (!phrase) return 0;
    if (entry._titleSpace && wordStart(entry._titleSpace, phrase) >= 0) return 400;
    const inLinks = wordStart(pocSpace(entry), phrase) >= 0;
    if (inLinks && wordStart(identitySpace(entry), phrase) >= 0) return 350;
    const at = wordStart(descSpace(entry), phrase);
    if (at >= 0) return 240 + leadBonus(at);
    return inLinks ? 80 : 0;
  }

  const raw = matcher.raw;
  if (entry._cveCompact === matcher.compact) return 1000;
  if (wordStart(entry._cveText, raw) >= 0 ||
      (matcher.loose && entry._cveCompact.startsWith(matcher.compact))) return 600;
  // The record's own title, vendor and product name what it is about; a hit
  // there outranks any position in the prose.
  if (entry._titleText && matchAt(entry._titleText, matcher) >= 0) return 400;
  const inLinks = matchAt(pocText(entry), matcher) >= 0;
  if (inLinks && matchAt(identityText(entry), matcher) >= 0) return 350;
  const at = matchAt(entry._descText, matcher);
  if (at >= 0) return 240 + leadBonus(at);
  return inLinks ? 80 : 0;
}

/** How many of an entry's links carry every search term. */
function countLinkHits(entry, matchers) {
  let hits = 0;
  for (const url of entryLinks(entry)) {
    const text = linkTarget(url).toLowerCase();
    if (matchers.every(m => matchAt(text, m) >= 0)) {
      hits += 1;
      if (hits >= 999) break;
    }
  }
  return hits;
}

function canonicalCvss(id) {
  const rows = ((metadata[id] || {}).cvss || []);
  if (!Array.isArray(rows) || !Array.isArray(rows[0])) return null;
  const row = rows[0];
  return {
    score: Number(row[1]),
    severity: String(row[2] || '').toUpperCase()
  };
}

// Cached per entry. A filter pass asked the metadata for every one of 82,000
// entries on every keystroke; the answer only changes when a data file lands,
// which bumps the epoch.
let severityEpoch = 0;
function entrySeverity(entry) {
  if (entry._sevEpoch === severityEpoch) return entry._sev;
  const score = canonicalCvss(entry.cve);
  let severity = '';
  if (score && ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(score.severity)) {
    severity = score.severity;
  } else {
    const fallback = String((ratings[entry.cve] || {}).severity || '').toUpperCase();
    severity = ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(fallback) ? fallback : '';
  }
  entry._sev = severity;
  entry._sevEpoch = severityEpoch;
  return severity;
}

function hasActiveFilters() {
  return state.kevOnly || Object.entries(state.filters).some(
    ([kind, filter]) => filter.size !== FILTER_OPTIONS[kind].length
  );
}

function entrySources(entry) {
  if (entry._sources) return entry._sources;
  const sources = new Set();
  const fields = {
    NUCLEI: 'nuclei', MSF: 'msf', EDB: 'edb', VULHUB: 'vulhub', COLLECTIONS: 'collections'
  };
  for (const [source, field] of Object.entries(fields)) {
    if ((entry[field] || []).length) sources.add(source);
  }
  for (const url of (entry.poc || []).map(linkTarget)) {
    if (/^https?:\/\/(?:www\.)?github\.com\/(?:advisories|[^/]+\/[^/]+\/security\/advisories)\/GHSA-/i.test(url)) {
      sources.add('GHSA');
    } else if (repoFromUrl(url)) {
      sources.add('GITHUB');
    } else {
      sources.add('REFERENCE');
    }
  }
  entry._sources = sources;
  return sources;
}

function matchesMultiFilter(values, filter) {
  for (const value of filter) {
    if (values.has(value)) return true;
  }
  return false;
}

function matchesFilters(entry) {
  if (state.kevOnly && !enrichmentNotices.has('KEV filter unavailable') && !kev[entry.cve]) return false;
  if (!matchesMultiFilter(entrySources(entry), state.filters.source)) return false;
  // ALL has to mean all. The options list only names the four scored bands, so
  // testing membership hid every CVE nobody has scored yet even with nothing
  // filtered: 41 of them were unreachable by search, including by exact ID.
  if (state.filters.severity.size === FILTER_OPTIONS.severity.length ||
      enrichmentNotices.has('severity filter unavailable')) return true;
  const severity = entrySeverity(entry);
  return severity ? matchesMultiFilter(new Set([severity]), state.filters.severity) : false;
}

/* ---- word index -------------------------------------------------------- */

// Every keystroke used to scan 28 MB of description text, and for terms of
// four characters or more the loose regex then ran against every entry that
// did not match, about 80,000 regex tests a keystroke. The index maps each
// word to the entries carrying it, so a term is a prefix lookup in a sorted
// word list and the scan only touches the candidates. It is built in slices
// after the index loads so typing never waits on it; until then the scan does
// the work exactly as before.
const wordIndex = { words: null, postings: new Map(), buckets: new Map(), ready: false, built: 0 };

function tokensOf(text) {
  return text ? text.match(/[a-z0-9]+/g) || [] : [];
}

function indexWords(text) {
  const words = tokensOf(text);
  // Every suffix is needed: "php-2-shell" inside "lab-php-2-shell-poc"
  // must be a candidate for "php2sh", just as it is in the scoring pass.
  for (const compound of text.match(/[a-z0-9]+(?:[-_.]+[a-z0-9]+)+/g) || []) {
    const parts = tokensOf(compound);
    for (let i = 0; i < parts.length - 1; i++) words.push(parts.slice(i).join(''));
  }
  return words;
}

function indexSlice(budget) {
  const started = performance.now();
  const postings = wordIndex.postings;
  while (wordIndex.built < dataset.length) {
    const at = wordIndex.built;
    const entry = dataset[at];
    const words = indexWords(entry._cveText + ' ' + entry._descText + ' ' + entry._titleText + ' ' + pocText(entry));
    if (words) {
      // Entries arrive in order, so a repeat within one entry is always the
      // last id on the list and needs no set to catch it.
      for (const word of words) {
        const list = postings.get(word);
        if (!list) {
          postings.set(word, [at]);
          const prefix = word.slice(0, 2);
          const bucket = wordIndex.buckets.get(prefix);
          if (bucket) bucket.push(word);
          else wordIndex.buckets.set(prefix, [word]);
        } else if (list[list.length - 1] !== at) list.push(at);
      }
    }
    wordIndex.built += 1;
    if ((at & 127) === 0 && performance.now() - started > budget) break;
  }
  if (wordIndex.built < dataset.length) {
    yieldThen(() => indexSlice(budget));
    return;
  }
  sortWordIndex(budget);
}

function sortWordIndex(budget) {
  // Sorting the expanded vocabulary in one pass paused typing for ~130 ms.
  // Prefix buckets retain lexicographic order and let us yield between sorts.
  const buckets = wordIndex.buckets;
  const prefixes = [...buckets.keys()].sort();
  const words = [];
  let next = 0;
  function slice() {
    const started = performance.now();
    while (next < prefixes.length) {
      const prefix = prefixes[next++];
      for (const word of buckets.get(prefix).sort()) words.push(word);
      buckets.delete(prefix);
      if (performance.now() - started > budget) {
        yieldThen(slice);
        return;
      }
    }
    wordIndex.words = words;
    wordIndex.ready = true;
    wordIndex.elapsed = Math.round(performance.now() - wordIndex.startedAt);
    if (state.ready && state.query.length >= MIN_QUERY && !state.results.length) render();
  }
  slice();
}

// Hands the thread back between slices. A timer would do, except that a
// background tab clamps timers to once a second and the build took a minute
// there; a message port yields to the event loop without that throttle.
const yieldPort = new MessageChannel();
let yieldNext = null;
yieldPort.port1.onmessage = () => {
  const next = yieldNext;
  yieldNext = null;
  if (next) next();
};
function yieldThen(fn) {
  yieldNext = fn;
  yieldPort.port2.postMessage(null);
}

function buildWordIndex() {
  wordIndex.postings = new Map();
  wordIndex.buckets = new Map();
  wordIndex.words = null;
  wordIndex.built = 0;
  wordIndex.ready = false;
  wordIndex.startedAt = performance.now();
  indexSlice(32);
}

// The slice of the sorted word list that starts with the prefix.
function wordRange(prefix) {
  const words = wordIndex.words;
  if (!words) return [0, 0];
  let low = 0;
  let high = words.length;
  while (low < high) {
    const mid = (low + high) >> 1;
    if (words[mid] < prefix) low = mid + 1;
    else high = mid;
  }
  const start = low;
  high = words.length;
  while (low < high) {
    const mid = (low + high) >> 1;
    if (words[mid].startsWith(prefix)) low = mid + 1;
    else high = mid;
  }
  return [start, low];
}

// How many of the terms each entry can satisfy, by word. A term has to start a
// word, and may run on into the end of one, so its last part is a prefix and
// any earlier parts are whole words: "pan-os" is the word "pan" followed by a
// word starting "os". The scoring pass still checks the literal text; this
// only decides which entries are worth its time.
function candidateCounts(groups) {
  const size = dataset.length;
  const total = new Uint8Array(size);
  const stampOf = new Int32Array(size);
  const hit = new Uint8Array(size);
  let stamp = 0;
  for (const group of groups) {
    hit.fill(0);
    for (const matcher of group) {
      const parts = tokensOf(matcher.isPhrase ? matcher.phrase : matcher.raw);
      if (!parts.length) return null;
      const partCount = new Uint8Array(size);
      parts.forEach((part, index) => {
        stamp += 1;
        const bump = at => {
          if (stampOf[at] !== stamp) {
            stampOf[at] = stamp;
            partCount[at] += 1;
          }
        };
        if (index === parts.length - 1) {
          const [start, end] = wordRange(part);
          for (let i = start; i < end; i++) {
            for (const at of wordIndex.postings.get(wordIndex.words[i])) bump(at);
          }
        } else {
          for (const at of wordIndex.postings.get(part) || []) bump(at);
        }
      });
      if (matcher.loose && matcher.compact !== matcher.raw) {
        const [start, end] = wordRange(matcher.compact);
        for (let i = start; i < end; i++) {
          for (const at of wordIndex.postings.get(wordIndex.words[i])) hit[at] = 1;
        }
      }
      for (let at = 0; at < size; at++) {
        if (partCount[at] === parts.length) hit[at] = 1;
      }
    }
    for (let at = 0; at < size; at++) if (hit[at]) total[at] += 1;
  }
  return total;
}

function scoreGroup(entry, group) {
  let best = 0;
  for (const matcher of group) {
    const score = scoreEntry(entry, matcher);
    if (score > best) best = score;
  }
  return best;
}

/* ---- what people type versus what the records say ----------------------- */

// Security slang against NVD prose. "sqli" found 843 CVEs and "sql injection"
// 12,719; a term expands to its phrases and an entry matches on any of them.
const ALIASES = {
  sqli: ['sql injection'],
  xss: ['cross-site scripting', 'cross site scripting'],
  rce: ['remote code execution'],
  lpe: ['privilege escalation'],
  privesc: ['privilege escalation'],
  eop: ['elevation of privilege', 'privilege escalation'],
  lfi: ['local file inclusion'],
  rfi: ['remote file inclusion'],
  xxe: ['xml external entity'],
  csrf: ['cross-site request forgery'],
  ssrf: ['server-side request forgery'],
  ssti: ['server-side template injection'],
  idor: ['insecure direct object reference'],
  dos: ['denial of service'],
  cmdi: ['command injection'],
  traversal: ['path traversal', 'directory traversal'],
  deserialization: ['deserialization of untrusted data', 'insecure deserialization'],
  bypass: ['authentication bypass', 'authorization bypass'],
  overflow: ['buffer overflow', 'heap overflow', 'stack overflow', 'integer overflow']
};

// The names a vulnerability is known by, when the query is exactly that name.
// The record it belongs to leads whatever the prose and repositories say.
const NAMED = {
  log4shell: 'CVE-2021-44228', heartbleed: 'CVE-2014-0160', eternalblue: 'CVE-2017-0144',
  eternalromance: 'CVE-2017-0145', wannacry: 'CVE-2017-0144', printnightmare: 'CVE-2021-34527',
  zerologon: 'CVE-2020-1472', spring4shell: 'CVE-2022-22965', proxyshell: 'CVE-2021-34473',
  proxylogon: 'CVE-2021-26855', proxynotshell: 'CVE-2022-41040', citrixbleed: 'CVE-2023-4966',
  citrixbleed2: 'CVE-2025-5777', regresshion: 'CVE-2024-6387', bluekeep: 'CVE-2019-0708',
  shellshock: 'CVE-2014-6271', dirtypipe: 'CVE-2022-0847', dirtycow: 'CVE-2016-5195',
  follina: 'CVE-2022-30190', ghostcat: 'CVE-2020-1938', looneytunables: 'CVE-2023-4911',
  text4shell: 'CVE-2022-42889', pwnkit: 'CVE-2021-4034', baronsamedit: 'CVE-2021-3156',
  moveit: 'CVE-2023-34362', smbghost: 'CVE-2020-0796', petitpotam: 'CVE-2021-36942',
  hivenightmare: 'CVE-2021-36934', serioussam: 'CVE-2021-36934', sambacry: 'CVE-2017-7494',
  drupalgeddon: 'CVE-2014-3704', drupalgeddon2: 'CVE-2018-7600', curveball: 'CVE-2020-0601',
  sigred: 'CVE-2020-1350', poodle: 'CVE-2014-3566', meltdown: 'CVE-2017-5754', spectre: 'CVE-2017-5753',
  krack: 'CVE-2017-13077', zenbleed: 'CVE-2023-20593', downfall: 'CVE-2022-40982',
  terrapin: 'CVE-2023-48795', xzbackdoor: 'CVE-2024-3094'
};

function namedCve(query) {
  return NAMED[query.toLowerCase().replace(/[^a-z0-9]+/g, '')] || null;
}

// A typo has no word in the index at all, which a real term nearly never has.
// The closest word one edit away, weighed by how many records use it, stands
// in and the status line says so.
function withinOneEdit(a, b) {
  if (a === b) return true;
  if (Math.abs(a.length - b.length) > 1) return false;
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i++;
  if (a.length === b.length) {
    if (a.slice(i + 1) === b.slice(i + 1)) return true;
    return i + 1 < a.length && a[i] === b[i + 1] && a[i + 1] === b[i] && a.slice(i + 2) === b.slice(i + 2);
  }
  return a.length > b.length ? a.slice(i + 1) === b.slice(i) : b.slice(i + 1) === a.slice(i);
}

function closestWord(term) {
  const [start, end] = wordRange(term[0]);
  let best = null;
  let bestSize = 0;
  for (let i = start; i < end; i++) {
    const word = wordIndex.words[i];
    if (Math.abs(word.length - term.length) > 1 || !withinOneEdit(term, word)) continue;
    const size = wordIndex.postings.get(word).length;
    if (size > bestSize) { best = word; bestSize = size; }
  }
  return best;
}

function correctTerms(terms) {
  const changes = [];
  const fixed = terms.map(term => {
    const bare = term.replace(/^-?"|"$/g, '').toLowerCase();
    if (term[0] === '-' || term[0] === '"' || !/^[a-z0-9]{4,}$/.test(bare) || ALIASES[bare]) return term;
    const [start, end] = wordRange(bare);
    if (end > start) return term;
    const alt = closestWord(bare);
    if (!alt) return term;
    changes.push([bare, alt]);
    return alt;
  });
  return changes.length ? { query: fixed.join(' '), changes } : null;
}

/* ---- search ------------------------------------------------------------ */

const SORTS = [['RELEVANCE', 'RELEVANCE'], ['NEWEST', 'NEWEST'], ['POCS', 'MOST POCS']];

// Coarse steps so that one extra repository never decides the order on its own.
function linkBucket(count) {
  return count >= 100 ? 4 : count >= 20 ? 3 : count >= 5 ? 2 : count >= 2 ? 1 : 0;
}

// Within a score tier the evidence decides, newest last: whether CISA lists
// it, how many PoCs exist, how likely exploitation is. Falling straight
// through to the year put five 2026 records above regreSSHion for "openssh"
// and hid Log4Shell from the first page of "log4j".
function compareRelevance(a, b) {
  if (b._score !== a._score) return b._score - a._score;
  if (b._hits !== a._hits) return b._hits - a._hits;
  const ka = kev[a.cve] ? 1 : 0;
  const kb = kev[b.cve] ? 1 : 0;
  if (kb !== ka) return kb - ka;
  const la = linkBucket(entryLinks(a).length);
  const lb = linkBucket(entryLinks(b).length);
  if (lb !== la) return lb - la;
  const ea = Math.round(((epss[a.cve] || [0])[0] || 0) * 100);
  const eb = Math.round(((epss[b.cve] || [0])[0] || 0) * 100);
  if (eb !== ea) return eb - ea;
  if (b._year !== a._year) return b._year - a._year;
  return b._num - a._num;
}

function compareNewest(a, b) {
  return (b._published - a._published) || (b._year - a._year) || (b._num - a._num) || (b._score - a._score);
}

function comparePocs(a, b) {
  return (entryLinks(b).length - entryLinks(a).length) || (b._score - a._score)
    || (b._year - a._year) || (b._num - a._num);
}

function runSearch(query, scan = false, corrected = false) {
  // Pasted CVE identifiers also commonly arrive without hyphens or with spaces.
  query = query.trim().replace(/^cve[\s_-]*(\d{4})[\s_-]*(\d{4,})$/i, 'CVE-$1-$2');
  const terms = query.match(/-?"[^"]+"|-?\S+/g) || [];
  const cleaned = terms.map(t => t.replace(/^(-?)"/, '$1').replace(/"$/, ''));
  const positive = cleaned.filter(t => t && t[0] !== '-');
  const matchers = positive.map(buildMatcher).filter(Boolean);
  const groups = matchers.map(m => [m, ...(ALIASES[m.raw] || []).map(buildMatcher).filter(Boolean)]);
  // Unquoted words are matched independently, so "active directory" also hits a
  // description holding "active session" and "working directory". Reward the
  // words appearing together to keep those below real matches.
  const adjacent = positive.length > 1 ? positive.join(' ').toLowerCase() : '';
  const adjacentSpace = normalizeToSpaces(adjacent);
  const compound = positive.length > 1 && positive.length <= 4 &&
    positive.every(term => /^[a-z0-9]+$/i.test(term)) && !terms.some(term => term[0] !== '-' && term.includes('"'))
    ? buildMatcher(positive.join('')) : null;
  const negatives = cleaned
    .filter(t => t && t[0] === '-')
    .map(t => t.slice(1))
    .filter(Boolean)
    .map(buildMatcher)
    .filter(Boolean);

  const counts = !scan && wordIndex.ready && groups.length ? candidateCounts(groups) : null;
  const compoundCounts = counts && compound ? candidateCounts([[compound]]) : null;
  const results = [];
  results.pocTotal = 0;
  for (let at = 0; at < dataset.length; at++) {
    if (counts && counts[at] !== groups.length && !compoundCounts?.[at]) continue;
    const entry = dataset[at];
    if (!matchesFilters(entry)) continue;
    let score = 0;
    let matched = true;
    let linked = false;
    for (const group of groups) {
      const termScore = scoreGroup(entry, group);
      if (termScore === 0) { matched = false; break; }
      if (termScore === 350 || termScore === 80) linked = true;
      score += termScore;
    }
    const compoundScore = compound && (!compoundCounts || compoundCounts[at]) ? scoreEntry(entry, compound) : 0;
    if (compoundScore >= 350 && (!matched || compoundScore * groups.length > score)) {
      score = compoundScore * groups.length;
      matched = true;
      linked = compoundScore === 350;
    }
    if (!matched) continue;
    if (negatives.some(m => scoreEntry(entry, m) > 0)) continue;

    if (adjacent) {
      if (wordStart(identitySpace(entry), adjacentSpace) >= 0) score += 400;
      else {
        const at = wordStart(descSpace(entry), adjacentSpace);
        if (at >= 0) score += 300 + leadBonus(at);
        else if (wordStart(pocSpace(entry), adjacentSpace) >= 0) score += 100;
      }
      if (compoundScore >= 350) score += 400;
    }
    entry._score = score;
    // Within the same match tier, several PoCs using a name are stronger
    // evidence than a single link mentioning it on an unrelated, newer CVE.
    entry._hits = linked ? countLinkHits(entry, compoundScore >= 350 ? [compound] : matchers) : 0;
    results.pocTotal += entryLinks(entry).length;
    results.push(entry);
  }

  const out = results;

  if (!out.length && !scan && !corrected && wordIndex.ready) {
    const fix = correctTerms(terms);
    if (fix) {
      const again = runSearch(fix.query, false, true);
      again.corrected = fix.changes;
      return again;
    }
  }

  const star = namedCve(query);
  if (star) {
    let entry = out.find(e => e.cve === star);
    if (!entry) {
      entry = dataset.find(e => e.cve === star);
      if (entry && matchesFilters(entry)) {
        entry._score = 0;
        entry._hits = 0;
        out.pocTotal += entryLinks(entry).length;
        out.push(entry);
      }
    }
    if (entry) entry._score += 100000;
  }

  out.sort(state.sort === 'NEWEST' ? compareNewest : state.sort === 'POCS' ? comparePocs : compareRelevance);
  return out;
}

function prepareDataset(raw) {
  if (!Array.isArray(raw)) return [];
  const out = [];
  for (const entry of raw) {
    const cve = (entry.cve || '').trim();
    if (!cve) continue;
    for (const field of POC_FIELDS) {
      if (!Array.isArray(entry[field])) entry[field] = [];
    }
    if (!entryLinks(entry).length) continue;
    const parts = cve.split('-');
    entry._cveText = cve.toLowerCase();
    entry._cveCompact = entry._cveText.replace(/-/g, '');
    entry._descText = REPLACE_STRINGS
      .reduce((desc, str) => desc.replace(str, ''), entry.desc || '')
      .toLowerCase();
    entry._year = parseInt(parts[1], 10) || 0;
    entry._num = parseInt(parts[2], 10) || 0;
    entry._published = Date.parse(entry.published || entry.poc_observed || '') || 0;
    // Title, vendor and product, once the records carry them.
    const named = [entry.title || '', ...(entry.vendor || []), ...(entry.product || [])].join(' ');
    entry._titleText = named.toLowerCase();
    entry._titleSpace = normalizeToSpaces(entry._titleText);
    out.push(entry);
  }
  return out;
}

/* ---- rendering --------------------------------------------------------- */

const el = {
  input: document.querySelector('[data-search]'),
  status: document.querySelector('[data-status]'),
  notices: document.querySelector('[data-notices]'),
  results: document.querySelector('[data-results]'),
  trending: document.querySelector('[data-trending]'),
  trendDate: document.querySelector('[data-trend-date]'),
  trendRows: document.querySelector('[data-trend-rows]'),
  statTotal: document.querySelector('[data-stat-total]'),
  statPocs: document.querySelector('[data-stat-pocs]'),
  statKev: document.querySelector('[data-stat-kev]'),
  refreshed: document.querySelector('[data-refreshed]'),
  filterChips: {
    severity: document.querySelector('[data-filter-chips="severity"]'),
    source: document.querySelector('[data-filter-chips="source"]')
  },
  kevOnly: document.querySelector('[data-filter-kev]'),
  clearFilters: document.querySelector('[data-clear-filters]')
};

const CURATED = [
  { match: 'github.com/advisories/GHSA-', tag: 'GHSA', hint: 'GitHub reviewed advisory with reproducible exploit material',
    label: url => url.split('/').pop() },
  { match: '/zan8in/afrog/', tag: 'AFROG', hint: 'Runnable afrog CVE template',
    label: url => decodeURIComponent(url.split('/').pop()) },
  { match: '/chaitin/xray/', tag: 'XRAY', hint: 'Runnable xray CVE template',
    label: url => decodeURIComponent(url.split('/').pop()) },
  { match: '/helloexp/0day/', tag: '0DAY', hint: 'CVE-specific exploit collection path',
    label: url => decodeURIComponent(url.split('/').pop()) },
  { match: '/tzwlhack/Vulnerability/', tag: 'POC', hint: 'CVE-specific reproduction guide',
    label: url => decodeURIComponent(url.split('/').pop()) },
  { match: '/nuclei-templates/', tag: 'NUCLEI', hint: 'Runnable nuclei detection template',
    label: url => url.split('/').pop() },
  { match: '/metasploit-framework/', tag: 'MSF', hint: 'Metasploit module',
    label: url => url.split('/modules/').pop().replace(/\.rb$/, '') },
  { match: 'exploit-db.com/exploits/', tag: 'EDB', hint: 'ExploitDB entry',
    label: url => 'exploit-db.com/' + url.split('/').pop() },
  { match: '/vulhub/vulhub/tree/', tag: 'VULHUB', hint: 'Runnable Vulhub environment',
    label: url => url.split('/tree/master/').pop() }
];

// Multi-CVE research collections. A path into one is labelled below the
// collection's exploit directory, without the collection's stars.
const COLLECTION_SOURCES = {
  'google/security-research': { tag: 'GOOGLE', hint: 'Google Security Research exploit', root: 'pocs/' },
  'github/securitylab': { tag: 'GHSL', hint: 'GitHub Security Lab exploit', root: 'SecurityExploits/' },
  'tenable/poc': { tag: 'TENABLE', hint: 'Tenable Research proof of concept', root: '' },
  'pedrib/poc': { tag: 'PEDRIB', hint: 'pedrib/PoC exploit or advisory', root: '' }
};

/** A curated link's path below its collection's exploit directory, such as
 *  linux/kernelctf/CVE-2024-26642_cos. Empty for a repository root. */
function artifactPath(url) {
  const parsed = repoFromUrl(url);
  if (!parsed) return '';
  let parts = new URL(url).pathname.split('/').filter(Boolean).slice(2);
  if (parts[0] === 'tree' || parts[0] === 'blob') parts = parts.slice(2);
  let path = parts.join('/');
  try {
    path = decodeURIComponent(path);
  } catch (err) {
    // A malformed escape is shown as written.
  }
  const root = (COLLECTION_SOURCES[`${parsed.owner}/${parsed.repo}`.toLowerCase()] || {}).root;
  return root && path.startsWith(root) && path.length > root.length ? path.slice(root.length) : path;
}

function repositoryCells(url) {
  const parsed = repoFromUrl(url);
  const name = parsed ? (parsed.owner + '/' + parsed.repo).toLowerCase() : '';
  const meta = repoMeta[name];
  const stars = meta ? meta[0] : null;
  const starCell = stars == null ? 'N/A' : `${formatStars(stars)} <span class="star">★</span>`;
  const title = parsed ? `Repository stars: ${name}${stars == null ? ' (unavailable)' : ''}` : 'No GitHub repository';
  const pushed = meta && meta[1];
  const hours = pushed ? hoursSince(pushed) : null;
  // The repository cache stores UTC dates, not exact push times.
  const age = hours == null ? 'N/A' : /^\d{4}-\d{2}-\d{2}$/.test(pushed)
    ? hours < 24 ? 'today' : shortAge(Math.floor(hours / 24) * 24)
    : shortAge(hours);
  return `<span class="poc-stars${stars >= 500 ? ' is-popular' : ''}" title="${escapeHTML(title)}">${starCell}</span>` +
    `<span class="poc-age" title="Repository last push${meta && meta[1] ? ': ' + escapeHTML(meta[1]) + ' UTC' : ' unavailable'}">${escapeHTML(age)}</span>`;
}

function pocRow(url, artifact = false, listed = new Set()) {
  // A snapshot published in place of a lost original is named, tagged and
  // measured as that original, and its link opens the snapshot.
  const capture = waybackCapture(url);
  const target = capture ? capture.original : url;
  const href = escapeHTML(url);
  const row = (name, label) => {
    // Saved files share the Wayback control's cell, so the columns hold.
    const files = sourceFiles(url, label, listed);
    const archive = files ? `<div class="poc-archive">${archiveLink(url, label)}${files}</div>` : archiveLink(url, label);
    return '<div class="poc-row"><span class="poc-name">' + name + '</span>' + archive + repositoryCells(target) + '</div>';
  };
  const curated = CURATED.find(source => target.includes(source.match));
  if (curated) {
    const label = curated.label(target);
    return row(`<span class="poc-tag is-${curated.tag.toLowerCase()}" title="${escapeHTML(curated.hint)}">${curated.tag}</span>` +
      `<a href="${href}"${archivedName(label, capture)} target="_blank" rel="noopener">${escapeHTML(label)}</a>`, label);
  }
  const parsed = repoFromUrl(target);
  // Gists and advisories do not inherit a project's repository metadata.
  if (!parsed) {
    const label = plainLinkLabel(target);
    return row(`<a class="plain" href="${href}"${archivedName(label, capture)} target="_blank" rel="nofollow noopener">` +
      `${escapeHTML(label)}</a>`, label);
  }
  // Keep artifact identity while labelling stars and pushes as repository metadata.
  const path = artifact ? artifactPath(target) : '';
  if (path) {
    const name = `${parsed.owner}/${parsed.repo}`;
    const source = COLLECTION_SOURCES[name.toLowerCase()] || { tag: parsed.owner.toUpperCase(), hint: name };
    return row(`<span class="poc-tag is-${escapeHTML(source.tag.toLowerCase())}" title="${escapeHTML(source.hint)}">${escapeHTML(source.tag)}</span>` +
      `<a href="${href}"${archivedName(path, capture)} target="_blank" rel="noopener">${escapeHTML(path)}</a>`, path);
  }
  return row(`${escapeHTML(parsed.owner)}<span class="poc-sep"> / </span>` +
    `<a href="${href}"${archivedName(parsed.repo, capture)} target="_blank" rel="nofollow noopener">${escapeHTML(parsed.repo)}</a>`,
    `${parsed.owner}/${parsed.repo}`);
}

/** Published links are already scoped to the CVE. Rank their repositories by
 *  stars regardless of naming, with unknown readings after measured zeroes.
 *  An archived source ranks where its original would. */
function rankedLinks(entry) {
  if (entry._ranked) return entry._ranked;
  const scored = entryLinks(entry).map((url, index) => {
    const target = linkTarget(url);
    const parsed = repoFromUrl(target);
    const meta = parsed && repoMeta[(parsed.owner + '/' + parsed.repo).toLowerCase()];
    return {
      url,
      key: target.toLowerCase(),
      index,
      stars: meta ? meta[0] : -1
    };
  });
  scored.sort((a, b) =>
    (b.stars - a.stars) || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0) || (a.index - b.index));
  entry._ranked = scored.map(item => item.url);
  return entry._ranked;
}

function cvssTooltip(id) {
  const rows = ((metadata[id] || {}).cvss || []);
  if (!Array.isArray(rows)) return '';
  return rows.filter(Array.isArray).map(row => {
    const source = row[4] ? ` by ${row[4]}` : '';
    const assessment = row[5] ? ` (${row[5]})` : '';
    return `CVSS ${row[0]} ${row[1]} ${row[2]}${source}${assessment}\n${row[3] || ''}`.trim();
  }).join('\n\n');
}

function advisoryRow(item) {
  if (!Array.isArray(item) || !item[0]) return '';
  const url = String(item[0]);
  const tags = Array.isArray(item[1]) ? item[1].map(String) : [];
  const advisory = tags.some(tag => ADVISORY_TAGS.has(tag));
  const tag = tags.includes('Vendor Advisory') ? 'VENDOR' : tags.includes('Patch') ? 'PATCH'
    : advisory ? 'ADVISORY' : 'REFERENCE';
  return '<div class="poc-row"><span class="poc-name">' +
    `<span class="poc-tag is-advisory" title="${escapeHTML(tags.join(', ') || 'Reference')}">${tag}</span>` +
    `<a class="plain" href="${escapeHTML(url)}" target="_blank" rel="${tag === 'REFERENCE' ? 'nofollow noopener' : 'noopener'}">` +
    `${escapeHTML(plainLinkLabel(url))}</a>` +
    '</span><span class="poc-stars"></span><span class="poc-age"></span></div>';
}

function normalizedLink(url, preservePath = false) {
  const parsed = repoFromUrl(String(url || ''));
  if (parsed) {
    const key = `github:${parsed.owner.toLowerCase()}/${parsed.repo.toLowerCase()}`;
    if (!preservePath) return key;
    const location = new URL(url);
    const path = location.pathname.split('/').filter(Boolean).slice(2).join('/');
    return `${key}/${path}${location.search}${location.hash}`;
  }
  return String(url || '').replace(/\/$/, '');
}

function uniqueSourceLinks(urls, curated = []) {
  const seen = new Set();
  const artifacts = new Set(curated);
  const sources = new Set(curated.map(url => normalizedLink(url)));
  return urls.filter(url => {
    if (!artifacts.has(url) && sources.has(normalizedLink(url))) return false;
    const key = normalizedLink(url, artifacts.has(url));
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function resultRow(entry) {
  const id = entry.cve;
  const open = state.descOpen.has(id);
  const all = state.pocOpen.has(id);
  const links = rankedLinks(entry);
  const visible = all ? links : links.slice(0, POC_PREVIEW);
  const artifacts = new Set(POC_FIELDS.slice(1).flatMap(field => entry[field] || []));
  const listed = new Set(links.map(linkIdentity));
  // Nothing to expand means no control: a line reading "all repositories
  // shown" under a list of three is chrome that answers a question nobody has.
  const moreButton = links.length > POC_PREVIEW
    ? `<button type="button" class="poc-more" data-toggle-poc="${escapeHTML(id)}">` +
      `${all ? '↑ show fewer' : '+ ' + formatCount(links.length - POC_PREVIEW) + ' more'}</button>`
    : '';

  const advisoryOpen = state.advisoryOpen.has(id);
  const pocLinks = new Set(links.map(url => normalizedLink(url, true)));
  const advisories = ((metadata[id] || {}).advisories || [])
    .filter(item => Array.isArray(item) && !pocLinks.has(normalizedLink(item[0], true)));
  const shownAdvisories = advisoryOpen ? advisories : advisories.slice(0, ADVISORY_PREVIEW);
  const advisoryMore = advisories.length > ADVISORY_PREVIEW
    ? `<button type="button" class="poc-more" data-toggle-advisory="${escapeHTML(id)}">` +
      `${advisoryOpen ? '↑ show fewer' : '+ ' + formatCount(advisories.length - ADVISORY_PREVIEW) + ' more'}</button>`
    : '';
  const advisoryHtml = advisories.length
    ? `<div class="advisory-list"><div class="advisory-head">CVE REFERENCES <span>${formatCount(advisories.length)}</span></div>` +
      `${shownAdvisories.map(advisoryRow).join('')}${advisoryMore}</div>`
    : '';

  // NVD is canonical and carries every CVSS generation. Nuclei remains a
  // fallback for a template scored before NVD or its CNA publishes a vector.
  const canonical = canonicalCvss(id);
  const fallback = ratings[id] || {};
  const severity = canonical ? canonical.severity : entrySeverity(entry);
  const cvss = canonical ? canonical.score : fallback.cvss;
  const tooltip = canonical ? cvssTooltip(id) : String(fallback.cvss_vector || '');
  const severityChip = severity
    ? `<span class="chip chip-sev is-${escapeHTML(severity.toLowerCase())}"${tooltip ? ` title="${escapeHTML(tooltip)}"` : ''}>` +
      `${escapeHTML(severity)}${cvss != null ? ' ' + escapeHTML(cvss) : ''}</span>`
    : '';
  // FIRST's feed covers nearly the whole index; a template's own score is the
  // fallback for the handful it misses.
  const scored = epss[id] || null;
  const epssChip = scored
    ? `<span class="chip chip-epss${scored[0] >= 0.1 ? ' is-hot' : ''}" title="EPSS: estimated chance of exploitation in the next 30 days, ${ordinal(Math.round(scored[1] * 100))} percentile">` +
      `EPSS ${(scored[0] * 100).toFixed(scored[0] >= 0.1 ? 0 : 1)}%</span>`
    : '';

  const flagged = kev[id];
  const kevChip = flagged
    ? `<span class="chip chip-kev" title="Listed in CISA's Known Exploited Vulnerabilities catalogue on ${escapeHTML(flagged[0])}${flagged[1] ? ', used in ransomware campaigns' : ''}">` +
      `KEV${flagged[1] ? ' RANSOMWARE' : ''}</span>`
    : '';
  const metadataChip = entry.metadata_pending
    ? '<span class="chip">CVE metadata pending</span>'
    : '';

  const dates = [];
  if (entry.published) dates.push(`published ${entry.published}`);
  else if (entry.poc_observed) dates.push(`PoC observed ${entry.poc_observed}`);
  if (entry.modified) dates.push(`modified ${entry.modified}`);
  const dateHtml = dates.length
    ? `<div class="result-dates">${dates.map(d => `<span>${escapeHTML(d)}</span>`).join('')}</div>`
    : '';

  return `<div class="result-row">
  <div class="result-meta">
    <a class="result-id" href="/${encodeURIComponent(id)}">${escapeHTML(id)}</a>
    <div class="result-pocs">${formatCount(links.length)} linked PoC${links.length === 1 ? '' : 's'}</div>
    ${dateHtml}
    <div class="chips">${metadataChip}${kevChip}${severityChip}${epssChip}
      <a class="chip" href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}" target="_blank" rel="noopener">NVD ↗</a>
      <a class="chip" href="https://www.cve.org/CVERecord?id=${encodeURIComponent(id)}" target="_blank" rel="noopener">CVE.ORG ↗</a>
    </div>
  </div>
  <div class="result-body">
    ${entry.title ? `<p class="result-title">${escapeHTML(entry.title)}</p>` : ''}
    <p class="result-desc${open ? ' is-open' : ''}">${escapeHTML(entry.desc || '')}</p>
    <button type="button" class="expander" data-toggle-desc="${escapeHTML(id)}">${open ? '↑ collapse' : '↓ full description'}</button>
    <div class="poc-list">
      ${visible.map(url => pocRow(url, artifacts.has(url), listed)).join('')}
      ${moreButton}
    </div>
    ${advisoryHtml}
  </div>
</div>`;
}

/** Hide the expander on descriptions that already fit; a button that does
 *  nothing when clicked is worse than no button. */
function pruneExpanders() {
  for (const row of el.results.querySelectorAll('.result-row')) {
    const desc = row.querySelector('.result-desc');
    const button = row.querySelector('.expander');
    if (!desc || !button) continue;
    if (!desc.classList.contains('is-open') && desc.scrollHeight <= desc.clientHeight + 1) {
      button.hidden = true;
    }
  }
}

function renderResults(elapsed) {
  const results = state.results;
  el.trending.hidden = true;
  el.results.hidden = false;

  if (!results.length) {
    const subject = state.query.length >= MIN_QUERY
      ? ` for ${escapeHTML(state.query)}`
      : ' for the active filters';
    el.results.innerHTML = `<div class="empty">No results${subject}</div>`;
    // The live region is the only account of this a screen reader gets, and
    // returning here left it reading "loading index…" over a page that had
    // already given up.
    if (elapsed != null) {
      el.status.textContent = `no results in ${Math.max(1, Math.round(elapsed))}ms`;
    }
    return;
  }

  const shown = results.slice(0, state.shown);
  const pocTotal = results.pocTotal;
  const remaining = results.length - shown.length;
  const footer = remaining > 0
    ? `<button type="button" class="poc-more" style="padding:9px 16px" data-more-results>+ ${formatCount(remaining)} more matching CVEs</button>`
    : '';

  const sortSwitch = SORTS.map(([key, label]) =>
    `<button type="button" data-sort="${key}" aria-pressed="${String(state.sort === key)}">${label}</button>`
  ).join('');
  el.results.innerHTML = `<div class="panel-head">
      <h2>Results</h2>
      <span class="panel-count">${formatCount(results.length)} CVE${results.length === 1 ? '' : 's'} · ${formatCount(pocTotal)} PoC${pocTotal === 1 ? '' : 's'}</span>
      <div class="switch switch-sort" role="group" aria-label="Order">${sortSwitch}</div>
    </div>
    <div class="col-head"><span>CVE</span><span>DESCRIPTION / POC LINKS</span></div>
    ${shown.map(resultRow).join('')}${footer}`;
  pruneExpanders();

  if (elapsed != null) {
    const note = results.corrected
      ? results.corrected.map(([typed, used]) => `${used} for ${typed}`).join(', ') + ' · '
      : '';
    el.status.textContent = `${formatCount(results.length)} CVE${results.length === 1 ? '' : 's'} · ${note}matched in ${Math.max(1, Math.round(elapsed))}ms`;
  }
}

// Switch value to the trending_poc.json list it shows. RECENT is the old
// newest-first value, still sent by cached pages.
const TREND_LISTS = { LANDED: 'landed', TRENDING: 'items', RECENT: 'landed' };

function trendRow(item, landed, listed = new Set()) {
  const url = String(item.url || '');
  const parsed = repoFromUrl(url);
  const repository = parsed ? (parsed.owner + '/' + parsed.repo).toLowerCase() : '';
  const stars = repository ? item.stars : null;
  const starCell = stars == null ? 'N/A' : `${formatStars(stars)} <span class="star">★</span>`;
  const title = repository ? `Repository stars: ${repository}${stars == null ? ' (unavailable)' : ''}` : 'No GitHub repository';
  // Off GitHub the last path segment is a bare id, so it keeps its host.
  const host = String(item.source || '').replace(/^www\./, '');
  const name = item.artifact && host && host !== 'github.com' ? `${host}/${item.name || ''}` : item.name;
  // The trending table flags the same catalogue the CVE rows do, so a row worth
  // reading first is visible without opening it.
  const flagged = item.kev ? '<span class="trend-kev" title="CISA known exploited">KEV</span>' : '';
  const detail = item.page
    ? `<a class="trend-detail" href="${escapeHTML(item.page)}">${escapeHTML(item.cve)} details</a>`
    : '';
  const label = String(name || url);
  return `<div class="trend-row"><span class="trend-stars${stars >= 500 ? ' is-popular' : ''}" title="${escapeHTML(title)}">${starCell}</span>` +
    trendAge(landed ? item.released : item.pushed) +
    `<div class="trend-name-cell">${flagged}<a class="trend-name" href="${escapeHTML(item.url)}" target="_blank" rel="nofollow noopener"` +
    `${archivedName(label, waybackCapture(url))}>${escapeHTML(name)}</a>` +
    `<div class="trend-sub">${detail}${archiveLink(url, label)}${sourceFiles(url, label, listed)}</div></div>` +
    `<span class="trend-desc">${escapeHTML(item.desc || 'Description unavailable')}</span></div>`;
}

function renderTrending() {
  el.results.hidden = true;
  el.trending.hidden = false;
  // Keep the build's rows if the optional feed is still loading or unavailable.
  if (!indexMeta) return;

  // Each list arrives ranked and is shown as published, as build_pages.py
  // pre-renders it.
  const list = TREND_LISTS[state.mode];
  const landed = list === 'landed';
  const rows = (Array.isArray(indexMeta[list]) ? indexMeta[list] : []).slice(0, TREND_ROWS);
  const listed = new Set(rows.map(item => linkIdentity(String(item.url || ''))));
  el.trendRows.innerHTML = rows.length
    ? rows.map(item => trendRow(item, landed, listed)).join('')
    : '<div class="empty">No recent PoCs.</div>';
  if (el.trendDate) {
    el.trendDate.textContent = landed ? 'RELEASED' : 'UPDATED';
    el.trendDate.title = landed ? 'First release (UTC)' : 'Latest artifact commit (UTC)';
  }

  document.querySelectorAll('.trend-controls .switch button').forEach(button => {
    button.setAttribute('aria-pressed', String(TREND_LISTS[button.dataset.mode] === list));
  });
}

function paintHeroStats() {
  if (!el.statTotal) return;
  if (indexMeta) {
    el.statTotal.textContent = formatCount(indexMeta.total_cves);
    el.statPocs.textContent = formatCount(indexMeta.with_pocs);
  }
  const flagged = Object.keys(kev).length;
  if (flagged) el.statKev.textContent = formatCount(flagged);
}

function idleStatus() {
  // The hero carries the totals now, so the field keeps its slot for timings.
  return '';
}

/* ---- url state --------------------------------------------------------- */

// A result was unlinkable: every search lived in memory, so nobody could cite
// one and no crawler ever saw a second page. The query rides in ?q= now, which
// is also the route the OpenSearch descriptor declares.
function readURLState() {
  const params = new URLSearchParams(location.search);
  const query = (params.get('q') || '').trim();
  if (query) {
    state.query = query;
    el.input.value = query;
  }
  if (params.get('kev') === '1') state.kevOnly = true;
  const sort = (params.get('sort') || '').toUpperCase();
  if (SORTS.some(([key]) => key === sort)) state.sort = sort;
  const short = { severity: 'sev', source: 'src' };
  for (const [kind, options] of Object.entries(FILTER_OPTIONS)) {
    const wanted = (params.get(short[kind]) || '').toUpperCase().split(',')
      .filter(value => options.some(([each]) => each === value));
    if (wanted.length) state.filters[kind] = new Set(wanted);
  }
}

// replaceState, not pushState: typing a query should not bury the back button
// under one history entry per keystroke.
let urlTimer = null;
function syncURL() {
  clearTimeout(urlTimer);
  urlTimer = setTimeout(() => {
    const params = new URLSearchParams();
    if (state.query.length >= MIN_QUERY) params.set('q', state.query);
    if (state.kevOnly) params.set('kev', '1');
    if (state.sort !== 'RELEVANCE') params.set('sort', state.sort.toLowerCase());
    const short = { severity: 'sev', source: 'src' };
    for (const [kind, filter] of Object.entries(state.filters)) {
      if (filter.size !== FILTER_OPTIONS[kind].length) {
        params.set(short[kind], FILTER_OPTIONS[kind].map(([value]) => value).filter(value => filter.has(value)).join(','));
      }
    }
    const search = params.toString();
    const next = search ? `${location.pathname}?${search}` : location.pathname;
    if (next !== location.pathname + location.search) history.replaceState(null, '', next);
  }, 300);
}

function render() {
  syncURL();
  el.notices.textContent = [...enrichmentNotices].join(' · ');
  el.notices.hidden = !enrichmentNotices.size;
  if (state.query.length < MIN_QUERY && !hasActiveFilters()) {
    el.status.textContent = state.ready ? idleStatus() : state.loadFailed ? 'index unavailable' : 'loading index…';
    renderTrending();
    return;
  }
  if (!state.ready) {
    el.results.hidden = false;
    el.trending.hidden = true;
    el.status.textContent = state.loadFailed ? 'index unavailable' : 'loading index…';
    el.results.innerHTML = state.loadFailed
      ? '<div class="empty">The CVE index could not be loaded. Reload the page to try again, or browse by year below.</div>'
      : '<div class="empty">Loading the CVE index…</div>';
    return;
  }
  const started = performance.now();
  state.results = runSearch(state.query.length >= MIN_QUERY ? state.query : '');
  renderResults(performance.now() - started);
}

/* ---- wiring ------------------------------------------------------------ */

// A full pass over the index costs ~200ms, so one per keystroke makes typing
// stutter. 160ms covers an ordinary typing cadence without the wait being felt;
// clearing the field stays instant.
let searchTimer = null;
el.input.addEventListener('input', () => {
  const next = el.input.value.trim();
  if (next === state.query) return;
  state.query = next;
  state.shown = PAGE_SIZE;
  clearTimeout(searchTimer);
  if (next.length < MIN_QUERY) {
    render();
    return;
  }
  searchTimer = setTimeout(render, 160);
});

document.querySelector('.search').addEventListener('submit', event => event.preventDefault());

// One chip per value, every one of them on the page. A full set is the idle
// state and draws nothing lit, so the first click narrows to that value; later
// clicks widen the set, and switching the last lit chip off is a clear.
function renderFilterOptions() {
  for (const [kind, options] of Object.entries(FILTER_OPTIONS)) {
    el.filterChips[kind].innerHTML = options.map(([value, label]) =>
      `<button type="button" class="filter-chip is-${escapeHTML(value.toLowerCase())}" ` +
      `data-filter-kind="${kind}" data-filter-value="${value}" aria-pressed="false" disabled>` +
      `${escapeHTML(label)}</button>`
    ).join('');
  }
}

function enableFilter(kind) {
  for (const chip of el.filterChips[kind].querySelectorAll('[data-filter-value]')) chip.disabled = false;
}

function toggleFilter(kind, value) {
  const filter = state.filters[kind];
  if (filter.size === FILTER_OPTIONS[kind].length) {
    filter.clear();
    filter.add(value);
  } else if (!filter.has(value)) {
    filter.add(value);
  } else {
    filter.delete(value);
    if (!filter.size) for (const [each] of FILTER_OPTIONS[kind]) filter.add(each);
  }
}

function syncFilterControls() {
  for (const kind of Object.keys(FILTER_OPTIONS)) {
    const filter = state.filters[kind];
    const narrowed = filter.size !== FILTER_OPTIONS[kind].length;
    for (const chip of el.filterChips[kind].querySelectorAll('[data-filter-value]')) {
      chip.setAttribute('aria-pressed', String(narrowed && filter.has(chip.dataset.filterValue)));
    }
  }
  el.kevOnly.setAttribute('aria-pressed', String(state.kevOnly));
  el.clearFilters.hidden = !hasActiveFilters();
}

for (const kind of Object.keys(FILTER_OPTIONS)) {
  el.filterChips[kind].addEventListener('click', event => {
    const chip = event.target.closest('[data-filter-value]');
    if (!chip || chip.disabled) return;
    toggleFilter(kind, chip.dataset.filterValue);
    state.shown = PAGE_SIZE;
    syncFilterControls();
    render();
  });
}

el.kevOnly.addEventListener('click', () => {
  state.kevOnly = !state.kevOnly;
  state.shown = PAGE_SIZE;
  syncFilterControls();
  render();
});

el.clearFilters.addEventListener('click', () => {
  state.kevOnly = false;
  for (const [kind, filter] of Object.entries(state.filters)) {
    filter.clear();
    for (const [value] of FILTER_OPTIONS[kind]) filter.add(value);
  }
  state.shown = PAGE_SIZE;
  syncFilterControls();
  render();
});

renderFilterOptions();
syncFilterControls();

// Typing anywhere on the page means typing into the search field. The keystroke
// is not swallowed: focusing during keydown lets the character land in the
// field it just moved to, so the first letter is never lost.
document.addEventListener('keydown', event => {
  if (event.ctrlKey || event.metaKey || event.altKey) return;
  if (document.activeElement === el.input) {
    if (event.key === 'Escape') {
      el.input.value = '';
      el.input.dispatchEvent(new Event('input', { bubbles: true }));
      el.input.blur();
    }
    return;
  }
  const active = document.activeElement;
  // Space on a saved-files disclosure toggles it, as on a button.
  const editing = active && (active.isContentEditable
    || ['INPUT', 'TEXTAREA', 'SELECT', 'BUTTON', 'SUMMARY'].includes(active.tagName));
  if (editing) return;
  // A lone slash is the shortcut, so it focuses without typing itself.
  if (event.key === '/') {
    event.preventDefault();
    el.input.focus();
    return;
  }
  if (event.key.length !== 1 && event.key !== 'Backspace') return;
  el.input.focus();
});

// A pointer landing on the page is not a request to type, so the field is only
// focused up front where a keyboard is the likely input.
if (window.matchMedia('(min-width: 900px)').matches) el.input.focus();

document.querySelector('.switch').addEventListener('click', event => {
  const button = event.target.closest('button[data-mode]');
  if (!button || !TREND_LISTS[button.dataset.mode]) return;
  state.mode = button.dataset.mode;
  renderTrending();
});

el.results.addEventListener('click', event => {
  const sort = event.target.closest('[data-sort]');
  if (sort) {
    state.sort = sort.dataset.sort;
    state.shown = PAGE_SIZE;
    render();
    return;
  }
  const desc = event.target.closest('[data-toggle-desc]');
  const poc = event.target.closest('[data-toggle-poc]');
  const advisory = event.target.closest('[data-toggle-advisory]');
  const more = event.target.closest('[data-more-results]');
  if (desc) {
    const id = desc.dataset.toggleDesc;
    state.descOpen.has(id) ? state.descOpen.delete(id) : state.descOpen.add(id);
  } else if (poc) {
    const id = poc.dataset.togglePoc;
    state.pocOpen.has(id) ? state.pocOpen.delete(id) : state.pocOpen.add(id);
  } else if (advisory) {
    const id = advisory.dataset.toggleAdvisory;
    state.advisoryOpen.has(id) ? state.advisoryOpen.delete(id) : state.advisoryOpen.add(id);
  } else if (more) {
    state.shown += PAGE_SIZE;
  } else {
    return;
  }
  renderResults(null);
});

// An open saved-files list stays open through the re-renders that late data
// and other toggles cause. Toggle events do not bubble, so this listens early.
function rememberSources(event) {
  const box = event.target;
  if (!box || typeof box.matches !== 'function' || !box.matches('details.sources')) return;
  if (box.open) state.sourcesOpen.add(box.dataset.sources);
  else state.sourcesOpen.delete(box.dataset.sources);
}
el.results.addEventListener('toggle', rememberSources, true);
el.trendRows.addEventListener('toggle', rememberSources, true);

async function loadJSON(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) throw new Error(`${url} (${response.status})`);
  return response.json();
}

function enrichmentUnavailable(kind, error) {
  console.warn(error.message);
  if (dataEpoch) return;
  if (kind === 'kev') {
    enrichmentNotices.add('KEV filter unavailable');
  } else if (kind === 'severity') {
    enrichmentNotices.add('severity filter unavailable');
  } else {
    enrichmentNotices.add(`${kind} unavailable`);
  }
  syncFilterControls();
  render();
}

// Snapshot links are display-only enrichment. They land whenever they arrive,
// never hold up the index or reorder a result, and a failed or malformed
// download keeps the snapshots already shown.
function landArchives(request, epoch) {
  request.then(data => {
    if (dataEpoch !== epoch || !data || typeof data !== 'object' || Array.isArray(data)) return;
    archives = data;
    if (state.query.length < MIN_QUERY && !hasActiveFilters()) renderTrending();
    else if (state.ready) renderResults(null);
  }).catch(err => console.warn(`Archive snapshots unavailable: ${err.message}`));
}

/** Snapshots and saved files the build confirmed for the rows it published.
 *  They stand until archives.json lands, so a row never trades its snapshot
 *  for a lookup or loses its files. */
function publishedSnapshots() {
  const found = new Map();
  const record = url => found.get(url) || found.set(url, {}).get(url);
  for (const link of el.trendRows.querySelectorAll('.trend-row a.wayback.is-snapshot, .trend-row details.sources a')) {
    const capture = waybackCapture(link.getAttribute('href'));
    const sources = capture && link.closest('details.sources');
    if (sources) {
      // A saved file, filed under the original its row discloses it for.
      const parent = sources.getAttribute('data-sources');
      const saved = parent ? record(linkTarget(parent)) : null;
      if (saved) (saved.files || (saved.files = [])).push({ original: capture.original, url: capture.url, timestamp: capture.stamp });
      continue;
    }
    const row = capture && link.closest('.trend-row');
    const name = row && row.querySelector('.trend-name');
    if (name) Object.assign(record(name.getAttribute('href')), { url: capture.url, timestamp: capture.stamp });
  }
  return Object.fromEntries(found);
}

function paintRefreshTime(meta) {
  const minutes = Math.max(0, Math.round((Date.now() - Date.parse(meta.generated)) / 60000));
  el.refreshed.textContent = minutes < 60
    ? `index refreshed ${minutes} minute${minutes === 1 ? '' : 's'} ago`
    : `index refreshed ${Math.round(minutes / 60)} hour${Math.round(minutes / 60) === 1 ? '' : 's'} ago`;
}

const DATA_REFRESH_MS = 5 * 60 * 1000;
let lastDataCheck = Date.now();
let refreshingData = false;

async function refreshData(force = false) {
  if (refreshingData || (!state.ready && !state.loadFailed) || document.hidden ||
      (!force && Date.now() - lastDataCheck < DATA_REFRESH_MS)) return false;
  refreshingData = true;
  lastDataCheck = Date.now();
  try {
    const feed = await loadJSON(`/trending_poc.json?refresh=${lastDataCheck}`, { cache: 'no-store' });
    if (!feed.generated) throw new Error('Refresh has no publication timestamp');
    if (feed.generated === indexMeta?.generated && state.ready && !enrichmentNotices.size) {
      paintRefreshTime(feed);
      return false;
    }
    const names = ['CVE_list', 'repo_meta', 'cvss', 'advisories', 'nuclei', 'kev', 'epss'];
    const [entries, repositories, scores, advisories, templates, exploited, probabilities] =
      await Promise.all(names.map(name => loadJSON(`/${name}.json?v=${encodeURIComponent(feed.generated)}`, { cache: 'no-store' })));
    if (!Array.isArray(entries) || entries.length !== feed.with_pocs ||
        [repositories, scores, advisories, templates, exploited, probabilities].some(value =>
          !value || typeof value !== 'object' || Array.isArray(value))) {
      throw new Error('Incomplete index refresh');
    }
    const current = await loadJSON(`/trending_poc.json?refresh=${Date.now()}`, { cache: 'no-store' });
    if (current.generated !== feed.generated) throw new Error('Publication changed during refresh');
    const nextMetadata = {};
    for (const [id, rows] of Object.entries(scores)) (nextMetadata[id] || (nextMetadata[id] = {})).cvss = rows;
    for (const [id, rows] of Object.entries(advisories)) (nextMetadata[id] || (nextMetadata[id] = {})).advisories = rows;
    // Swap one complete snapshot. A failed optional download keeps the current
    // search, ordering and expanded rows intact, and is retried on the next check.
    dataset = prepareDataset(entries);
    dataEpoch += 1;
    repoMeta = repositories;
    metadata = nextMetadata;
    ratings = templates;
    kev = exploited;
    epss = probabilities;
    indexMeta = feed;
    severityEpoch += 1;
    state.results = [];
    state.ready = true;
    state.loadFailed = false;
    enrichmentNotices.clear();
    yieldNext = null;
    buildWordIndex();
    enableFilter('severity');
    enableFilter('source');
    el.kevOnly.disabled = false;
    syncFilterControls();
    document.querySelectorAll('.trend-controls .switch button').forEach(button => { button.disabled = false; });
    paintHeroStats();
    paintRefreshTime(feed);
    render();
    // Optional: until it lands, or if it fails, the previous snapshots stand.
    landArchives(loadJSON(`/archives.json?v=${encodeURIComponent(feed.generated)}`, { cache: 'no-store' }), dataEpoch);
    return true;
  } catch (err) {
    console.warn(`Index refresh deferred: ${err.message}`);
    return false;
  } finally {
    refreshingData = false;
  }
}

async function checkForUpdates() {
  await refreshData();
  setTimeout(checkForUpdates, DATA_REFRESH_MS);
}
setTimeout(checkForUpdates, DATA_REFRESH_MS);
document.addEventListener('visibilitychange', () => { if (!document.hidden) refreshData(); });
window.addEventListener?.('focus', () => { refreshData(); });

(async () => {
  archives = publishedSnapshots();
  readURLState();
  syncFilterControls();
  render();

  // Trending is optional. A slow feed must not hold up a bookmarked search.
  loadJSON('/trending_poc.json', { cache: 'no-store' }).then(meta => {
    if (dataEpoch) return;
    indexMeta = meta;
    paintRefreshTime(meta);
    document.querySelectorAll('.trend-controls .switch button').forEach(button => { button.disabled = false; });
    paintHeroStats();
    render();
  }).catch(err => console.warn(err.message));

  // Optional enrichment must not block discovery; unavailable values are explicit.
  loadJSON('/kev.json', { cache: 'no-cache' }).then(data => {
    if (dataEpoch) return;
    kev = data || {};
    el.kevOnly.disabled = false;
    paintHeroStats();
    render();
  }).catch(err => enrichmentUnavailable('kev', err));

  // The metadata comes in two halves. The CVSS rows are small and gate the
  // severity filter, so they load with everything else; the advisories are
  // 2.4 MB on the wire and only show inside a rendered row, so they follow
  // the index rather than compete with it.
  loadJSON('/cvss.json', { cache: 'no-cache' }).then(data => {
    if (dataEpoch) return;
    for (const [id, rows] of Object.entries(data || {})) (metadata[id] || (metadata[id] = {})).cvss = rows;
    severityEpoch += 1;
    enableFilter('severity');
    if (state.ready && (state.query || hasActiveFilters())) render();
  }).catch(err => enrichmentUnavailable('severity', err));
  const loadAdvisories = () => loadJSON('/advisories.json', { cache: 'no-cache' }).then(data => {
    if (dataEpoch) return;
    for (const [id, rows] of Object.entries(data || {})) (metadata[id] || (metadata[id] = {})).advisories = rows;
    if (state.ready && (state.query || hasActiveFilters())) renderResults(null);
  }).catch(err => enrichmentUnavailable('advisories', err));

  loadJSON('/nuclei.json', { cache: 'no-cache' }).then(data => {
    if (dataEpoch) return;
    ratings = data || {};
    severityEpoch += 1;
    if (state.ready && (state.query || hasActiveFilters())) render();
  }).catch(err => enrichmentUnavailable('template ratings', err));

  loadJSON('/epss.json', { cache: 'no-cache' }).then(data => {
    if (dataEpoch) return;
    epss = data || {};
    if (state.ready && (state.query || hasActiveFilters())) render();
  }).catch(err => enrichmentUnavailable('EPSS', err));

  loadJSON('/repo_meta.json', { cache: 'no-cache' }).then(data => {
    if (dataEpoch) return;
    repoMeta = data || {};
    for (const entry of dataset) entry._ranked = null;
    if (state.ready && (state.query || hasActiveFilters())) renderResults(null);
  }).catch(err => enrichmentUnavailable('repository metadata', err));

  try {
    const entries = await loadJSON('/CVE_list.json', { cache: 'no-cache' });
    if (dataEpoch) return;
    dataset = prepareDataset(entries);
    state.ready = true;
    enableFilter('source');
    render();
    buildWordIndex();
  } catch (err) {
    if (dataEpoch) return;
    console.warn(err.message);
    state.loadFailed = true;
    render();
  }
  loadAdvisories();
  // One snapshot per linked PoC adds up, so it follows the index as well.
  landArchives(loadJSON('/archives.json', { cache: 'no-cache' }), 0);
})();
