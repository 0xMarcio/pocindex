"""The front-page lists read the same before and after the feed arrives.

build_pages pre-renders Just landed; logic.js renders both lists from
trending_poc.json, run in node the way tests/test_search.js runs it.
"""

from __future__ import annotations

import html
import json
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_pages

KERNELCTF = "https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-26642_"
SHARED = "https://github.com/owner/CVE-2026-21589"
# Published order. Sorting either list by stars or by date would change it.
LANDED = [
    {"cve": "CVE-2024-26642", "url": KERNELCTF + "mitigation", "name": "CVE-2024-26642_mitigation", "stars": None,
     "desc": "nf_tables", "released": "2026-10-06T23:30:00-02:00", "basis": "commit", "kev": False,
     "page": "/CVE-2024-26642", "landed": True, "source": "github.com", "artifact": True},
    {"cve": "CVE-2026-21589", "url": SHARED, "name": "CVE-2026-21589", "stars": 5,
     "desc": "Atlassian's <b>file read</b>", "released": "2026-10-06T15:51:43Z", "basis": "commit", "kev": True,
     "page": "/CVE-2026-21589", "landed": True, "source": "github.com", "artifact": False},
    {"cve": "CVE-2021-44228", "url": "https://www.exploit-db.com/exploits/50592", "name": "50592", "stars": 4682,
     "desc": "log4j", "released": "2026-10-05", "basis": "source", "kev": True,
     "page": "/CVE-2021-44228", "landed": True, "source": "www.exploit-db.com", "artifact": True},
]
TRENDING = [
    {"cve": "CVE-2026-21589", "url": SHARED, "name": "CVE-2026-21589", "stars": 5, "desc": "Atlassian",
     "pushed": "2026-10-06T15:51:43Z", "released": "2026-10-06T15:51:43Z", "basis": "commit", "score": 0.4,
     "trending": True, "kev": True, "page": "/CVE-2026-21589"},
    {"cve": "CVE-2026-24061", "url": "https://github.com/owner/CVE-2026-24061", "name": "CVE-2026-24061",
     "stars": 1250, "desc": "telnetd", "pushed": "2026-10-03T16:24:22Z", "released": "2026-03-08T11:25:39Z",
     "basis": "commit", "score": 0.3, "trending": True, "kev": False, "page": "/CVE-2026-24061"},
    {"cve": "CVE-2026-99999", "url": "https://github.com/owner/unpublished", "name": "unpublished", "stars": 40,
     "desc": "", "pushed": None, "released": None, "basis": "unknown", "score": 0.2, "trending": True,
     "kev": False, "page": None},
]
FEED = {"generated": "2026-10-07T09:00:00+00:00", "total_cves": 5, "with_pocs": 4,
        "items": TRENDING, "landed": LANDED, "ranking": "stars_weighted_by_artifact_release_age"}
INDEXED = [{"cve": cve} for cve in ("CVE-2024-26642", "CVE-2026-21589", "CVE-2021-44228", "CVE-2026-24061")]

HARNESS = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const { MessageChannel } = require('node:worker_threads');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const elements = new Map();
const buttons = ['LANDED', 'TRENDING'].map(mode => ({
  dataset: { mode }, disabled: mode !== 'LANDED', pressed: null,
  setAttribute(name, value) { if (name === 'aria-pressed') this.pressed = value; }
}));
const document = {
  addEventListener() {},
  querySelectorAll: selector => selector === '.trend-controls .switch button' ? buttons : [],
  querySelector(selector) {
    if (!elements.has(selector)) elements.set(selector, {
      value: '', innerHTML: '', textContent: '', addEventListener() {}, setAttribute() {}, querySelectorAll: () => []
    });
    return elements.get(selector);
  }
};
const context = vm.createContext({
  console: { warn() {} }, document, performance, MessageChannel, URLSearchParams, URL,
  location: { pathname: '/', search: '' },
  window: { matchMedia: () => ({ matches: false }) },
  setTimeout() {}, clearTimeout() {},
  fetch: url => url === '/trending_poc.json'
    ? Promise.resolve({ ok: true, json: async () => input.feed })
    : new Promise(() => {})
});
vm.runInContext(fs.readFileSync(input.script, 'utf8'), context);
const view = () => ({
  rows: elements.get('[data-trend-rows]').innerHTML,
  date: elements.get('[data-trend-date]').textContent,
  pressed: buttons.map(button => button.pressed),
  disabled: buttons.map(button => button.disabled)
});
setImmediate(() => {
  const views = { initial: view() };
  for (const mode of ['TRENDING', 'RECENT', 'LANDED']) {
    vm.runInContext(`state.mode = ${JSON.stringify(mode)}; renderTrending();`, context);
    views[mode] = view();
  }
  vm.runInContext('yieldPort.port1.close(); yieldPort.port2.close();', context);
  process.stdout.write(JSON.stringify(views));
});
"""


def browser(feed: dict) -> dict:
    """What logic.js shows once the feed arrives, then for each switch value."""
    node = shutil.which("node")
    if node is None:
        raise unittest.SkipTest("node renders the browser lists")
    payload = {"script": str(ROOT / "docs" / "logic.js"), "feed": feed}
    done = subprocess.run([node, "-e", HARNESS], input=json.dumps(payload), capture_output=True,
                          text=True, timeout=60)
    if done.returncode:
        raise AssertionError(done.stderr)
    return json.loads(done.stdout)


def as_browser(markup: str) -> str:
    """html.escape writes an apostrophe as &#x27; where logic.js writes &#39;."""
    return markup.replace("&#x27;", "&#39;")


def cells(markup: str) -> list[dict]:
    rows = []
    for row in re.findall(r'<div class="trend-row">(.*?)</div>', markup):
        stars = re.search(r'<span class="trend-stars[^"]*">(.*?)</span><span class="trend-age">', row).group(1)
        href, name = re.search(r'<a class="trend-name" href="([^"]*)"[^>]*>([^<]*)</a>', row).groups()
        rows.append({"href": html.unescape(href), "name": html.unescape(name),
                     "stars": re.sub(r"<[^>]+>", "", stars), "kev": 'class="trend-kev"' in row,
                     "date": re.search(r'<span class="trend-age">([^<]*)</span>', row).group(1)})
    return rows


class HomepageListTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.views = browser(FEED)

    def test_browser_and_prerendered_homepage_render_the_same_rows(self) -> None:
        landed, trending = build_pages.trend_rows(LANDED, True), build_pages.trend_rows(TRENDING, False)
        for mode in ("initial", "LANDED", "RECENT"):
            with self.subTest(mode=mode):
                self.assertEqual(self.views[mode]["rows"], as_browser(landed))
        self.assertEqual(self.views["TRENDING"]["rows"], as_browser(trending))
        page = build_pages.homepage(INDEXED, {}, FEED)
        self.assertIn(landed, page)
        self.assertNotIn("telnetd", page)

    def test_each_list_keeps_its_published_order_and_may_share_a_poc(self) -> None:
        landed, trending = cells(self.views["LANDED"]["rows"]), cells(self.views["TRENDING"]["rows"])
        self.assertEqual([row["href"] for row in landed], [item["url"] for item in LANDED])
        self.assertEqual([row["href"] for row in trending], [item["url"] for item in TRENDING])
        self.assertIn(SHARED, [row["href"] for row in landed])
        self.assertIn(SHARED, [row["href"] for row in trending])

    def test_dates_are_utc_days_and_unknown_dates_stay_blank(self) -> None:
        landed, trending = cells(self.views["LANDED"]["rows"]), cells(self.views["TRENDING"]["rows"])
        self.assertEqual([row["date"] for row in landed], ["2026-10-07", "2026-10-06", "2026-10-05"])
        self.assertEqual([row["date"] for row in trending], ["2026-10-06", "2026-10-03", ""])
        self.assertEqual([self.views[mode]["date"] for mode in ("initial", "TRENDING", "RECENT")],
                         ["RELEASED", "UPDATED", "RELEASED"])
        self.assertNotIn(" ago", self.views["LANDED"]["rows"] + self.views["TRENDING"]["rows"])

    def test_artifacts_drop_collection_stars_and_keep_their_variant_or_host(self) -> None:
        landed = cells(self.views["LANDED"]["rows"])
        self.assertEqual([(row["name"], row["stars"], row["kev"]) for row in landed], [
            ("CVE-2024-26642_mitigation", "", False), ("CVE-2026-21589", "5 ★", True),
            ("exploit-db.com/50592", "", True)])
        self.assertEqual(cells(self.views["TRENDING"]["rows"])[1]["stars"], "1.3k ★")
        self.assertIn("Atlassian&#39;s &lt;b&gt;file read&lt;/b&gt;", self.views["LANDED"]["rows"])

    def test_switch_starts_on_just_landed_and_trending_waits_for_the_feed(self) -> None:
        page = build_pages.homepage(INDEXED, {}, FEED)
        landed = re.search(r'<button [^>]*data-mode="LANDED"[^>]*>', page).group(0)
        trending = re.search(r'<button [^>]*data-mode="TRENDING"[^>]*>', page).group(0)
        self.assertIn('aria-pressed="true"', landed)
        self.assertIn(" disabled", trending)
        self.assertEqual(self.views["initial"]["disabled"], [False, False])
        self.assertEqual([self.views[mode]["pressed"] for mode in ("initial", "TRENDING", "RECENT")],
                         [["true", "false"], ["false", "true"], ["true", "false"]])

    def test_an_empty_list_shows_the_empty_state_in_both(self) -> None:
        empty = build_pages.trend_rows([], True)
        self.assertIn("No recent PoCs.", empty)
        self.assertEqual(browser({**FEED, "landed": []})["initial"]["rows"], empty)


if __name__ == "__main__":
    unittest.main()
