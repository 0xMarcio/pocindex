"""Curated collection paths are named by place, not by their repository's stars.

The CVE page comes from build_pages; the search results come from logic.js, run
in node the way tests/test_search.js runs it, so the two can be compared.
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
VARIANTS = [KERNELCTF + target for target in ("cos", "lts", "mitigation")]
# url: (search tag, label, repository named on the CVE page)
COLLECTION_PATHS = {
    "https://github.com/github/securitylab/tree/main/SecurityExploits/freedesktop/poppler-CVE-2025-52885":
        ("GHSL", "freedesktop/poppler-CVE-2025-52885", "github/securitylab"),
    "https://github.com/tenable/poc/tree/master/netatalk/cve_2018_1160":
        ("TENABLE", "netatalk/cve_2018_1160", "tenable/poc"),
    "https://github.com/pedrib/PoC/blob/master/advisories/Pwn2Own/Tokyo_2020/minesweeper.md":
        ("PEDRIB", "advisories/Pwn2Own/Tokyo_2020/minesweeper.md", "pedrib/PoC"),
    "https://github.com/zan8in/afrog/blob/main/pocs/afrog-pocs/CVE/2025/CVE-2025-52885.yaml":
        ("AFROG", "CVE-2025-52885.yaml", "zan8in/afrog"),
    "https://github.com/tzwlhack/Vulnerability/blob/main/Poppler/Poppler%20CVE-2025-52885.md":
        ("POC", "Poppler CVE-2025-52885.md", "tzwlhack/Vulnerability"),
    "https://github.com/example/exploits/tree/main/poppler/CVE-2025-52885":
        ("EXAMPLE", "poppler/CVE-2025-52885", "example/exploits"),
}
ROOT_LINK = "https://github.com/owner/dedicated"
TEMPLATE = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-44228.yaml"
ADVISORY_TEXT = "https://github.com/pedrib/PoC/blob/master/advisories/webnms-5.2-sp1-pwn.txt"
REPO_META = {
    "google/security-research": [4682, "2026-10-01"],
    "github/securitylab": [1632, "2026-06-08"],
    "tenable/poc": [1335, "2024-11-12"],
    "pedrib/poc": [861, "2025-04-16"],
    "example/exploits": [12, "2026-09-30"],
    "projectdiscovery/nuclei-templates": [13023, "2026-09-26"],
    "owner/dedicated": [120, "2026-09-29"],
}
VARIANT_ENTRY = {"cve": "CVE-2024-26642", "desc": "nf_tables", "poc": [ROOT_LINK], "collections": VARIANTS}
SOURCE_ENTRY = {"cve": "CVE-2025-52885", "desc": "poppler", "poc": [], "collections": list(COLLECTION_PATHS)}
ROOT_ENTRY = {"cve": "CVE-2021-44228", "desc": "log4j", "poc": [], "nuclei": [TEMPLATE], "collections": [ROOT_LINK]}
POC_ENTRY = {"cve": "CVE-2016-6602", "desc": "webnms", "poc": [ADVISORY_TEXT]}

HARNESS = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const { MessageChannel } = require('node:worker_threads');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const elements = new Map();
const document = {
  addEventListener() {},
  querySelectorAll: () => [],
  querySelector(selector) {
    if (!elements.has(selector)) elements.set(selector, {
      value: '', innerHTML: '', addEventListener() {}, setAttribute() {}, querySelectorAll: () => []
    });
    return elements.get(selector);
  }
};
const context = vm.createContext({
  console: { warn() {} }, document, performance, MessageChannel, URLSearchParams, URL,
  location: { pathname: '/', search: '' },
  window: { matchMedia: () => ({ matches: false }) },
  setTimeout() {}, clearTimeout() {},
  fetch: () => new Promise(() => {})
});
vm.runInContext(fs.readFileSync(input.script, 'utf8'), context);
context.input = input;
const markup = vm.runInContext(
  'repoMeta = input.repoMeta; state.pocOpen.add(input.entry.cve); resultRow(input.entry)', context);
vm.runInContext('yieldPort.port1.close(); yieldPort.port2.close();', context);
process.stdout.write(JSON.stringify(markup));
"""


def page_blocks(entry: dict) -> dict[str, list[tuple[str, str, str]]]:
    """(href, label, note) for each row under each counted heading of a CVE page."""
    data = {"cves": [entry], "meta": {}, "epss": {}, "kev": {}, "nuclei": {}, "repo_meta": REPO_META,
            "related": {}, "lastmod": {entry["cve"]: "2026-10-07"}}
    markup = build_pages.page(entry, data)
    return {
        heading: [tuple(html.unescape(part) for part in row) for row in re.findall(
            r'<li><a href="([^"]*)"[^>]*>([^<]*)</a>(?:<span>([^<]*)</span>)?</li>', body)]
        for heading, body in re.findall(r'<h2>([^<]+?) \([\d,]+\)</h2><ul class="cve-links">(.*?)</ul>', markup, re.S)
    }


def search_rows(entry: dict) -> dict[str, dict]:
    """The tag, label and star and age cells of each search result PoC row, by href."""
    node = shutil.which("node")
    if node is None:
        raise unittest.SkipTest("node renders the search results")
    payload = {"script": str(ROOT / "docs" / "logic.js"), "entry": entry, "repoMeta": REPO_META}
    done = subprocess.run([node, "-e", HARNESS], input=json.dumps(payload), capture_output=True,
                          text=True, timeout=60)
    if done.returncode:
        raise AssertionError(done.stderr)
    rows = {}
    for row in re.findall(r'<div class="poc-row">(.*?)</div>', json.loads(done.stdout), re.S):
        tag = re.search(r'<span class="poc-tag[^"]*"[^>]*>([^<]*)</span>', row)
        href, label = re.search(r'<a href="([^"]*)"[^>]*>([^<]*)</a>', row).groups()
        stars, age = re.search(r'<span class="poc-stars[^"]*">(.*?)</span><span class="poc-age">([^<]*)</span>',
                               row, re.S).groups()
        rows[html.unescape(href)] = {"tag": tag[1] if tag else "", "label": html.unescape(label),
                                     "stars": stars, "age": age}
    return rows


class ArtifactLabelTests(unittest.TestCase):
    def test_kernelctf_variants_are_named_by_target(self) -> None:
        self.assertEqual([build_pages.artifact_label(url) for url in VARIANTS], [
            "linux/kernelctf/CVE-2024-26642_cos",
            "linux/kernelctf/CVE-2024-26642_lts",
            "linux/kernelctf/CVE-2024-26642_mitigation",
        ])

    def test_each_collection_is_named_by_its_place_in_the_collection(self) -> None:
        for url, (_, label, _) in COLLECTION_PATHS.items():
            with self.subTest(url=url):
                self.assertEqual(build_pages.artifact_label(url), label)

    def test_roots_advisories_and_other_hosts_are_not_artifacts(self) -> None:
        for url in (ROOT_LINK, ROOT_LINK + "/", "https://github.com/google/security-research/tree/master",
                    "https://github.com/google/security-research/security/advisories/GHSA-7f33-f4f5-xwgw",
                    "https://www.exploit-db.com/exploits/50592"):
            with self.subTest(url=url):
                self.assertEqual(build_pages.artifact_label(url), "")


class CvePageTests(unittest.TestCase):
    def test_kernelctf_variants_are_distinct_and_carry_no_repository_stars_or_dates(self) -> None:
        rows = page_blocks(VARIANT_ENTRY)["Exploit collections"]
        self.assertEqual(rows, [
            (KERNELCTF + "cos", "linux/kernelctf/CVE-2024-26642_cos", "google/security-research"),
            (KERNELCTF + "lts", "linux/kernelctf/CVE-2024-26642_lts", "google/security-research"),
            (KERNELCTF + "mitigation", "linux/kernelctf/CVE-2024-26642_mitigation", "google/security-research"),
        ])

    def test_every_collection_names_its_repository_in_place_of_its_stars(self) -> None:
        self.assertEqual(page_blocks(SOURCE_ENTRY)["Exploit collections"],
                         [(url, label, repository) for url, (_, label, repository) in COLLECTION_PATHS.items()])

    def test_other_curated_paths_keep_their_label_and_lose_repository_metadata(self) -> None:
        self.assertEqual(page_blocks(ROOT_ENTRY)["Nuclei templates"],
                         [(TEMPLATE, TEMPLATE[len(build_pages.GITHUB):], "")])

    def test_repository_roots_and_repository_links_keep_stars_and_push_dates(self) -> None:
        root = [(ROOT_LINK, "owner/dedicated", "120★ · 2026-09-29")]
        self.assertEqual(page_blocks(ROOT_ENTRY)["Exploit collections"], root)
        self.assertEqual(page_blocks(VARIANT_ENTRY)["Proof-of-concept exploits"], root)
        self.assertEqual(page_blocks(POC_ENTRY)["Proof-of-concept exploits"],
                         [(ADVISORY_TEXT, ADVISORY_TEXT[len(build_pages.GITHUB):], "861★ · 2025-04-16")])


class SearchAgreementTests(unittest.TestCase):
    def test_search_names_each_collection_path_as_the_cve_page_does(self) -> None:
        tags = {**{url: "GOOGLE" for url in VARIANTS}, **{url: row[0] for url, row in COLLECTION_PATHS.items()}}
        for entry in (VARIANT_ENTRY, SOURCE_ENTRY):
            rows = search_rows(entry)
            for href, label, _ in page_blocks(entry)["Exploit collections"]:
                with self.subTest(href=href):
                    self.assertEqual(rows[href], {"tag": tags[href], "label": label, "stars": "", "age": ""})

    def test_search_keeps_repository_columns_outside_curated_paths(self) -> None:
        for entry, url, label in ((VARIANT_ENTRY, ROOT_LINK, "dedicated"), (ROOT_ENTRY, ROOT_LINK, "dedicated"),
                                  (POC_ENTRY, ADVISORY_TEXT, "PoC")):
            with self.subTest(cve=entry["cve"]):
                row = search_rows(entry)[url]
                self.assertEqual((row["tag"], row["label"]), ("", label))
                self.assertRegex(row["stars"], r"^\d+ <span class=\"star\">★</span>$")
                self.assertTrue(row["age"])
        template = search_rows(ROOT_ENTRY)[TEMPLATE]
        self.assertEqual((template["tag"], template["stars"], template["age"]), ("NUCLEI", "", ""))


if __name__ == "__main__":
    unittest.main()
