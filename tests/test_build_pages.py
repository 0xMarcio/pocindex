from __future__ import annotations

import copy
import io
import json
import re
import sys
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import build_pages
import build_seo

# A source file saved at a pinned commit, as archives.json lists it under its page.
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def raw_file(path: str, repository: str = "owner/poc", commit: str = COMMIT) -> str:
    return f"https://raw.githubusercontent.com/{repository}/{commit}/{path}"


def saved_file(original: str, stamp: str = "20261022161013") -> dict:
    return {"original": original, "url": f"https://web.archive.org/web/{stamp}/{original}", "timestamp": stamp}


class ContentDateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.entry = {"cve": "CVE-2024-1234", "desc": "Widget flaw", "modified": "2024-01-01",
                      "poc": ["https://github.com/owner/poc"]}
        self.data = {"today": "2026-10-06", "meta": {}, "nuclei": {}, "kev": {}, "repo_meta": {}}

    def test_new_links_from_every_source_advance_the_page_date(self) -> None:
        original = build_pages.content_state(self.entry, self.data, {})
        self.assertEqual(original[1], "2024-01-01")
        previous = {self.entry["cve"]: original}
        for source in ("poc", "nuclei", "msf", "edb", "vulhub", "collections"):
            with self.subTest(source=source):
                changed = copy.deepcopy(self.entry)
                changed.setdefault(source, []).append("https://example.com/new-exploit")
                result = build_pages.content_state(changed, self.data, previous)
                self.assertNotEqual(result[0], original[0])
                self.assertEqual(result[1], "2026-10-06")
                self.assertEqual(build_pages.content_state(changed, {**self.data, "today": "2026-10-07"},
                                                          {changed["cve"]: result}), result)

    def test_removed_links_and_changed_assessments_advance_the_date(self) -> None:
        original = build_pages.content_state(self.entry, self.data, {})
        previous = {self.entry["cve"]: original}
        removed = {**self.entry, "poc": []}
        self.assertEqual(build_pages.content_state(removed, self.data, previous)[1], self.data["today"])
        for field, value in (("kev", ["2026-10-06", False]), ("meta", {"cvss": [["3.1", 9.8, "CRITICAL"]]})):
            changed = {**self.data, field: {self.entry["cve"]: value}}
            self.assertEqual(build_pages.content_state(self.entry, changed, previous)[1], self.data["today"])

    def test_new_pages_in_an_established_manifest_get_publication_date(self) -> None:
        previous = {"CVE-2024-9999": ["previous fingerprint", "2024-01-01"]}
        self.assertEqual(build_pages.content_state(self.entry, self.data, previous)[1], self.data["today"])

    def test_stars_scores_and_repository_pushes_do_not_advance_date(self) -> None:
        self.entry["poc"].append("https://github.com/vendor/project/security/advisories/GHSA-1234")
        self.data["repo_meta"] = {"owner/poc": [10, "2024-02-01"], "vendor/project": [5000, "2026-10-06"]}
        original = build_pages.content_state(self.entry, self.data, {})
        self.assertEqual(original[1], "2024-01-01")
        previous = {self.entry["cve"]: original}
        self.data["repo_meta"] = {"owner/poc": [100, "2026-10-06"], "vendor/project": [5000, "2026-10-07"]}
        self.data["epss"] = {self.entry["cve"]: [0.9, 0.99]}
        self.assertEqual(build_pages.content_state(self.entry, self.data, previous), original)

    def test_manifests_fingerprinted_with_repository_pushes_keep_their_dates(self) -> None:
        self.data["repo_meta"] = {"owner/poc": [10, "2024-02-01"]}
        payload = {"entry": self.entry, "cvss": None, "advisories": None, "nuclei": None, "kev": None}
        published = {self.entry["cve"]: [build_pages.digest({**payload, "pushed": {"owner/poc": "2024-02-01"}}),
                                         "2024-02-01"]}
        self.assertEqual(build_pages.content_state(self.entry, self.data, published),
                         [build_pages.digest(payload), "2024-02-01"])
        changed = {**self.entry, "desc": "Widget flaw, now remote"}
        self.assertEqual(build_pages.content_state(changed, self.data, published)[1], self.data["today"])

    def test_confirmed_snapshots_advance_the_date_and_other_archive_records_do_not(self) -> None:
        url, stamp = self.entry["poc"][0], "20251021093000"
        record = {"url": f"https://web.archive.org/web/{stamp}/{url}", "timestamp": stamp}
        original = build_pages.content_state(self.entry, self.data, {})
        previous = {self.entry["cve"]: original}
        # Records the page cannot render leave it as published.
        for archives in ({}, {"https://github.com/owner/other": record}, {url: {**record, "timestamp": "20251021093001"}},
                         {url: {**record, "url": f"http://web.archive.org/web/{stamp}/{url}"}}):
            with self.subTest(archives=archives):
                self.assertEqual(build_pages.content_state(self.entry, {**self.data, "archives": archives}, previous),
                                 original)
        archived = build_pages.content_state(self.entry, {**self.data, "archives": {url: record}}, previous)
        self.assertNotEqual(archived[0], original[0])
        self.assertEqual(archived[1], self.data["today"])
        later = {**self.data, "today": "2026-10-07"}
        self.assertEqual(build_pages.content_state(self.entry, {**later, "archives": {url: {**record, "checked": "x"}}},
                                                   {self.entry["cve"]: archived}), archived)
        self.assertEqual(build_pages.content_state(self.entry, later, {self.entry["cve"]: archived})[1], "2026-10-07")

    def test_saved_files_advance_the_date_and_other_file_records_do_not(self) -> None:
        url, cid = self.entry["poc"][0], self.entry["cve"]

        def archived(files: object, data: dict = self.data) -> dict:
            return {**data, "archives": {url: {"files": files}}}

        original = build_pages.content_state(self.entry, self.data, {})
        previous = {cid: original}
        # Files the page cannot show leave it as published.
        for files in ([], [saved_file(raw_file("poc.py", "owner/other"))], [saved_file(raw_file("poc.py", commit="main"))],
                      [{**saved_file(raw_file("poc.py")), "timestamp": "20261022161014"}],
                      [saved_file("https://hackerone.com/reports/123456.json")]):
            with self.subTest(files=files):
                self.assertEqual(build_pages.content_state(self.entry, archived(files), previous), original)
        # A first saved file advances the page while its own snapshot is pending.
        first = build_pages.content_state(self.entry, archived([saved_file(raw_file("poc.py"))]), previous)
        self.assertNotEqual(first[0], original[0])
        self.assertEqual(first[1], self.data["today"])
        later = {**self.data, "today": "2026-10-07"}
        # Order, repeats and older captures of the same file change nothing the page shows.
        same = [saved_file(raw_file("poc.py"), "20261021120000"), saved_file(raw_file("poc.py")), saved_file(raw_file("poc.py"))]
        self.assertEqual(build_pages.content_state(self.entry, archived(same, later), {cid: first}), first)
        # A refreshed capture, or another file, does.
        for files in ([saved_file(raw_file("poc.py"), "20261023100000")],
                      [saved_file(raw_file("poc.py")), saved_file(raw_file("lib.py"))]):
            with self.subTest(files=files):
                changed = build_pages.content_state(self.entry, archived(files, later), {cid: first})
                self.assertNotEqual(changed[0], first[0])
                self.assertEqual(changed[1], "2026-10-07")
        # A file the page lists in a row of its own is not disclosed, or counted, twice.
        listed = {**self.entry, "poc": [url, raw_file("poc.py")]}
        self.assertEqual(build_pages.content_state(listed, archived([saved_file(raw_file("poc.py"))]), {}),
                         build_pages.content_state(listed, self.data, {}))
        # Pages with a snapshot and no files keep the fingerprint they were published with.
        snapshot = {"url": f"https://web.archive.org/web/20251021093000/{url}", "timestamp": "20251021093000"}
        payload = {"entry": self.entry, "cvss": None, "advisories": None, "nuclei": None, "kev": None,
                   "archives": {url: [snapshot["url"], snapshot["timestamp"]]}}
        self.assertEqual(build_pages.content_state(self.entry, {**self.data, "archives": {url: snapshot}}, {})[0],
                         build_pages.digest(payload))

    def test_missing_manifest_bootstraps_but_outages_do_not_erase_state(self) -> None:
        with patch.object(build_pages.request, "urlopen", side_effect=HTTPError("url", 404, "missing", {}, None)):
            self.assertEqual(build_pages.previous_page_state(), {})
        with patch.object(build_pages.request, "urlopen", side_effect=URLError("offline")):
            with self.assertRaises(URLError):
                build_pages.previous_page_state()
        with patch.object(build_pages.request, "urlopen", return_value=io.BytesIO(b'{"version":1,"pages":{}}')):
            self.assertEqual(build_pages.previous_page_state(), {})


class SeoOutputTests(unittest.TestCase):
    def test_removing_the_newest_cve_advances_hub_and_sitemap_dates(self) -> None:
        from xml.etree import ElementTree
        entries = [{"cve": f"CVE-2024-{n}", "poc": ["https://github.com/owner/poc"]} for n in (1001, 1002)]
        data = {"kev": {}, "lastmod": {entries[0]["cve"]: "2024-01-01", entries[1]["cve"]: "2026-10-06"},
                "today": "2026-10-06"}
        first = build_pages.hub_pages(entries, data)
        remaining = entries[:1]
        updated = build_pages.hub_pages(remaining, {**data, "previous": first["states"], "today": "2026-10-07"})
        self.assertEqual(updated["lastmod"]["2024"], "2026-10-07")
        self.assertEqual(updated["lastmod"]["CVE-2024-1xxx"], "2026-10-07")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "CVE_list.json").write_text(json.dumps(remaining))
            (root / "page_lastmod.json").write_text(json.dumps({entries[0]["cve"]: "2024-01-01", **updated["lastmod"]}))
            with patch.multiple(build_seo, DOCS=directory, ROBOTS=str(root / "robots.txt"), SITEMAP=str(root / "sitemap.xml")):
                build_seo.main()
            index = ElementTree.parse(root / "sitemap.xml")
            ns = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
            dates = {row.find("s:loc", ns).text: row.find("s:lastmod", ns).text for row in index.findall("s:sitemap", ns)}
            self.assertEqual(dates[f"{build_seo.SITE}/sitemap-2024.xml"], "2026-10-07")

    def test_block_ranges_use_valid_cve_number_padding(self) -> None:
        entry = {"cve": "CVE-2024-0001", "poc": ["https://github.com/owner/poc"]}
        hubs = build_pages.hub_pages([entry], {"kev": {}, "lastmod": {entry["cve"]: "2024-01-01"}, "today": "2026-10-06"})
        self.assertIn("CVE-2024-0000 to CVE-2024-0999", hubs["pages"]["CVE-2024-0xxx.html"])
        self.assertIn("CVE-2024-0000 to 0999", hubs["pages"]["2024.html"])

    def test_opensearch_escapes_description_as_xml(self) -> None:
        from xml.etree import ElementTree
        with patch.object(build_seo, "DESCRIPTION", "PoCs & CVEs <indexed>"):
            descriptor = ElementTree.fromstring(build_seo.opensearch())
        self.assertEqual(descriptor.find("{http://a9.com/-/spec/opensearch/1.1/}Description").text, "PoCs & CVEs <indexed>")


class ParsedPage(HTMLParser):
    def __init__(self, markup: str) -> None:
        super().__init__()
        self.tags = []
        self.text = []
        self.feed(markup)

    def handle_starttag(self, tag, attrs) -> None:
        self.tags.append((tag, dict(attrs)))

    def handle_data(self, data) -> None:
        self.text.append(data)


class HomepageTests(unittest.TestCase):
    def render(self, total: int = 123456) -> str:
        return build_pages.homepage(
            [{"cve": "CVE-2030-1234"}, {"cve": "CVE-2024-3400"}],
            {"CVE-2024-3400": ["2024-04-12", False]},
            {"total_cves": total, "with_pocs": 2, "generated": "2030-01-02T12:00:00Z", "landed": [
                {"cve": "CVE-2030-1234", "stars": 5, "released": "2030-01-02T09:00:00Z", "page": "/CVE-2030-1234",
                 "name": "Example PoC", "url": "https://github.com/owner/poc", "desc": "A widget exploit"},
                {"cve": "CVE-2030-9999", "stars": None, "released": "2030-01-01T00:00:00Z", "page": None,
                 "name": "New PoC", "url": "https://github.com/owner/new", "desc": "</script><script>alert(1)</script>"},
            ], "items": [
                {"cve": "CVE-2024-3400", "stars": 40, "pushed": "2030-01-01T00:00:00Z", "page": "/CVE-2024-3400",
                 "name": "Trending PoC", "url": "https://github.com/owner/trending", "desc": "A trending exploit"},
            ]},
        )

    def test_initial_html_has_current_counts_and_crawlable_links(self) -> None:
        for total in (123456, 123457):
            page = ParsedPage(self.render(total))
            text = " ".join(page.text)
            self.assertIn(f"{total:,}", text)
            self.assertIn("Example PoC", text)
            self.assertIn("A widget exploit", text)
            links = [attrs.get("href") for tag, attrs in page.tags if tag == "a"]
            self.assertIn("/2030", links)
            self.assertIn("/2024", links)
            self.assertNotIn("/2026", links)
            self.assertIn("/CVE-2030-1234", links)
            self.assertNotIn("/CVE-2030-9999", links)

    def test_metadata_is_consistent_and_does_not_bake_in_counts(self) -> None:
        page = ParsedPage(self.render())
        descriptions = [attrs["content"] for tag, attrs in page.tags if tag == "meta" and
                        (attrs.get("name") in {"description", "twitter:description"} or
                         attrs.get("property") == "og:description")]
        self.assertEqual(descriptions, [build_pages.DESCRIPTION] * 3)
        self.assertTrue(all("82,000" not in text and "123,456" not in text for text in descriptions))
        schemas = [json.loads(text) for text in page.text if text.startswith('{"@context"')]
        self.assertEqual(schemas[0]["description"], build_pages.DESCRIPTION)
        self.assertIn("pocindex", schemas[0]["alternateName"])
        self.assertTrue(any(tag == "section" and "data-trending" in attrs and
                            "data-nosnippet" in attrs for tag, attrs in page.tags))
        self.assertEqual(sum(tag == "div" and "data-nosnippet" in attrs for tag, attrs in page.tags), 3)

    def test_untrusted_text_cannot_add_markup_or_end_structured_data(self) -> None:
        unsafe = '</script><script>alert("injected")</script>'
        with patch.object(build_pages, "DESCRIPTION", unsafe):
            page = ParsedPage(self.render())
        scripts = [attrs for tag, attrs in page.tags if tag == "script"]
        self.assertEqual(len(scripts), 2)  # One JSON-LD block and logic.js.
        schemas = [json.loads(text) for text in page.text if text.startswith('{"@context"')]
        self.assertEqual(schemas[0]["description"], unsafe)

    def test_inconsistent_feed_counts_fail_the_build(self) -> None:
        with self.assertRaisesRegex(ValueError, "counts disagree"):
            build_pages.homepage([], {}, {"total_cves": 1, "with_pocs": 1})


class AssessmentRenderingTests(unittest.TestCase):
    def test_pending_record_page_keeps_public_pocs_visible(self) -> None:
        entry = {"cve": "CVE-2026-109618", "desc": "Official CVE details are pending.",
                 "metadata_pending": True, "poc": ["https://github.com/example/php2shell-poc"]}
        data = {"cves": [entry], "meta": {}, "epss": {}, "kev": {}, "nuclei": {},
                "repo_meta": {}, "related": {}, "lastmod": {entry["cve"]: "2026-10-21"}}
        markup = build_pages.page(entry, data)
        self.assertIn("CVE metadata pending</span>", markup)
        self.assertIn('href="https://github.com/example/php2shell-poc"', markup)
        del entry["metadata_pending"]
        self.assertNotIn("CVE metadata pending", build_pages.page(entry, data))

    def test_zero_cvss_score_is_visible_in_chip_and_assessment(self) -> None:
        entry = {"cve": "CVE-1999-0497", "poc": ["https://example.com/poc"]}
        data = {
            "cves": [entry],
            "meta": {entry["cve"]: {"cvss": [[
                "2.0", 0.0, "LOW", "AV:N/AC:L/Au:N/C:N/I:N/A:N", "nvd@nist.gov", "Primary",
            ]]}},
            "epss": {}, "kev": {}, "nuclei": {}, "repo_meta": {}, "related": {},
            "lastmod": {entry["cve"]: "2026-10-06"},
        }
        markup = build_pages.page(entry, data)
        self.assertIn("LOW 0.0</span>", markup)
        self.assertIn("<dd>0.0 LOW<code>", markup)

    def test_exploit_only_cve_references_are_nofollow_references(self) -> None:
        poc = "https://github.com/owner/poc"
        attachment = "https://github.com/user-attachments/files/24473682/environment_newline_injection.sh"
        rfc = "https://www.rfc-editor.org/rfc/rfc9110"
        commit = "https://github.com/vendor/project/commit/0123abc"
        entry = {"cve": "CVE-2026-1234", "desc": "Widget flaw", "poc": [poc]}
        rows = [["https://vendor.example/advisory", ["Vendor Advisory", "Patch", "Exploit"]],
                [commit, ["Patch", "Exploit"]], ["https://lists.example/thread", ["Third Party Advisory", "Exploit"]],
                [attachment, ["Exploit"]], [rfc, ["Exploit"]], [poc, ["Exploit"]]]
        data = {"cves": [entry], "meta": {entry["cve"]: {"advisories": rows}}, "epss": {}, "kev": {}, "nuclei": {},
                "repo_meta": {}, "related": {}, "lastmod": {entry["cve"]: "2026-10-29"}}
        markup = build_pages.page(entry, data)
        self.assertNotIn("Security advisories", markup)
        references = markup.split("<h2>CVE references</h2>", 1)[1].split("</ul>", 1)[0]
        self.assertEqual(re.findall(r'<li><a href="([^"]+)" rel="([^"]+)" target="_blank">[^<]*</a>'
                                    r'<span title="([^"]*)">([A-Z]+)</span></li>', references), [
            (attachment, "nofollow noopener", "Exploit", "REFERENCE"),
            (commit, "noopener", "Patch, Exploit", "PATCH"),
            ("https://lists.example/thread", "noopener", "Third Party Advisory, Exploit", "ADVISORY"),
            ("https://vendor.example/advisory", "noopener", "Vendor Advisory, Patch, Exploit", "VENDOR"),
            (rfc, "nofollow noopener", "Exploit", "REFERENCE"),
        ])
        # The listed PoC keeps its own section and count, and is not repeated as a reference.
        self.assertIn("<title>CVE-2026-1234: 1 public PoC exploit | PoC Index</title>", markup)
        self.assertIn(f'<h2>Proof-of-concept exploits (1)</h2><ul class="cve-links"><li><a href="{poc}" '
                      'rel="nofollow noopener" target="_blank">owner/poc</a>', markup)

    def test_ibm_assessment_names_its_scorer(self) -> None:
        row = ["3.0", 7.1, "HIGH", "", "psirt@us.ibm.com", "Secondary"]
        self.assertEqual(build_pages.assessor(row), "IBM")


class RepositoryMetadataTests(unittest.TestCase):
    def test_repository_links_sort_by_stars_without_name_priority(self) -> None:
        named = "https://github.com/owner/CVE-2021-1675"
        alias = "https://github.com/nemo-wq/PrintNightmare-CVE-2021-34527"
        unknown = "https://github.com/owner/unknown"
        row = build_pages.link_rows([named, unknown, alias], {
            "owner/cve-2021-1675": [0, "2026-10-21"],
            "nemo-wq/printnightmare-cve-2021-34527": [177, "2021-06-29"],
        })
        self.assertLess(row.index(alias), row.index(named))
        self.assertLess(row.index(named), row.index(unknown))

    def test_repository_advisories_do_not_inherit_repository_metadata(self) -> None:
        url = "https://github.com/vendor/project/security/advisories/GHSA-1234"
        row = build_pages.link_rows([url], {"vendor/project": [5000, "2026-10-06"]})
        self.assertIn(f'href="{url}"', row)
        self.assertNotIn("★", row)
        self.assertIsNone(build_pages.owner_of(url))

    def test_repository_metadata_is_shown_for_repository_paths(self) -> None:
        metadata = {"owner/repo": [123, "2026-10-06", "2025-01-01"]}
        for suffix in ("", "/blob/main/poc.py", "/tree/main", ".git"):
            url = f"https://github.com/Owner/Repo{suffix}"
            with self.subTest(url=url):
                row = build_pages.link_rows([url], metadata)
                self.assertIn(f'href="{url}"', row)
                self.assertIn("Repo stars 123★ · pushed 2026-10-06", row)

    def test_links_without_repository_metadata_are_still_rendered(self) -> None:
        url = "https://example.com/advisory"
        row = build_pages.link_rows([url], {})
        self.assertIn(f'href="{url}"', row)
        self.assertNotIn("★", row)


class WaybackTests(unittest.TestCase):
    URL = "https://github.com/owner/poc"
    STAMP = "20251021093000"
    SNAPSHOT = f"https://web.archive.org/web/{STAMP}/{URL}"
    FILES_TITLE = "Wayback Machine captures of individual files at pinned commits, not a copy of the whole repository"

    def render(self, entry: dict, archives: dict, repo_meta: dict | None = None, meta: dict | None = None) -> str:
        data = {"cves": [entry], "meta": meta or {}, "epss": {}, "kev": {}, "nuclei": {}, "repo_meta": repo_meta or {},
                "related": {}, "lastmod": {entry["cve"]: "2026-10-21"}, "archives": archives}
        return build_pages.page(entry, data)

    def test_cve_pages_link_confirmed_snapshots_and_label_lookups(self) -> None:
        other = "https://www.exploit-db.com/exploits/50592"
        advisory = "https://vendor.example/advisory"
        entry = {"cve": "CVE-2026-1234", "desc": "Widget flaw", "poc": [self.URL], "edb": [other]}
        markup = self.render(entry, {self.URL: {"url": self.SNAPSHOT, "timestamp": self.STAMP}},
                             meta={entry["cve"]: {"advisories": [[advisory, ["Vendor Advisory"]]]}})
        self.assertIn(
            'Repo metadata unavailable · '
            f'<a class="wayback is-snapshot" href="{self.SNAPSHOT}" target="_blank" rel="nofollow noopener" '
            'title="Wayback Machine page snapshot, captured 2025-10-21 09:30 UTC" '
            'aria-label="snapshot of owner/poc on the Wayback Machine, captured 2025-10-21 09:30 UTC">snapshot</a>', markup)
        self.assertIn(
            f'<span><a class="wayback is-lookup" href="https://web.archive.org/web/*/{other}" target="_blank" '
            'rel="nofollow noopener" title="Search the Wayback Machine for captures; none confirmed" '
            f'aria-label="find archive of {other} on the Wayback Machine">find archive</a></span>', markup)
        # The original stays the PoC link, counts are unchanged and advisories are not PoCs.
        self.assertIn(f'<li><a href="{self.URL}" rel="nofollow noopener" target="_blank">owner/poc</a>', markup)
        self.assertIn("<title>CVE-2026-1234: 2 public PoC exploits | PoC Index</title>", markup)
        advisories = markup.split("<h2>CVE references</h2>", 1)[1].split("</ul>", 1)[0]
        self.assertIn(f'href="{advisory}"', advisories)
        self.assertNotIn("wayback", advisories)
        self.assertNotIn("web.archive.org/save", markup)

    def test_untrusted_snapshot_records_fall_back_to_a_lookup(self) -> None:
        url, stamp, snapshot = self.URL, self.STAMP, self.SNAPSHOT
        for record in (
            {"url": f"http://web.archive.org/web/{stamp}/{url}", "timestamp": stamp},
            {"url": f"https://web.archive.org.example/web/{stamp}/{url}", "timestamp": stamp},
            {"url": f"https://example.com/web.archive.org/web/{stamp}/{url}", "timestamp": stamp},
            {"url": f"https://user@web.archive.org/web/{stamp}/{url}", "timestamp": stamp},
            {"url": f"https://web.archive.org/save/{url}", "timestamp": stamp},
            {"url": f"https://web.archive.org/web/*/{url}", "timestamp": stamp},
            {"url": f"https://web.archive.org/web/{stamp}id_/{url}", "timestamp": stamp},
            {"url": f"https://web.archive.org/web/2025102109300/{url}", "timestamp": "2025102109300"},
            {"url": f"https://web.archive.org/web/20250230093000/{url}", "timestamp": "20250230093000"},
            {"url": f"https://web.archive.org/web/20251021240000/{url}", "timestamp": "20251021240000"},
            {"url": f"https://web.archive.org/web/19951021093000/{url}", "timestamp": "19951021093000"},
            {"url": snapshot, "timestamp": "20251021093001"},
            {"url": snapshot, "timestamp": int(stamp)},
            {"url": snapshot},
            {"url": f"https://web.archive.org/web/{stamp}/javascript:alert(1)", "timestamp": stamp},
            {"url": f"https://web.archive.org/web/{stamp}/https://example.com/poc", "timestamp": stamp},
            {"url": f'{snapshot}"><script>alert(1)</script>', "timestamp": stamp},
            {"url": f"{snapshot} onmouseover=alert(1)", "timestamp": stamp},
            snapshot, None, [snapshot, stamp],
        ):
            with self.subTest(record=record):
                link = build_pages.archive_link(url, "owner/poc", {url: record})
                self.assertIn(f'<a class="wayback is-lookup" href="https://web.archive.org/web/*/{url}"', link)
                self.assertNotIn("is-snapshot", link)
                self.assertNotIn("<script", link)
                self.assertNotIn("onmouseover", link)
        # The Wayback Machine may record the scheme, www. or default port differently.
        canonical = {"url": f"https://web.archive.org/web/{stamp}/http://www.github.com:80/owner/poc", "timestamp": stamp}
        self.assertIn('class="wayback is-snapshot"', build_pages.archive_link(url, "owner/poc", {url: canonical}))

    def test_archive_links_escape_urls_and_labels(self) -> None:
        url = "https://example.com/exploit?id=1&name='x'"
        snapshot = f"https://web.archive.org/web/{self.STAMP}/{url}"
        for archives, href, kind in (({}, f"https://web.archive.org/web/*/{url}", "is-lookup"),
                                     ({url: {"url": snapshot, "timestamp": self.STAMP}}, snapshot, "is-snapshot")):
            with self.subTest(kind=kind):
                markup = build_pages.archive_link(url, '<b>"label"</b>', archives)
                (tag, attrs), = ParsedPage(markup).tags
                self.assertEqual((tag, attrs["class"], attrs["href"]), ("a", f"wayback {kind}", href))
                self.assertIn('<b>"label"</b>', attrs["aria-label"])
                self.assertNotIn("<b>", markup)

    def test_archived_fallbacks_link_their_snapshot_under_the_original_name(self) -> None:
        original = "https://github.com/owner/gone-poc"
        fallback = f"https://web.archive.org/web/20240101120000/{original}"
        live = "https://github.com/owner/live"
        collection = "https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-26642_lts"
        entry = {"cve": "CVE-2026-1234", "desc": "Widget flaw", "poc": [live, fallback],
                 "collections": [f"https://web.archive.org/web/20240101120000/{collection}"]}
        markup = self.render(entry, {original: {"url": fallback, "timestamp": "20240101120000"}},
                             {"owner/gone-poc": [50, "2024-01-01"], "owner/live": [10, "2026-10-01"]})
        stamp = ('<span class="wayback is-archived" title="Wayback Machine page snapshot captured 2024-01-01 12:00 UTC, '
                 'linked in place of the original" aria-hidden="true">ARCHIVED</span>')
        rows = re.findall(r'<li><a href="([^"]*)"([^>]*)>([^<]*)</a>(?:<span>(.*?)</span>)?</li>', markup)
        # Ranked, named and measured as the original, linked to the snapshot.
        self.assertEqual(rows[:3], [
            (fallback, ' rel="nofollow noopener" target="_blank" '
                       'aria-label="owner/gone-poc, archived page snapshot captured 2024-01-01 12:00 UTC"',
             "owner/gone-poc", f"Repo stars 50★ · pushed 2024-01-01 · {stamp}"),
            (live, ' rel="nofollow noopener" target="_blank"', "owner/live",
             "Repo stars 10★ · pushed 2026-10-01 · "
             f'<a class="wayback is-lookup" href="https://web.archive.org/web/*/{live}" target="_blank" rel="nofollow noopener" '
             'title="Search the Wayback Machine for captures; none confirmed" '
             'aria-label="find archive of owner/live on the Wayback Machine">find archive</a>'),
            (f"https://web.archive.org/web/20240101120000/{collection}",
             ' rel="noopener" target="_blank" aria-label="linux/kernelctf/CVE-2024-26642_lts, archived page snapshot '
             'captured 2024-01-01 12:00 UTC"',
             "linux/kernelctf/CVE-2024-26642_lts", f"google/security-research · Repo metadata unavailable · {stamp}"),
        ])
        self.assertNotIn(f'href="{original}"', markup)
        self.assertNotIn(f'href="{collection}"', markup)
        self.assertNotIn("/web/*/https://web.archive.org", markup)
        self.assertIn("3 public PoC exploits", markup)

    def test_cve_pages_disclose_saved_files_beside_snapshots_and_lookups(self) -> None:
        pending = "https://github.com/Owner/Other-PoC"
        report = "https://hackerone.com/reports/123456"
        newest, spaced, report_json = (saved_file(raw_file("poc.py")), saved_file(raw_file("src/exploit%20one.py")),
                                       saved_file(f"{report}.json"))
        entry = {"cve": "CVE-2026-1234", "desc": "Widget flaw", "poc": [self.URL, pending, report]}
        markup = self.render(entry, {
            # One capture per file, the latest, however often the record lists it.
            self.URL: {"url": self.SNAPSHOT, "timestamp": self.STAMP,
                       "files": [spaced, saved_file(raw_file("poc.py"), "20261021120000"), newest, newest]},
            # A page whose own snapshot is still pending.
            pending: {"files": [saved_file(raw_file("run.sh", "owner/other-poc"))]},
            report: {"files": [report_json]},
            # Each file is also listed under its own original, which is no row.
            newest["original"]: {"url": newest["url"], "timestamp": newest["timestamp"]},
        })
        self.assertIn(
            'aria-label="snapshot of owner/poc on the Wayback Machine, captured 2025-10-21 09:30 UTC">snapshot</a></span>'
            f'<details class="sources" style="--files:2" data-sources="{self.URL}"><summary title="{self.FILES_TITLE}" '
            'aria-label="2 files saved from owner/poc">2 files</summary><div class="sources-list">'
            f'<a href="{newest["url"]}" target="_blank" rel="nofollow noopener" '
            'title="Wayback Machine capture of poc.py at commit 0123456, 2026-10-22 16:10 UTC" '
            'aria-label="poc.py at commit 0123456 of owner/poc, Wayback Machine capture 2026-10-22 16:10 UTC">poc.py</a>'
            f'<a href="{spaced["url"]}" target="_blank" rel="nofollow noopener" '
            'title="Wayback Machine capture of src/exploit one.py at commit 0123456, 2026-10-22 16:10 UTC" '
            'aria-label="src/exploit one.py at commit 0123456 of owner/poc, Wayback Machine capture 2026-10-22 16:10 UTC">'
            "src/exploit one.py</a></div></details></li>", markup)
        self.assertNotIn("20261021120000", markup)
        self.assertIn(
            f'find archive</a></span><details class="sources" style="--files:1" data-sources="{pending}">'
            f'<summary title="{self.FILES_TITLE}" aria-label="1 file saved from Owner/Other-PoC">1 file</summary>', markup)
        self.assertIn(
            f'find archive</a></span><details class="sources" style="--files:1" data-sources="{report}">'
            f'<summary title="Wayback Machine capture of the report JSON" aria-label="1 file saved from {report}">1 file</summary>'
            f'<div class="sources-list"><a href="{report_json["url"]}" target="_blank" rel="nofollow noopener" '
            'title="Wayback Machine capture of 123456.json, the report JSON, 2026-10-22 16:10 UTC" '
            f'aria-label="123456.json, the report JSON of {report}, Wayback Machine capture 2026-10-22 16:10 UTC">'
            "123456.json</a></div></details></li>", markup)
        # Saved files are no PoCs of their own, and nothing saved is looked up again.
        self.assertIn("<title>CVE-2026-1234: 3 public PoC exploits | PoC Index</title>", markup)
        self.assertEqual(markup.count('class="wayback '), 3)
        self.assertEqual(markup.count("<details "), 3)
        self.assertNotRegex(markup, r"/web/\*/https://(?:web\.archive\.org|raw\.githubusercontent\.com|hackerone\.com/reports/123456\.json)")

    def test_saved_files_must_be_captures_of_the_linked_pages_own_files(self) -> None:
        good = saved_file(raw_file("poc.py"))
        stamp = good["timestamp"]

        def disclosed(parent: str, files: object) -> str:
            return build_pages.source_files(parent, "label", {parent: {"files": files}})

        # GitHub names repositories without regard to case or a .git suffix.
        for parent in (self.URL, "https://github.com/Owner/POC.git", "https://www.github.com/owner/poc/blob/main/README.md"):
            with self.subTest(parent=parent):
                self.assertIn("1 file</summary>", disclosed(parent, [good]))
        for file in (
            saved_file(raw_file("poc.py", "owner/other")),
            saved_file(raw_file("poc.py", "other/poc")),
            saved_file(raw_file("poc.py", commit="main")),
            saved_file(raw_file("poc.py", commit=COMMIT[1:])),
            saved_file(raw_file("poc.py", commit=COMMIT.upper())),
            # A dot segment would open another repository's file.
            saved_file(raw_file(f"../../other/poc/{COMMIT}/poc.py")),
            saved_file(raw_file("%2e%2E/poc.py")),
            saved_file(raw_file("./poc.py")),
            saved_file(raw_file("src//poc.py")),
            saved_file(raw_file("poc.py?token=1")),
            saved_file(raw_file("poc.py#L1")),
            saved_file(f"http://raw.githubusercontent.com/owner/poc/{COMMIT}/poc.py"),
            saved_file(f"https://raw.githubusercontent.com.example/owner/poc/{COMMIT}/poc.py"),
            saved_file(f"https://gist.githubusercontent.com/owner/poc/raw/{COMMIT}/poc.py"),
            saved_file(f"https://github.com/owner/poc/blob/{COMMIT}/poc.py"),
            saved_file(f"https://example.com/owner/poc/{COMMIT}/poc.py"),
            saved_file("https://hackerone.com/reports/123456.json"),
            # An archive link is never saved again.
            saved_file(good["url"]),
            {**good, "url": saved_file(raw_file("other.py"))["url"]},
            {**good, "url": f"https://web.archive.org/web/{stamp}/https://example.com/owner/poc/{COMMIT}/poc.py"},
            {**good, "timestamp": "20261022161014"},
            {**good, "timestamp": int(stamp)},
            {**good, "url": f"https://web.archive.org/web/{stamp}id_/{good['original']}"},
            {**good, "url": f"https://web.archive.org/web/*/{good['original']}"},
            {**good, "url": f"http://web.archive.org/web/{stamp}/{good['original']}"},
            {**good, "url": f"https://web.archive.org/web/20250230093000/{good['original']}", "timestamp": "20250230093000"},
            {"url": good["url"], "timestamp": stamp},
            good["url"], None, [good],
        ):
            with self.subTest(file=file):
                self.assertEqual(disclosed(self.URL, [file]), "")
        for files in (good, "files", None, {}):
            with self.subTest(files=files):
                self.assertEqual(disclosed(self.URL, files), "")
        # Advisories, gists, other hosts and files themselves hold no repository files.
        for parent in ("https://github.com/owner/poc/security/advisories/GHSA-1234-5678-9abc",
                       "https://gist.github.com/owner/0123", "https://example.com/owner/poc", good["original"]):
            with self.subTest(parent=parent):
                self.assertEqual(disclosed(parent, [good]), "")
        # A HackerOne report holds its own report JSON and nothing else.
        report_json = saved_file("https://hackerone.com/reports/123456.json")
        for parent in ("https://hackerone.com/reports/123456", "https://www.hackerone.com/reports/123456/",
                       "https://hackerone.com/reports/123456?subject=x"):
            with self.subTest(parent=parent):
                self.assertIn("1 file</summary>", disclosed(parent, [report_json]))
        for parent, file in (
            ("https://hackerone.com/reports/123456", saved_file("https://hackerone.com/reports/654321.json")),
            ("https://hackerone.com/reports/123456", saved_file("https://hackerone.example/reports/123456.json")),
            ("https://hackerone.com/reports/123456", saved_file("https://hackerone.com/reports/123456")),
            ("https://hackerone.com/reports/123456", saved_file("https://hackerone.com/reports/123456.json?x=1")),
            ("https://hackerone.com/reports/123456", good),
            ("https://hackerone.com/reports/123456.json", report_json),
            ("https://hackerone.com/bugs?report_id=123456", report_json),
            ("https://example.com/reports/123456", report_json),
        ):
            with self.subTest(parent=parent, file=file):
                self.assertEqual(disclosed(parent, [file]), "")

    def test_saved_file_names_links_and_labels_are_escaped(self) -> None:
        odd = saved_file(raw_file("x%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E/it's.py"))
        malformed = saved_file(raw_file("100%.py"))
        markup =build_pages.source_files(self.URL, '<b>"label"</b>', {self.URL: {"files": [odd, malformed]}})
        page = ParsedPage(markup)
        self.assertEqual([tag for tag, _ in page.tags], ["details", "summary", "div", "a", "a"])
        self.assertEqual(page.tags[1][1]["aria-label"], '2 files saved from <b>"label"</b>')
        links = [attrs for tag, attrs in page.tags if tag == "a"]
        self.assertEqual([attrs["href"] for attrs in links], [malformed["url"], odd["url"]])
        self.assertEqual(links[1]["aria-label"], 'x"><img src=x onerror=alert(1)>/it\'s.py at commit 0123456 of '
                                                 '<b>"label"</b>, Wayback Machine capture 2026-10-22 16:10 UTC')
        # A malformed escape is shown as written.
        self.assertEqual(page.text[1:], ["100%.py", 'x"><img src=x onerror=alert(1)>/it\'s.py'])
        self.assertNotIn("<img", markup)
        self.assertNotIn("<b>", markup)

    def test_archived_fallbacks_disclose_their_original_saved_files_once(self) -> None:
        original = "https://github.com/owner/gone-poc"
        fallback = f"https://web.archive.org/web/20240101120000/{original}"
        exploit = saved_file(raw_file("exploit.c", "owner/gone-poc"))
        listed, helper = saved_file(raw_file("poc.py")), saved_file(raw_file("helper.py"))
        entry = {"cve": "CVE-2026-1234", "desc": "Widget flaw", "poc": [fallback, self.URL, listed["original"]]}
        archives = {original: {"url": fallback, "timestamp": "20240101120000", "files": [exploit]},
                    self.URL: {"files": [listed, helper]},
                    listed["original"]: {"url": listed["url"], "timestamp": listed["timestamp"]}}
        markup = self.render(entry, archives)
        self.assertIn('linked in place of the original" aria-hidden="true">ARCHIVED</span></span>'
                      f'<details class="sources" style="--files:1" data-sources="{fallback}"><summary', markup)
        self.assertIn(f'<a href="{exploit["url"]}" target="_blank" rel="nofollow noopener" '
                      'title="Wayback Machine capture of exploit.c at commit 0123456, 2026-10-22 16:10 UTC" '
                      'aria-label="exploit.c at commit 0123456 of owner/gone-poc, Wayback Machine capture '
                      '2026-10-22 16:10 UTC">exploit.c</a>', markup)
        # The lost original is never linked, and no capture is looked up again.
        self.assertNotIn(f'href="{original}"', markup)
        self.assertNotRegex(markup, r"/web/\*/https://(?:web\.archive\.org|raw\.githubusercontent\.com)")
        # poc.py has a row and a snapshot of its own, so its page discloses only helper.py.
        self.assertIn('aria-label="1 file saved from owner/poc">1 file</summary>', markup)
        self.assertIn(f'<a href="{helper["url"]}"', markup)
        self.assertEqual(markup.count(f'href="{listed["url"]}"'), 1)
        self.assertIn("3 public PoC exploits", markup)
        # The page's fingerprint follows the files it shows.
        data = {"today": "2026-10-21", "meta": {}, "nuclei": {}, "kev": {}, "repo_meta": {}}
        without = {**archives, original: {"url": fallback, "timestamp": "20240101120000"}}
        self.assertNotEqual(build_pages.content_state(entry, {**data, "archives": archives}, {})[0],
                            build_pages.content_state(entry, {**data, "archives": without}, {})[0])

    def test_a_missing_archive_index_is_empty_and_a_malformed_one_stops_the_build(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.object(build_pages, "DOCS", directory):
            self.assertEqual(build_pages.load_optional("archives.json"), {})
            index = Path(directory, "archives.json")
            records = {self.URL: {"url": self.SNAPSHOT, "timestamp": self.STAMP}}
            index.write_text(json.dumps(records), encoding="utf-8")
            self.assertEqual(build_pages.load_optional("archives.json"), records)
            index.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "archives.json"):
                build_pages.load_optional("archives.json")


if __name__ == "__main__":
    unittest.main()
