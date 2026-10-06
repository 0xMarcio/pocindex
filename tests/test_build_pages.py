from __future__ import annotations

import copy
import io
import json
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

    def test_ibm_assessment_names_its_scorer(self) -> None:
        row = ["3.0", 7.1, "HIGH", "", "psirt@us.ibm.com", "Secondary"]
        self.assertEqual(build_pages.assessor(row), "IBM")


class RepositoryMetadataTests(unittest.TestCase):
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
                self.assertIn("123★ · 2026-10-06", row)

    def test_links_without_repository_metadata_are_still_rendered(self) -> None:
        url = "https://example.com/advisory"
        row = build_pages.link_rows([url], {})
        self.assertIn(f'href="{url}"', row)
        self.assertNotIn("★", row)


if __name__ == "__main__":
    unittest.main()
