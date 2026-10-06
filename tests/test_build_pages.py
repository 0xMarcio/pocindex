from __future__ import annotations

import json
import sys
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import build_pages


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
            {"total_cves": total, "with_pocs": 2, "generated": "2030-01-02T12:00:00Z", "items": [
                {"cve": "CVE-2030-1234", "stars": 5, "pushed": "2030-01-02T09:00:00Z",
                 "name": "Example PoC", "url": "https://github.com/owner/poc", "desc": "A widget exploit"},
                {"cve": "CVE-2030-9999", "stars": 1, "pushed": "2030-01-01T00:00:00Z",
                 "name": "New PoC", "url": "https://github.com/owner/new", "desc": "</script><script>alert(1)</script>"},
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


class RepositoryMetadataTests(unittest.TestCase):
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
