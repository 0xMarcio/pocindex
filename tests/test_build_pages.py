from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import build_pages


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
