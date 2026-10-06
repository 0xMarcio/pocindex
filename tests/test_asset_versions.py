import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import build_pages


class AssetVersionTests(unittest.TestCase):
    def tearDown(self):
        build_pages.asset_url.cache_clear()

    def test_asset_urls_follow_bytes_without_changing_page_dates(self):
        entry = {"cve": "CVE-2024-1234", "desc": "Widget flaw", "modified": "2024-01-01",
                 "poc": ["https://example.org/poc"]}
        payloads = {"CVE_list.json": [entry], "cve_metadata.json": {}, "epss.json": {},
                    "kev.json": {}, "nuclei.json": {}, "repo_meta.json": {},
                    "trending_poc.json": {"with_pocs": 1, "total_cves": 1,
                                          "generated": "2026-10-07T00:00:00Z", "landed": []}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, body in (("style.css", b"body { color: black; }"), ("logic.js", b"const version = 1;")):
                (root / name).write_bytes(body)
            with patch.object(build_pages, "DOCS", directory), \
                    patch.object(build_pages, "load", side_effect=payloads.__getitem__), \
                    patch.object(build_pages, "previous_page_state", return_value={}) as previous:
                build_pages.main()
                state = (root / build_pages.PAGE_STATE).read_bytes()
                dates = (root / build_pages.LASTMOD).read_bytes()
                first = (root / "index.html").read_text()
                css = "/style.css?v=" + hashlib.sha256((root / "style.css").read_bytes()).hexdigest()[:16]
                js = "/logic.js?v=" + hashlib.sha256((root / "logic.js").read_bytes()).hexdigest()[:16]
                for name in ("index.html", "404.html", "CVE-2024-1234.html", "2024.html", "CVE-2024-1xxx.html"):
                    self.assertIn(f'href="{css}"', (root / name).read_text(), name)
                self.assertIn(f'src="{js}"', first)
                self.assertIn(f'href="{build_pages.SITE}/CVE-2024-1234"', (root / "CVE-2024-1234.html").read_text())
                previous.return_value = json.loads(state)["pages"]
                for name in ("style.css", "logic.js"):
                    with (root / name).open("ab") as handle:
                        handle.write(b"\n/* new bundle */")
                build_pages.main()
                second = (root / "index.html").read_text()
                self.assertNotIn(css, second)
                self.assertNotIn(js, second)
                self.assertEqual((root / build_pages.PAGE_STATE).read_bytes(), state)
                self.assertEqual((root / build_pages.LASTMOD).read_bytes(), dates)


if __name__ == "__main__":
    unittest.main()
