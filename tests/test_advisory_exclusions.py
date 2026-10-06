from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import build_pages
import build_site


class AdvisoryExclusionTests(unittest.TestCase):
    def test_explicit_wrong_cve_pair_is_removed_from_metadata_and_detail_only(self):
        wrong, correct = 'CVE-2024-23749', 'CVE-2024-25004'
        url = 'http://seclists.org/fulldisclosure/2024/Feb/14'
        ordinary = 'https://vendor.example/security/advisory'
        rows = [[url, ['Third Party Advisory', 'Exploit']], [ordinary, ['Vendor Advisory']]]
        raw = {cve: {'advisories': rows} for cve in (wrong, correct)}
        entries = [{'cve': cve, 'poc': []} for cve in (wrong, correct)]
        with patch.object(build_site, 'load_metadata', return_value=raw):
            metadata = build_site.build_metadata(entries)
        self.assertEqual(metadata[wrong]['advisories'], [rows[1]])
        self.assertEqual(metadata[correct]['advisories'], rows)
        self.assertFalse(build_site.reference_is_verified_poc(wrong, ordinary, raw, set()))
        self.assertTrue(build_site.reference_is_verified_poc(correct, url, raw, {(correct, url)}))
        self.assertFalse(build_site.reference_is_verified_poc(wrong, url, raw, {(wrong, url)}))
        data = {'cves': entries, 'meta': metadata, 'epss': {}, 'kev': {}, 'nuclei': {},
                'repo_meta': {}, 'related': {}, 'lastmod': {cve: '2026-10-07' for cve in (wrong, correct)}}
        wrong_page, correct_page = [build_pages.page(entry, data) for entry in entries]
        self.assertNotIn(f'href="{url}"', wrong_page)
        self.assertIn(f'href="{url}"', correct_page)
        for markup in (wrong_page, correct_page):
            self.assertIn(f'href="{ordinary}"', markup)


if __name__ == '__main__':
    unittest.main()
