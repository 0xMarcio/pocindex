from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import build_site
import releases


class FrontpageReleaseTests(unittest.TestCase):
    def test_landed_uses_release_order_and_keeps_zero_star_and_collection_artifacts(self):
        cve = 'CVE-2024-26642'
        repo = 'https://github.com/owner/new-poc'
        path = 'https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-26642_cos'
        older = 'https://github.com/owner/old-poc'
        unknown = 'https://github.com/owner/imported-poc'
        missing = 'https://github.com/owner/removed-poc'
        entries = [{'cve': cve, 'desc': 'nf_tables', 'poc': [repo, older, unknown], 'collections': [path]}]
        ledger = {}
        now = '2026-10-06T22:00:00Z'
        for url, date in ((repo, '2026-10-06T20:00:00Z'), (path, '2026-10-05T00:00:00Z'),
                          (older, '2024-01-01T00:00:00Z'), (missing, '2026-10-06T21:00:00Z')):
            releases.record(ledger, cve, url, {'commit': date, 'commit_verified': True},
                            observed_at=now, import_mode=True)
        releases.record(ledger, cve, unknown, observed_at=now, import_mode=True)
        rows = build_site.build_landed(entries, {'owner/new-poc': [0, '2026-10-06'],
                                               'owner/old-poc': [999, '2026-10-06'],
                                               'google/security-research': [5000, '2026-10-06']},
                                      {cve: []}, ledger, now=now)
        self.assertEqual([row['url'] for row in rows], [repo, path])
        self.assertEqual([row['stars'] for row in rows], [0, None])
        self.assertEqual([row['released'] for row in rows], ['2026-10-06T20:00:00Z', '2026-10-05T00:00:00Z'])
        self.assertTrue(all(row['page'] == '/' + cve and row['kev'] for row in rows))

    def test_removed_rejected_or_copied_artifacts_cannot_leak_from_the_ledger(self):
        cve = 'CVE-2024-1234'
        urls = ['https://github.com/owner/' + name for name in ('kept', 'copy', 'gone', 'bulk')]
        ledger = {}
        for url in urls:
            releases.record(ledger, cve, url, {'created': '2026-10-06T01:00:00Z'},
                            observed_at='2026-10-06T22:00:00Z')
        ledger[releases.key(cve, urls[1])]['copy'] = releases.key(cve, urls[0])
        ledger[releases.key(cve, urls[2])]['gone'] = '2026-10-06T21:00:00Z'
        ledger[releases.key(cve, urls[3])]['bulk'] = True
        entries = [{'cve': cve, 'poc': urls}]
        rows = build_site.build_landed(entries, {}, {}, ledger, now='2026-10-06T22:00:00Z')
        self.assertEqual([row['url'] for row in rows], urls[:1])
        self.assertEqual(build_site.build_landed([], {}, {}, ledger, now='2026-10-06T22:00:00Z'), [])
