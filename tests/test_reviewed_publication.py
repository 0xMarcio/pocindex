from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import build_site
import source_artifacts

SPEC = importlib.util.spec_from_file_location('reviewed_trending', ROOT / '.github/getTrending.py')
trending = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trending)


class ReviewedPublicationTests(unittest.TestCase):
    def test_reviewed_pinned_artifact_wins_over_existing_repository_root(self):
        row = source_artifacts.load_reviews()[0]
        artifact = source_artifacts.ArtifactEvidence(row['cve'], row['repository'], row['path'],
                                                    row['revision'], row['sha256'], row['id'])
        root = f"https://github.com/{row['repository']}"
        for links in ([root, artifact.url], [artifact.url, root]):
            self.assertEqual(build_site.dedupe_source_links(links, row['cve']), [artifact.url])
        unrelated = root + '/blob/main/unreviewed.py'
        self.assertEqual(build_site.dedupe_source_links([root, unrelated], row['cve']), [root])

    def test_multiple_reviewed_paths_use_the_same_publication_choice(self):
        cve, name = 'CVE-2024-1234', 'researcher/CVE-2024-1234-lab'
        evidence = [source_artifacts.ArtifactEvidence(cve, name, path, 'a' * 40, 'b' * 64, 'test')
                    for path in ['expl/longer.py', 'expl/a.py']]
        row = {'name': name.split('/')[1], 'full_name': name, 'html_url': f'https://github.com/{name}'}
        content = {'root': {'entries': [{'name': 'expl', 'type': 'tree'}]},
                   'readmeMd': {'text': f'PoC for {cve}'}, 'defaultBranchRef': {'target': {'oid': 'a' * 40}}}
        def attach(repo, *args, **kwargs):
            repo['_source_artifacts'] = tuple(evidence)
        with patch.object(trending, 'graphql', return_value={'r0': content}), \
                patch.object(trending, 'load_blacklist', return_value=[]), \
                patch.object(trending, 'attach_source_artifacts', side_effect=attach), \
                patch.object(build_site, 'reviewed_artifact_keys', return_value={cve: {build_site.link_key(a.url) for a in evidence}}):
            accepted, paths = trending.qualifying_repositories([row], '')
            published = build_site.dedupe_source_links([row['html_url'], *[a.url for a in evidence]], cve)
        self.assertEqual(len(accepted), 1)
        self.assertEqual(accepted[0]['_artifact_url'], published[0])
        self.assertEqual(published, [evidence[1].url])
        self.assertEqual(set(paths[name]), {a.path for a in evidence})

    def test_landed_merge_rejects_a_link_that_publication_dedupes_away(self):
        cve = 'CVE-2024-1234'
        root = f'https://github.com/unknown/{cve}'
        payload = root + '/blob/main/exploit.py'
        candidate = {'cve': cve, 'html_url': root, '_artifact_url': payload, '_released': '2026-10-07T00:00:00Z'}
        with tempfile.TemporaryDirectory() as temp:
            metadata = Path(temp) / 'metadata.json'
            metadata.write_text('{}')
            with patch.object(build_site, 'REPO_META', metadata), \
                    patch.object(build_site, 'build_cve_list', return_value=([{'cve': cve, 'poc': [root]}], 1)), \
                    patch.object(trending, 'known_exploited', return_value=set()):
                self.assertEqual(trending.ledger_landed({}, [candidate]), [])

    def test_landed_merge_keeps_reviewed_payload_that_will_replace_root(self):
        row = source_artifacts.load_reviews()[0]
        artifact = source_artifacts.ArtifactEvidence(row['cve'], row['repository'], row['path'],
                                                    row['revision'], row['sha256'], row['id'])
        root = f"https://github.com/{row['repository']}"
        candidate = {'cve': row['cve'], 'html_url': root, '_artifact_url': artifact.url,
                     '_released': '2026-10-07T00:00:00Z'}
        with tempfile.TemporaryDirectory() as temp:
            metadata = Path(temp) / 'metadata.json'
            metadata.write_text('{}')
            with patch.object(build_site, 'REPO_META', metadata), \
                    patch.object(build_site, 'build_cve_list', return_value=([{'cve': row['cve'], 'poc': [root]}], 1)), \
                    patch.object(trending, 'known_exploited', return_value=set()):
                self.assertEqual(trending.ledger_landed({}, [candidate]), [candidate])

    def test_landed_switch_replaces_dated_root_without_removing_other_sources_or_cves(self):
        row = source_artifacts.load_reviews()[0]
        artifact = source_artifacts.ArtifactEvidence(row['cve'], row['repository'], row['path'],
                                                    row['revision'], row['sha256'], row['id'])
        root = f"https://github.com/{row['repository']}"
        other_cve = 'CVE-2024-1234'
        other_source = 'https://github.com/another/poc'
        released = trending.releases.utcnow()
        ledger = trending.releases.Ledger()
        entries = [{'cve': row['cve'], 'poc': [root, other_source]}, {'cve': other_cve, 'poc': [root]}]
        for entry in entries:
            for url in entry['poc']:
                trending.releases.record(ledger, entry['cve'], url,
                                         {'commit': released, 'commit_verified': True,
                                          'history_version': trending.releases.HISTORY_VERSION})
        candidate = {'cve': row['cve'], 'html_url': root, '_artifact_url': artifact.url, '_released': released}
        with tempfile.TemporaryDirectory() as temp:
            metadata = Path(temp) / 'metadata.json'
            metadata.write_text('{}')
            with patch.object(build_site, 'REPO_META', metadata), \
                    patch.object(build_site, 'build_cve_list', return_value=(entries, len(entries))), \
                    patch.object(trending, 'known_exploited', return_value=set()):
                merged = trending.ledger_landed(ledger, [candidate])
        actual = {(trending.cve_of(item), item.get('_artifact_url') or item['html_url']) for item in merged}
        self.assertEqual(actual, {(row['cve'], artifact.url), (row['cve'], other_source), (other_cve, root)})
        self.assertIn(candidate, merged)

    def test_landed_merge_preserves_dated_curated_sibling_variants(self):
        cve = 'CVE-2024-1234'
        urls = [f'https://github.com/google/security-research/blob/master/pocs/{cve}/variant-{n}.c'
                for n in range(3)]
        released = trending.releases.utcnow()
        ledger = trending.releases.Ledger()
        for url in urls:
            trending.releases.record(ledger, cve, url, {'commit': released, 'commit_verified': True,
                                                       'history_version': trending.releases.HISTORY_VERSION})
        candidate = {'cve': cve, 'html_url': 'https://github.com/google/security-research',
                     '_artifact_url': urls[0], '_released': released}
        entries = [{'cve': cve, 'poc': [], 'collections': urls}]
        with tempfile.TemporaryDirectory() as temp:
            metadata = Path(temp) / 'metadata.json'
            metadata.write_text('{}')
            with patch.object(build_site, 'REPO_META', metadata), \
                    patch.object(build_site, 'build_cve_list', return_value=(entries, 1)), \
                    patch.object(trending, 'known_exploited', return_value=set()):
                merged = trending.ledger_landed(ledger, [candidate])
        self.assertEqual({item.get('_artifact_url') or item['html_url'] for item in merged}, set(urls))
        self.assertIn(candidate, merged)

    def test_curated_variants_keep_independent_paths(self):
        urls = [f'https://github.com/google/security-research/blob/master/pocs/CVE-2024-1234/variant-{n}.c'
                for n in range(116)]
        self.assertEqual(build_site.dedupe_source_links(urls, 'CVE-2024-1234', preserve_paths=True), urls)


if __name__ == '__main__':
    unittest.main()
