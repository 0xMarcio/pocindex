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

    def test_curated_variants_keep_independent_paths(self):
        urls = [f'https://github.com/google/security-research/blob/master/pocs/CVE-2024-1234/variant-{n}.c'
                for n in range(116)]
        self.assertEqual(build_site.dedupe_source_links(urls, 'CVE-2024-1234', preserve_paths=True), urls)


if __name__ == '__main__':
    unittest.main()
