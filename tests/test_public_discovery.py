from __future__ import annotations

import importlib.util
import io
import json
import sys
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import source_artifacts
import sync_pocingithub
import update_cves

SPEC = importlib.util.spec_from_file_location('public_trending', ROOT / '.github/getTrending.py')
trending = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trending)
CVE = 'CVE-2024-1234'
NAME = 'researcher/' + CVE


def repo(**fields):
    return {'nameWithOwner': NAME, 'url': 'https://github.com/' + NAME, 'description': 'Proof of concept',
            'isFork': False, 'defaultBranchRef': {'target': {'oid': 'a' * 40}},
            'root': {'entries': [{'name': 'exploit.py', 'type': 'blob'}]},
            'readmeMd': {'text': 'Proof of concept for ' + CVE}, **fields}


class PublicDiscoveryTests(unittest.TestCase):
    def test_explicit_nonpublic_repositories_never_qualify(self):
        for fields in ({'isPrivate': True}, {'private': True}, {'visibility': 'PRIVATE'}, {'visibility': 'INTERNAL'}):
            with self.subTest(fields=fields):
                self.assertEqual(update_cves.qualifying_repo_cves(repo(**fields), 2024, []), set())
        self.assertEqual(update_cves.qualifying_repo_cves(repo(isPrivate=False, visibility='PUBLIC'), 2024, []), {CVE})

    def test_reviewed_private_payload_is_not_inspected_or_published(self):
        row = source_artifacts.load_reviews()[0]
        artifact = source_artifacts.ArtifactEvidence(row['cve'], row['repository'], row['path'],
                                                    row['revision'], row['sha256'], row['id'])
        candidate = repo(nameWithOwner=row['repository'], isPrivate=True, _source_artifacts=(artifact,))
        with patch.object(source_artifacts, 'inspect_repository') as inspect:
            update_cves.attach_source_artifacts(candidate, {}, [])
        inspect.assert_not_called()
        self.assertEqual(update_cves.qualifying_repo_cves(candidate, int(row['cve'].split('-')[1]), []), set())

    def test_rest_search_is_public_only_and_discards_explicit_nonpublic_rows(self):
        rows = [{'full_name': 'public/' + CVE, 'private': False, 'visibility': 'public'},
                {'full_name': 'private/' + CVE, 'private': True},
                {'full_name': 'internal/' + CVE, 'visibility': 'internal'}]
        urls = []
        def response(req, **kwargs):
            urls.append(req.full_url)
            return io.BytesIO(json.dumps({'total_count': 3, 'items': rows}).encode())
        with patch.object(trending, 'github_token', return_value='test'), \
                patch.object(trending.request, 'urlopen', side_effect=response):
            _, found = trending.search(CVE)
        self.assertEqual(found, [rows[0]])
        self.assertTrue(all('is:public' in parse_qs(urlsplit(url).query)['q'][0].split() for url in urls))

    def test_graphql_searches_request_public_visibility(self):
        query = update_cves.build_search_query(CVE, 'pushed', date(2026, 10, 1), date(2026, 10, 7))
        self.assertIn('is:public', query.split())
        client = Mock()
        client.search_page.return_value = {'repositoryCount': 0, 'nodes': [], 'pageInfo': {'hasNextPage': False}}
        list(update_cves.search_without_range(client, CVE))
        self.assertIn('is:public', client.search_page.call_args.args[0].split())
        self.assertIn('isPrivate', update_cves.GITHUB_SEARCH_QUERY)
        self.assertIn('visibility', update_cves.GITHUB_SEARCH_QUERY)

    def test_direct_description_and_readme_refresh_discard_nonpublic_nodes(self):
        for visibility in ('PRIVATE', 'INTERNAL'):
            candidate = repo(visibility=visibility)
            for module, alias, read in (
                (sync_pocingithub, 'r0', lambda client: sync_pocingithub.describe(client, [NAME])),
                (update_cves, 'repo0', lambda client: client.fetch_readmes([NAME])),
            ):
                payload = {'data': {alias: candidate, 'rateLimit': {'remaining': 100}}}
                with self.subTest(visibility=visibility, module=module.__name__), \
                        patch.object(module, 'http_json', return_value=payload) as fetch:
                    result = read(update_cves.GitHubClient('test'))
                    self.assertFalse(result[0] if isinstance(result, tuple) else result)
                    query = fetch.call_args.kwargs['data']['query']
                    self.assertIn('isPrivate', query)
                    self.assertIn('visibility', query)

    def test_pending_replay_does_not_publish_newly_private_reviewed_repo(self):
        row = source_artifacts.load_reviews()[0]
        name, cve = row['repository'], row['cve']
        payload = {'data': {'repo0': repo(nameWithOwner=name, isPrivate=True), 'rateLimit': {'remaining': 100}}}
        with patch.object(source_artifacts, 'pending_reviewed_names', return_value=[name.lower()]), \
                patch.object(update_cves, 'search_range', return_value=[]), \
                patch.object(update_cves, 'http_json', return_value=payload) as fetch, \
                patch.object(update_cves.GitHubClient, 'fetch_readmes') as readmes:
            found = update_cves.discover_github_pocs('test', years=[int(cve.split('-')[1])],
                                                    lookback_days=3, backfill=False, cve_filter=set(), artifact_cache_write=False)
        self.assertEqual(found, {})
        readmes.assert_not_called()
        self.assertIn('isPrivate', fetch.call_args.kwargs['data']['query'])
        self.assertIn('visibility', fetch.call_args.kwargs['data']['query'])

    def test_trending_refresh_rejects_private_or_internal_repository(self):
        row = {'full_name': NAME, 'name': CVE, 'html_url': 'https://github.com/' + NAME}
        for fields in ({'isPrivate': True}, {'visibility': 'INTERNAL'}):
            with self.subTest(fields=fields), patch.object(trending, 'graphql', return_value={'r0': repo(**fields)}) as fetch:
                accepted, paths = trending.qualifying_repositories([dict(row)], 'test')
            self.assertEqual((accepted, paths), ([], {}))
            self.assertIn('isPrivate', fetch.call_args.args[0])
            self.assertIn('visibility', fetch.call_args.args[0])


if __name__ == '__main__':
    unittest.main()
