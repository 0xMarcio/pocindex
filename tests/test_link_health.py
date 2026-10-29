from __future__ import annotations

from contextlib import ExitStack
import json
import sys
import tempfile
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import audit_poc_links as audit
import build_site
import link_health as health
import sync_repo_metadata as metadata
import update_cves


class LinkHealthTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.index = self.root / 'index'
        self.index.mkdir()
        self.cves = self.root / 'cves'
        (self.cves / '2026').mkdir(parents=True)
        self.state = self.index / 'link_health.json'
        self.patch = patch.object(health, 'STATE', self.state)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        health.load.cache_clear()
        self.addCleanup(health.load.cache_clear)

    def test_repository_failures_cover_aliases_children_and_raw_files(self):
        health.record(missing={'owner/gone'})
        for url in ('https://github.com/Owner/Gone', 'https://www.github.com/Owner/Gone.git/',
                    'https://github.com/Owner/Gone/blob/main/poc.py',
                    'https://raw.githubusercontent.com/Owner/Gone/main/poc.py',
                    'https://github.com/Owner/Gone/security/advisories/GHSA-abcd'):
            self.assertTrue(health.unavailable(url), url)
        self.assertFalse(health.unavailable('https://github.com/owner/working'))
        self.assertFalse(health.unavailable('https://github.com/owner/gone-v2'))
        self.assertFalse(health.unavailable('https://notgithub.com/owner/gone'))

    def test_artifact_failure_never_hides_siblings_or_discards_case_and_query(self):
        url = 'https://github.com/Owner/Repo/blob/main/PoC.py?raw=1'
        health.record(dead_urls={url})
        self.assertTrue(health.unavailable(url + '#L10'))
        self.assertFalse(health.unavailable(url.replace('PoC.py', 'poc.py')))
        self.assertFalse(health.unavailable(url.replace('?raw=1', '?raw=2')))
        self.assertFalse(health.unavailable('https://github.com/Owner/Repo'))
        health.record(missing={'owner/repo'})
        health.record(healthy={'owner/repo'})
        self.assertTrue(health.unavailable(url))
        health.record(live_urls={url})
        self.assertFalse(health.unavailable(url))

    def test_repository_keys_are_normalized_without_recording_empty_identities(self):
        health.record(missing={'Owner/Gone.git', '', 'topics/security', 'owner/.git', 'owner//poc'})
        self.assertEqual(set(health.load()['repositories']), {'owner/gone'})
        for url in ('https://example.com/poc', 'https://gist.github.com/owner/123',
                    'https://github.com/topics/security'):
            self.assertFalse(health.unavailable(url), url)
        health.record(healthy={'OWNER/GONE.git'})
        self.assertEqual(health.load()['repositories'], {})

    def test_invalid_repository_state_is_rejected_before_survey_or_publication(self):
        for key in ('', 'owner', 'topics/security', 'owner/.git'):
            with self.subTest(key=key):
                self.state.write_text(json.dumps({'repositories': {key: '2026-10-22'}, 'urls': {}}))
                health.load.cache_clear()
                with self.assertRaises(ValueError):
                    health.load()

    def test_transient_http_and_network_errors_are_not_evidence_of_deletion(self):
        url = 'https://example.com/poc'
        failures = [HTTPError(url, code, 'Unavailable', {}, None)
                    for code in (401, 403, 405, 416, 429, 500, 502, 503)]
        failures += [URLError('temporary DNS failure'), TimeoutError('timeout')]
        for failure in failures:
            with self.subTest(failure=str(failure)), patch.object(health.request, 'urlopen', side_effect=failure):
                self.assertEqual(health.survey_urls([url]), (set(), set()))

    def test_api_not_found_without_public_404_does_not_prune(self):
        payload = {'data': {'r0': None}, 'errors': [{'type': 'NOT_FOUND', 'path': ['r0']}]}
        for public_result in (True, None):
            with patch.object(audit, 'http_json', return_value=payload), \
                    patch.object(health, 'check_url', return_value=public_result):
                self.assertEqual(audit.survey(update_cves.GitHubClient('test'), ['owner/poc']), (set(), {}, set()))

    def test_private_repository_visible_to_token_cannot_clear_suppression(self):
        health.record(missing={'owner/private'})
        payload = {'data': {'r0': {'isPrivate': True, 'visibility': 'PRIVATE',
                                  'stargazerCount': 100, 'pushedAt': '2026-10-22T00:00:00Z'}}}
        with patch.object(audit, 'http_json', return_value=payload), \
                patch.object(health, 'check_url', return_value=False):
            missing, readings, unavailable = audit.survey(update_cves.GitHubClient('test'), ['owner/private'])
        self.assertEqual((missing, readings, unavailable), ({'owner/private'}, {}, {'owner/private'}))
        health.record(missing=unavailable, healthy=readings)
        self.assertTrue(health.unavailable('https://github.com/owner/private'))

    def test_invalid_urls_are_inconclusive_without_a_network_request(self):
        with patch.object(health.request, 'urlopen') as fetch:
            for url in ('https://[broken', 'file:///tmp/poc', '', 'https://'):
                self.assertIsNone(health.check_url(url))
            fetch.assert_not_called()

    def test_redirect_response_without_http_status_is_inconclusive(self):
        response = MagicMock()
        response.__enter__.return_value = response
        response.status = None
        with patch.object(health.request, 'urlopen', return_value=response):
            self.assertEqual(health.survey_urls(['https://example.com/ftp-redirect']), (set(), set()))

    def test_redirects_follow_the_destination_without_losing_the_original_identity(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/renamed':
                    self.send_response(302)
                    self.send_header('Location', '/live')
                else:
                    self.send_response(200 if self.path == '/live' else 404)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f'http://127.0.0.1:{server.server_port}'
            self.assertEqual(health.survey_urls([base+'/renamed', base+'/gone']),
                             ({base+'/gone'}, {base+'/renamed'}))
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_publication_hides_dead_links_in_all_fields_but_preserves_cve_enrichment(self):
        dead = 'https://github.com/owner/gone'
        live = 'https://github.com/owner/live'
        health.record(missing={'owner/gone'})
        text = '### Description\nExample vulnerability\n\n### POC\n'
        for header in audit.SECTION_EMPTY:
            text += f'\n{header}\n- {dead}\n- {live}-{header.split()[-1]}/blob/main/poc.py\n'
        cve = 'CVE-2026-1234'
        (self.cves / f'2026/{cve}.md').write_text(text)
        stored = {cve: {'cvss': {'v3': [9.8, 'CRITICAL']}, 'advisories': [
            [dead, ['Exploit']], ['https://vendor.example/advisory', ['Vendor Advisory']]]}}
        with patch("archive_pocs.load_records", return_value={}), patch.multiple(build_site, CVES=self.cves, load_dates=lambda: {},
                            load_metadata=lambda: stored, load_verified_references=lambda: set()):
            entries, total = build_site.build_cve_list(set())
            enriched = build_site.build_metadata(entries)
        self.assertEqual((len(entries), total), (1, 1))
        for field in ['poc', *(f for _, f in build_site.CURATED)]:
            self.assertTrue(entries[0][field])
            self.assertTrue(all(url.startswith(live) for url in entries[0][field]))
        self.assertEqual(enriched[cve]['cvss'], stored[cve]['cvss'])
        self.assertEqual(enriched[cve]['advisories'], [['https://vendor.example/advisory', ['Vendor Advisory']]])

    def test_all_sources_prune_and_stale_imports_cannot_republish(self):
        dead_repo = 'https://github.com/owner/gone'
        dead_file = 'https://github.com/owner/collection/blob/main/removed.py'
        live_file = 'https://github.com/owner/collection/blob/main/live.py'
        health.record(missing={'owner/gone'}, dead_urls={dead_file})
        text = '### Description\nExample\n\n### POC\n'
        for header in audit.SECTION_EMPTY:
            text += f'\n{header}\n- {dead_repo}\n- {dead_file}\n- {live_file}\n'
        path = self.cves / '2026/CVE-2026-1234.md'
        path.write_text(text)
        for name in ('github.txt', 'references.txt', 'reference_pocs.txt'):
            (self.index / name).write_text(f'CVE-2026-1234 - {dead_repo}\nCVE-2026-1234 - {live_file}\n')
        (self.index / 'trending.json').write_text(json.dumps([{'url': dead_repo}, {'url': live_file}]))
        readme = self.root / 'README.md'
        readme.write_text(f'| [dead]({dead_repo}) |\n| [live]({live_file}) |\n')
        with patch.multiple(audit, ROOT=self.root, CVES=self.cves, INDEX=self.index,
                            GITHUB_LIST=self.index/'github.txt', REFERENCE_LIST=self.index/'references.txt'):
            self.assertEqual(audit.prune_unavailable(dry_run=True), (1, 14))
            self.assertEqual(path.read_text(), text)
            self.assertEqual(audit.prune_unavailable(), (1, 14))
        for header in audit.SECTION_EMPTY:
            self.assertEqual(update_cves.section_links(path.read_text(), header), [live_file])
            restored, _ = update_cves.replace_section(path.read_text(), header, [dead_file, live_file], 'No PoCs')
            self.assertNotIn(dead_file, restored)
        for name in ('github.txt', 'references.txt', 'reference_pocs.txt', 'trending.json'):
            self.assertNotIn(dead_repo, (self.index / name).read_text())
        self.assertNotIn(dead_repo, readme.read_text())
        self.assertEqual(build_site.collect_links(text), [live_file])
        with patch.object(build_site, 'TRENDING_INPUT', self.index/'trending.json'):
            self.assertEqual([r['url'] for r in build_site.build_trending(set())], [live_file])

    def test_exact_url_scope_includes_curated_and_github_files(self):
        path = self.cves / '2026/CVE-2026-1234.md'
        root = 'https://github.com/owner/collection'
        text = f'#### Github\n- {root}\n- {root}/blob/main/poc.py\n'
        text += f'#### Collections\n- {root}/blob/main/another.py\n'
        path.write_text(text)
        with patch.object(audit, 'CVES', self.cves):
            self.assertEqual(set(audit.collect_references()),
                             {root+'/blob/main/poc.py', root+'/blob/main/another.py'})

    def recovery_context(self, *, metadata=None, blacklist=(), excluded=(), sources=(), managed=(), verified=()):
        stack = ExitStack()
        stack.enter_context(patch.multiple(audit, ROOT=self.root, CVES=self.cves, INDEX=self.index,
                                          GITHUB_LIST=self.index/'github.txt', REFERENCE_LIST=self.index/'references.txt',
                                          load_blacklist=lambda: set(blacklist)))
        stack.enter_context(patch.multiple(build_site, load_metadata=lambda: metadata or {},
                                          load_reference_exclusions=lambda: set(excluded),
                                          load_source_exclusions=lambda: set(sources),
                                          load_managed_references=lambda: set(managed),
                                          load_verified_references=lambda: set(verified)))
        stack.enter_context(patch.object(update_cves, 'load_record_state', return_value={}))
        return stack

    def test_recovered_links_restore_from_release_history_with_exact_file_checks(self):
        cve, name = 'CVE-2026-1234', 'owner/cve-2026-1234'
        root = 'https://github.com/' + name
        file, reference = root + '/blob/main/other.py', 'https://example.org/exploit.py'
        path = self.cves / f'2026/{cve}.md'
        path.write_text(f'### Description\nExample\n\n### POC\n\n#### Github\n- {root}\n'
                        f'\n#### Collections\n- {file}\n\n#### Reference\n- {reference}\n')
        repo = {'nameWithOwner': name, 'databaseId': 123, 'isPrivate': False, 'visibility': 'PUBLIC',
                'root': {'entries': [{'name': 'exploit.py', 'type': 'blob'}]}}
        ledger = {str(i): {'cve': cve, 'url': url, 'gone_reason': 'unavailable', **extra}
                  for i, (url, extra) in enumerate([(root, {'repo': 123, 'field': 'poc'}),
                                                    (file, {'repo': 123, 'field': 'collections'}),
                                                    (reference, {'field': 'poc'})])}
        health.record(missing={name}, dead_urls={file, reference})
        with self.recovery_context():
            audit.prune_unavailable()
            self.assertNotIn(root, path.read_text())
            health.record(healthy={name}, live_urls={reference})
            before = path.read_bytes()
            self.assertEqual(audit.restore_recovered(ledger, {name: repo}, {reference}, dry_run=True), 2)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(audit.restore_recovered(ledger, {name: repo}, {reference}), 2)
            self.assertEqual(update_cves.section_links(path.read_text(), '#### Github'), [root])
            self.assertEqual(update_cves.section_links(path.read_text(), '#### Collections'), [])
            health.record(live_urls={file})
            self.assertEqual(audit.restore_recovered(ledger, {name: repo}, {file, reference}), 1)
            self.assertEqual(update_cves.section_links(path.read_text(), '#### Collections'), [file])
            self.assertEqual(audit.restore_recovered(ledger, {name: repo}, {file, reference}), 0)
        self.assertEqual((self.index/'github.txt').read_text(), f'{cve} - {root}\n')
        self.assertEqual((self.index/'reference_pocs.txt').read_text(), f'{cve} - {reference}\n')

    def test_recovery_respects_withdrawal_rejection_and_repository_identity(self):
        cve, name = 'CVE-2026-1234', 'owner/cve-2026-1234'
        url = 'https://github.com/' + name
        path = self.cves / f'2026/{cve}.md'
        empty = '### Description\nExample\n\n### POC\n\n#### Github\nNo PoCs found on GitHub currently.\n'
        row = {'cve': cve, 'url': url, 'gone_reason': 'unavailable', 'repo': 123}
        repo = {'nameWithOwner': name, 'databaseId': 123, 'isPrivate': False, 'visibility': 'PUBLIC',
                'root': {'entries': [{'name': 'exploit.py', 'type': 'blob'}]}}
        cases = [({'gone_reason': 'withdrawn'}, {}, {}), ({}, {'databaseId': 456}, {}),
                 ({}, {'isPrivate': True, 'visibility': 'PRIVATE'}, {}),
                 ({}, {}, {'blacklist': [name]}), ({}, {}, {'sources': [(cve, name)]}),
                 ({}, {}, {'excluded': [(cve, build_site.link_key(url))]}),
                 ({}, {}, {'metadata': {cve: {'rejected': True}}})]
        for row_change, repo_change, options in cases:
            with self.subTest(row=row_change, repo=repo_change, options=options), self.recovery_context(**options):
                path.write_text(empty)
                self.assertEqual(audit.restore_recovered({'x': {**row, **row_change}},
                                                         {name: {**repo, **repo_change}}, {url}), 0)
                self.assertEqual(path.read_text(), empty)

    def test_recovery_does_not_turn_managed_review_into_permanent_approval(self):
        cve, url = 'CVE-2026-1234', 'https://example.org/exploit.py'
        pair = (cve, build_site.link_key(url))
        path = self.cves / f'2026/{cve}.md'
        path.write_text('### Description\nExample\n\n#### Reference\nNo PoCs from references.\n')
        ledger = {'x': {'cve': cve, 'url': url, 'gone_reason': 'unavailable'}}
        with self.recovery_context(managed=[pair]):
            self.assertEqual(audit.restore_recovered(ledger, {}, {url}), 0)
        with self.recovery_context(managed=[pair], verified=[pair]):
            self.assertEqual(audit.restore_recovered(ledger, {}, {url}), 1)
        self.assertIn(url, (self.index/'references.txt').read_text())
        self.assertFalse((self.index/'reference_pocs.txt').exists())

    def test_metadata_only_recovery_remains_revocable(self):
        cve, url = 'CVE-2026-1234', 'https://example.org/advisory/42'
        path = self.cves / f'2026/{cve}.md'
        path.write_text('### Description\nExample\n\n#### Reference\nNo PoCs from references.\n')
        ledger = {'x': {'cve': cve, 'url': url, 'gone_reason': 'unavailable'}}
        with self.recovery_context(metadata={cve: {'advisories': [[url, ['Exploit']]]}}):
            self.assertEqual(audit.restore_recovered(ledger, {}, {url}), 1)
        self.assertIn(url, (self.index/'references.txt').read_text())
        self.assertFalse((self.index/'reference_pocs.txt').exists())
        self.assertFalse(build_site.reference_is_verified_poc(cve, url, {}, set()))

    def test_recovered_file_requires_public_repository_and_original_identity(self):
        cve, name = 'CVE-2026-1234', 'owner/repo'
        url = 'https://github.com/' + name + '/blob/main/poc.py'
        path = self.cves / f'2026/{cve}.md'
        empty = '### Description\nExample\n\n#### Collections\nNo PoCs from collections.\n'
        row = {'cve': cve, 'url': url, 'gone_reason': 'unavailable', 'gone': '2026-10-01T00:00:00Z', 'field': 'collections'}
        repos = [None, {'isPrivate': True, 'visibility': 'PRIVATE', 'databaseId': 12},
                 {'isPrivate': False, 'visibility': 'PUBLIC', 'databaseId': 99}]
        with self.recovery_context():
            for repo in repos:
                path.write_text(empty)
                self.assertEqual(audit.restore_recovered({'x': {**row, 'repo': 12}}, {name: repo}, {url}), 0)
            public = {'isPrivate': False, 'visibility': 'PUBLIC', 'createdAt': '2026-10-02T00:00:00Z'}
            self.assertEqual(audit.restore_recovered({'x': row}, {name: public}, {url}), 0)
            public['createdAt'] = '2026-09-01T00:00:00Z'
            path.write_text('<!-- CVE record: ABSENT -->\n' + empty)
            self.assertEqual(audit.restore_recovered({'x': row}, {name: public}, {url}), 0)
            path.write_text(empty)
            with patch.object(update_cves, 'load_record_state', return_value={cve: {'status': 'REJECTED'}}):
                self.assertEqual(audit.restore_recovered({'x': row}, {name: public}, {url}), 0)
            self.assertEqual(audit.restore_recovered({'x': row}, {name: public}, {url}), 1)

    def test_redirect_to_homepage_or_login_is_not_recovery_evidence(self):
        url = 'https://github.com/owner/poc'
        response = MagicMock()
        response.__enter__.return_value.status = 200
        for final in ('https://github.com/', 'https://github.com/login', 'https://example.org/'):
            response.__enter__.return_value.geturl.return_value = final
            with patch.object(health.request, 'urlopen', return_value=response):
                self.assertIsNone(health.check_url(url))
        response.__enter__.return_value.geturl.return_value = 'https://github.com/renamed/poc'
        with patch.object(health.request, 'urlopen', return_value=response):
            self.assertTrue(health.check_url(url))

    def test_hourly_refresh_withdraws_confirmed_dead_repo_and_schedules_recovery(self):
        url = 'https://github.com/owner/gone'
        entries = [{'poc': [url, 'https://github.com/owner/flaky']}]
        cache, state = self.index/'repo_meta.json', self.root/'metadata_state.json'
        cache.write_text('{"owner/gone":[10,"2026-10-21"],"owner/flaky":[0,"2026-10-21"]}')
        with patch.multiple(metadata, METADATA=cache, STATE=state), \
                patch.multiple(build_site, build_cve_list=lambda _: (entries, 1),
                               build_trending=lambda _: [], build_landed=lambda *a: []), \
                patch.object(metadata, 'survey', return_value=({}, {'owner/gone'}, {'owner/flaky'})), \
                patch.object(health, 'check_url', return_value=False), \
                patch.dict(metadata.os.environ, {'GITHUB_TOKEN': 'test'}), \
                patch.object(audit, 'prune_unavailable') as prune, \
                patch.object(sys, 'argv', ['sync_repo_metadata', '--references', '0']):
            self.assertEqual(metadata.main(), 0)
            prune.assert_called_once()
        self.assertTrue(health.unavailable(url))
        self.assertEqual(json.loads(cache.read_text()), {'owner/flaky': [0, '2026-10-21']})
        self.assertIn('owner/gone', json.loads(state.read_text())['retries'])
        self.assertIn('owner/flaky', json.loads(state.read_text())['retries'])
        # Still eligible after removal from the live index, unless cooling down.
        self.assertEqual(metadata.scope([], {}, [], '', 10)[0], ['owner/gone'])
        self.assertEqual(metadata.scope([], {}, [], '', 10, {'owner/gone'})[0], [])
        self.assertEqual(metadata.scope([], {}, [{'url': 'https://github.com/owner/flaky'}], '', 10,
                                        {'owner/gone', 'owner/flaky'})[0], ['owner/flaky'])

    def test_corrupt_state_fails_instead_of_republishing_everything(self):
        self.state.write_text('{"repositories":[]}')
        with self.assertRaises(ValueError):
            health.unavailable('https://github.com/owner/poc')


if __name__ == '__main__':
    unittest.main()
