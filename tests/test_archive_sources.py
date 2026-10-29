from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import unquote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import archive_sources as sources

REVISION = 'a' * 40
CVE = 'CVE-2026-1234'
URL = 'https://github.com/owner/poc'
BODY = b"import requests\nresponse = requests.post('http://example.invalid/', data={'payload': 'test'})\n"


def entry(path, body=BODY):
    return {'path': path, 'type': 'blob', 'mode': '100644', 'size': len(body),
            'sha': hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest()}


class Client:
    def __init__(self, tree, body=BODY, revision=REVISION):
        self.entries, self.body, self.urls = tree, body, []
        self.revision = revision

    def json(self, url):
        self.urls.append(url)
        if '/git/trees/' not in url:
            return {'sha': self.revision}
        expression = unquote(urlsplit(url).path.rsplit('/', 1)[-1])
        prefix = expression.split(':', 1)[1] + '/' if ':' in expression else ''
        entries = [{**e, 'path': e['path'][len(prefix):]} for e in self.entries if e['path'].startswith(prefix)]
        return {'tree': entries, 'truncated': False}

    def read(self, url):
        self.urls.append(url)
        return self.body


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.target = {'original': URL, 'cves': [CVE]}
        p = patch.object(sources.source_artifacts, 'load_reviews', return_value=[])
        p.start()
        self.addCleanup(p.stop)

    def test_partial_scan_resumes_without_replacing_verified_files(self):
        client = Client([entry('poc.py'), entry('exploit.py')])
        first = sources.inspect(self.target, {}, client, file_limit=1)
        self.assertFalse(first['complete'])
        self.assertEqual(len(first['files']), 1)
        client.urls.clear()
        second = sources.inspect(self.target, first, client, file_limit=1)
        self.assertTrue(second['complete'])
        self.assertEqual(len(second['files']), 2)
        raw = [url for url in client.urls if 'raw.githubusercontent.com' in url]
        self.assertEqual(len(raw), 1)
        self.assertIn('/' + REVISION + '/', raw[0])

    def test_explicit_nuclei_file_is_preserved_and_siblings_are_not(self):
        body = b'id: CVE-2026-1234\nhttp:\n  - method: GET\n    path: ["{{BaseURL}}/poc"]\n'
        target = {**self.target, 'original': URL + '/blob/main/http/CVE-2026-1234.yaml'}
        client = Client([entry('http/CVE-2026-1234.yaml', body), entry('other.yaml', body)], body)
        result = sources.inspect(target, {}, client)
        self.assertEqual([r['path'] for r in result['files']], ['http/CVE-2026-1234.yaml'])
        self.assertFalse(any('recursive=1' in url for url in client.urls))
        self.assertIn('/git/trees/' + REVISION + '%3Ahttp', client.urls[1])

    def test_folder_link_reads_only_its_subtree(self):
        target = {**self.target, 'original': URL + '/tree/main/lab'}
        client = Client([entry('lab/poc.py'), entry('outside/poc.py')])
        result = sources.inspect(target, {}, client)
        self.assertEqual([r['path'] for r in result['files']], ['lab/poc.py'])
        self.assertIn('/git/trees/' + REVISION + '%3Alab?recursive=1', client.urls[1])

    def test_wrong_source_bytes_never_enter_capture_queue(self):
        result = sources.inspect(self.target, {}, Client([entry('poc.py')], b'Not Found'))
        self.assertEqual(result['files'], [])
        self.assertEqual(result['error'], 'source-hash-mismatch')
        self.assertFalse(result['complete'])

    def test_rule_upgrade_keeps_an_unchanged_files_existing_pinned_url(self):
        old = {'scan_version': 1, 'revision': 'b' * 40, 'cves': [CVE],
               'files': [{'path': 'poc.py', 'oid': entry('poc.py')['sha'], 'cves': [CVE]}]}
        result = sources.inspect(self.target, old, Client([entry('poc.py')]))
        self.assertEqual(result['revision'], REVISION)
        self.assertEqual(result['files'][0]['revision'], old['revision'])

    def test_head_change_keeps_rejected_paths_checked_when_their_bytes_are_unchanged(self):
        body = b'# incomplete reproduction\npass\n'
        tree = [entry('a.py', body), entry('z.py', body)]
        first = sources.inspect(self.target, {}, Client(tree, body), file_limit=1)
        self.assertEqual(first['files'], [])
        client = Client(tree, body, revision='b' * 40)
        second = sources.inspect(self.target, first, client, file_limit=1)
        raw = [url for url in client.urls if 'raw.githubusercontent.com' in url]
        self.assertEqual(len(raw), 1)
        self.assertTrue(raw[0].endswith('/z.py'))
        self.assertTrue(second['complete'])

    def test_rule_upgrade_respects_discovery_error_backoff(self):
        for version in (None, 1):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'sources.json'
                row = {'error': 'HTTPError', 'next_check_at': sources.archive.after(86400)}
                if version is not None:
                    row['scan_version'] = version
                path.write_text(json.dumps({'version': 1, 'repositories': {URL: row}}))
                with patch.dict(os.environ, {'GITHUB_TOKEN': 'dummy'}), \
                        patch.object(sources.archive, 'inventory', return_value={URL: {**self.target, 'priority': ''}}), \
                        patch.object(sources.archive.link_health, 'unavailable', return_value=False), \
                        patch.object(sources, 'inspect') as inspect, \
                        patch.object(sys, 'argv', ['archive_sources', '--manifest', str(path)]):
                    self.assertEqual(sources.main(), 0)
                inspect.assert_not_called()

    def test_poc_covering_two_published_cves_is_not_rejected_by_its_filename(self):
        target = {**self.target, 'cves': [CVE, 'CVE-2026-5678']}
        result = sources.inspect(target, {}, Client([entry('CVE-2026-1234-CVE-2026-5678.py')]))
        self.assertEqual(result['files'][0]['cves'], target['cves'])

    def test_named_file_does_not_inherit_its_sibling_cve(self):
        target = {**self.target, 'cves': [CVE, 'CVE-2026-5678']}
        result = sources.inspect(target, {}, Client([entry('CVE-2026-1234.py')]))
        self.assertEqual(result['files'][0]['cves'], [CVE])

    def test_issues_do_not_archive_unrelated_repository_code(self):
        self.assertTrue(sources.repository_source(URL))
        self.assertTrue(sources.repository_source(URL + '/blob/main/poc.py'))
        self.assertFalse(sources.repository_source(URL + '/issues/1'))
        self.assertFalse(sources.repository_source(URL + '/pull/2'))

    def test_scan_rejects_placeholders_and_ignores_vendored_code(self):
        client = Client([entry('poc.py'), entry('node_modules/poc.py')], b'pass\n')
        client.entries[0] = entry('poc.py', b'pass\n')
        result = sources.inspect(self.target, {}, client)
        self.assertEqual(result['files'], [])
        self.assertEqual(result['candidate_files'], 1)
        self.assertTrue(result['complete'])

    def test_collection_files_need_their_own_cve_association(self):
        other = 'CVE-2026-5678'
        target = {**self.target, 'cves': [CVE, other]}
        tree = [entry(f'CVE-2025-{i}/poc.py') for i in range(1000, 1006)]
        tree += [entry(f'{CVE}/poc.py'), entry(f'{other}/poc.py'), entry('shared/client.py')]
        result = sources.inspect(target, {}, Client(tree))
        self.assertEqual({r['path']: r['cves'] for r in result['files']},
                         {f'{CVE}/poc.py': [CVE], f'{other}/poc.py': [other]})

    def test_collection_can_associate_an_unnamed_file_from_its_content(self):
        body = b'# CVE-2026-1234 reproduction\n' + BODY
        tree = [entry(f'CVE-2025-{i}/poc.py', body) for i in range(1000, 1006)]
        tree.append(entry('product/trigger.py', body))
        result = sources.inspect(self.target, {}, Client(tree, body))
        self.assertEqual(result['files'][0]['cves'], [CVE])

    def test_urllib_reproduction_is_not_mistaken_for_a_stub(self):
        for call in (b'urllib.request.urlopen(req)', b'urlopen(req)'):
            body = b'import urllib.request\nreq = urllib.request.Request(url, data=payload)\n' + call
            with self.subTest(call=call):
                result = sources.inspect(self.target, {}, Client([entry('fastjson_exp.py', body)], body))
                self.assertEqual([r['path'] for r in result['files']], ['fastjson_exp.py'])

    def test_unsent_request_is_not_a_reproduction(self):
        body = b'import urllib.request\nreq = urllib.request.Request(url, data=payload)\n'
        result = sources.inspect(self.target, {}, Client([entry('poc.py', body)], body))
        self.assertEqual(result['files'], [])

    def test_multiline_curl_reproduction_with_variable_target_is_retained(self):
        body = b'#!/bin/sh\nBASE_URL="$1"\ncurl -s -o /dev/null \\\n  "${BASE_URL}&payload=${2}"\n'
        result = sources.inspect(self.target, {}, Client([entry('poc/poc.sh', body)], body))
        self.assertEqual([r['path'] for r in result['files']], ['poc/poc.sh'])

    def test_named_reproductions_precede_library_code_and_readmes(self):
        paths = ['README.md', 'a/library.py', 'env/fastjson_exp.py', 'poc_example.py', f'{CVE}.py']
        selected = sources.candidate_paths([entry(path) for path in paths], self.target)
        self.assertEqual([r['path'] for r in selected],
                         [f'{CVE}.py', 'env/fastjson_exp.py', 'poc_example.py', 'a/library.py', 'README.md'])

    def test_large_tree_keeps_entrypoints_and_documented_files_not_vendor_code(self):
        paths = [f'packages/payload/src/lib{i}.ts' for i in range(101)]
        paths += ['env/fastjson_exp.py', 'env/fcgi.py', 'demo/run.py', 'README.md',
                  'vendorlib/README.md', 'packages/app/payload.config.ts', f'{CVE}/main.c']
        selected = sources.candidate_paths([entry(path) for path in paths], self.target,
                                           'Run python demo/run.py to reproduce the issue.')
        self.assertEqual({r['path'] for r in selected},
                         {'env/fastjson_exp.py', 'env/fcgi.py', 'demo/run.py', 'README.md', f'{CVE}/main.c'})

    def test_large_collection_does_not_cap_the_number_of_reproductions(self):
        paths = [f'{CVE}/poc{i}.py' for i in range(150)]
        self.assertEqual(len(sources.candidate_paths([entry(path) for path in paths], self.target)), 150)


if __name__ == '__main__':
    unittest.main()
