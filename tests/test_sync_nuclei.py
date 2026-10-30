from __future__ import annotations

import sys
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import sync_nuclei
import update_cves


CORE_VERSION_PROBE = '''id: CVE-2003-1598
info:
  name: WordPress Core SQL Injection
http:
  - method: GET
    path:
      - "{{BaseURL}}"
      - "{{BaseURL}}/wp-admin/install.php"
      - "{{BaseURL}}/feed/"
      - "{{BaseURL}}/?feed=rss2"
    matchers:
      - type: dsl
        dsl:
          - compare_versions(version_by_generator, '< 0.72')
          - compare_versions(version_by_js, '< 0.72')
          - compare_versions(version_by_css, '< 0.72')
    extractors:
      - type: regex
        name: version_by_generator
        regex:
          - 'wordpress.org/\\?v=([0-9.]+)'
'''


class VersionProbeTests(unittest.TestCase):
    def test_wordpress_core_version_probe_is_not_a_poc(self) -> None:
        self.assertTrue(sync_nuclei.version_probe_only(CORE_VERSION_PROBE))

    def test_actual_exploit_is_kept_even_with_a_version_check(self) -> None:
        for change in (
            CORE_VERSION_PROBE.replace('"{{BaseURL}}/feed/"', '"{{BaseURL}}/?posts=1+UNION+SELECT+1"'),
            CORE_VERSION_PROBE.replace('"{{BaseURL}}/feed/"', "'{{BaseURL}}/?posts=1+UNION+SELECT+1'"),
            CORE_VERSION_PROBE.replace('"{{BaseURL}}/feed/"', '"{{RootURL}}/exploit"'),
            CORE_VERSION_PROBE.replace('"{{BaseURL}}/feed/"', '"https://example.com/exploit"'),
            CORE_VERSION_PROBE.replace("method: GET", "method: POST"),
            CORE_VERSION_PROBE + '\n    raw: ["GET /exploit HTTP/1.1"]\n',
            CORE_VERSION_PROBE + '\ncode:\n  - engine: [python3]\n    source: exploit_code\n',
        ):
            with self.subTest(template=change):
                self.assertFalse(sync_nuclei.version_probe_only(change))

    def test_translation_catalog_version_checks_are_not_exploits(self):
        template = '''id: CVE-2026-6279
http:
  - method: GET
    path:
      - '{{BaseURL}}/wp-content/plugins/fusion-builder/languages/fusion-builder.pot'
    extractors:
      - type: regex
        name: version
    matchers:
      - type: dsl
        dsl:
          - compare_versions(version, '<= 3.15.2')
'''
        self.assertTrue(sync_nuclei.version_probe_only(template))
        for content in (template.replace('method: GET', 'method: POST'),
                        template.replace(".pot'", ".pot?payload=trigger'"),
                        template + '\ncode:\n  - engine: [python3]\n    source: reproduce\n',
                        template + '\n  - path:\n      - "{{RootURL}}/exploit"\n'):
            self.assertFalse(sync_nuclei.version_probe_only(content))

    def test_readme_metadata_probe_does_not_mask_another_exploit_protocol(self):
        template = CORE_VERSION_PROBE.replace('"{{BaseURL}}/feed/"', "'{{BaseURL}}/readme.txt'")
        template = template[template.index('http:'):].replace('"{{BaseURL}}"', "'{{BaseURL}}/readme.md'")
        template = template.replace('"{{BaseURL}}/wp-admin/install.php"', "'{{BaseURL}}/style.css'")
        template = template.replace('"{{BaseURL}}/?feed=rss2"', "'{{BaseURL}}/changelog.txt'")
        template = '\n' + template
        self.assertTrue(sync_nuclei.version_probe_only(template))
        self.assertFalse(sync_nuclei.version_probe_only(template + '\ncode:\n  - engine: [python3]\n    source: reproduce\n'))

    def test_login_version_probe_does_not_hide_payload_or_header_checks(self):
        text = '''id: CVE-2026-12345
http:
  - method: GET
    path:
      - '{{BaseURL}}/login.html'
    matchers:
      - type: dsl
        dsl:
          - "compare_versions(version, '< 1.2.3')"
    extractors:
      - type: regex
        name: version
'''
        self.assertTrue(sync_nuclei.version_probe_only(text))
        for content in (text.replace('/login.html', '/login.html?payload=trigger'),
                        text.replace('method: GET', 'method: POST'),
                        text + '    headers:\n      X-Auth-Bypass: trigger\n',
                        text + '\ncode:\n  - engine: [python3]\n    source: reproduce\n'):
            self.assertFalse(sync_nuclei.version_probe_only(content))


def archive(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as tar:
        for path, text in files.items():
            raw = text.encode()
            member = tarfile.TarInfo('templates/' + path)
            member.size = len(raw)
            tar.addfile(member, io.BytesIO(raw))
    return output.getvalue()


class TemplateCoverageTests(unittest.TestCase):
    def test_multiple_templates_survive_with_metadata_precedence_and_stale_removal(self):
        cve = 'CVE-2003-1598'
        primary = 'https://github.com/projectdiscovery/nuclei-templates/blob/main/'
        secondary = 'https://github.com/Akokonunes/Private-Nuclei-Templates/blob/main/'
        exploit = CORE_VERSION_PROBE.replace('method: GET', 'method: POST')
        feeds = {
            'primary': archive({f'http/cves/{cve}.yaml': exploit,
                                f'http/cves/{cve}-variant.yaml': exploit.replace('/feed/', '/other-endpoint/'),
                                f'http/cves/{cve}-version.yaml': CORE_VERSION_PROBE}),
            'secondary': archive({f'{cve}.yaml': exploit.replace('info:', 'info:\n  severity: critical')}),
        }
        expected = [primary + f'http/cves/{cve}-variant.yaml', primary + f'http/cves/{cve}.yaml',
                    secondary + f'{cve}.yaml']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / '2003' / f'{cve}.md'
            path.parent.mkdir()
            path.write_text('### POC\n#### Nuclei\n- ' + expected[0]
                            + '\n- https://example.org/stale\n\n#### Github\n- https://github.com/author/poc\n')
            with patch.object(sync_nuclei, 'CVES', root), \
                    patch.object(sync_nuclei, 'OUTPUT', root / 'nuclei.json'), \
                    patch.object(sync_nuclei, 'SOURCES', [('primary', 'primary', primary, True),
                                                        ('secondary', 'secondary', secondary, False)]), \
                    patch.object(sync_nuclei, 'download', side_effect=feeds.__getitem__), \
                    patch.object(sync_nuclei, 'ensure_cve_entries', return_value=(set(), set())), \
                    patch.object(sync_nuclei.releases, 'load_ledger', return_value={}), \
                    patch.object(sync_nuclei.releases, 'published_pairs', return_value=[]), \
                    patch.object(sync_nuclei.releases, 'save_ledger'), \
                    patch.object(sys, 'argv', ['sync_nuclei.py']):
                self.assertEqual(sync_nuclei.main(), 0)
                self.assertEqual(sync_nuclei.apply_to_markdown(cve, expected, False), 'unchanged')
            text = path.read_text()
            self.assertEqual(update_cves.section_links(text, sync_nuclei.SECTION), expected)
            self.assertIn('https://github.com/author/poc', text)
            self.assertNotIn('https://example.org/stale', text)
            metadata = json.loads((root / 'nuclei.json').read_text())[cve]
            self.assertEqual(metadata['urls'], expected)
            self.assertTrue(metadata['url'].startswith(primary))
            self.assertNotIn('severity', metadata)

    def test_exact_copies_are_deduplicated_without_changing_payload_whitespace(self):
        cve = 'CVE-2003-1598'
        text = CORE_VERSION_PROBE.replace('method: GET', 'method: POST')
        seen = set()
        primary = sync_nuclei.collect(archive({f'{cve}.yaml': text}), 'https://primary/', False, seen=seen)
        secondary = sync_nuclei.collect(archive({
            f'{cve}-copy.yaml': text.replace('\n', '\r\n') + '# digest: signature\r\n',
            f'{cve}-variant.yaml': text.replace('/feed/', '/feed/ '),
        }), 'https://secondary/', False, seen=seen)
        self.assertEqual(primary[cve]['urls'], [f'https://primary/{cve}.yaml'])
        self.assertEqual(secondary[cve]['urls'], [f'https://secondary/{cve}-variant.yaml'])

    def test_conflicting_template_identity_does_not_override_correct_template(self):
        cve = 'CVE-2003-1598'
        text = CORE_VERSION_PROBE.replace('method: GET', 'method: POST')
        found = sync_nuclei.collect(archive({
            f'{cve}-mislabeled.yaml': text.replace('id: CVE-2003-1598', 'id: CVE-2003-9999'),
            f'{cve}.yaml': text,
        }), 'https://source/', False)
        self.assertEqual(found[cve]['urls'], [f'https://source/{cve}.yaml'])

    def test_dead_first_copy_does_not_hide_an_identical_live_copy(self):
        cve = 'CVE-2003-1598'
        data = archive({f'{cve}.yaml': CORE_VERSION_PROBE.replace('method: GET', 'method: POST')})
        seen = set()
        with patch.object(sync_nuclei.link_health, 'unavailable', side_effect=lambda url: url.startswith('https://dead/')):
            self.assertEqual(sync_nuclei.collect(data, 'https://dead/', False, seen=seen), {})
            found = sync_nuclei.collect(data, 'https://live/', False, seen=seen)
        self.assertEqual(found[cve]['urls'], [f'https://live/{cve}.yaml'])

    def test_template_paths_are_encoded_as_complete_links(self):
        cve = 'CVE-2003-1598'
        data = archive({f'extra templates/{cve}-copy #2.yaml': CORE_VERSION_PROBE.replace('method: GET', 'method: POST')})
        found = sync_nuclei.collect(data, 'https://source/', False)
        self.assertEqual(found[cve]['urls'], [f'https://source/extra%20templates/{cve}-copy%20%232.yaml'])

    def test_only_dead_templates_remove_the_section_without_touching_other_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / '2026' / 'CVE-2026-1234.md'
            path.parent.mkdir()
            original = '### POC\n#### Nuclei\n- https://example.org/dead\n\n#### Github\n- https://github.com/author/poc\n'
            path.write_text(original)
            with patch.object(sync_nuclei, 'CVES', root), patch('link_health.unavailable', return_value=True):
                sync_nuclei.apply_to_markdown('CVE-2026-1234', ['https://example.org/dead'], True)
                self.assertEqual(path.read_text(), original)
                sync_nuclei.apply_to_markdown('CVE-2026-1234', ['https://example.org/dead'], False)
            self.assertNotIn('#### Nuclei', path.read_text())
            self.assertIn('https://github.com/author/poc', path.read_text())


if __name__ == "__main__":
    unittest.main()
