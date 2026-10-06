from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import sync_nuclei


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


if __name__ == "__main__":
    unittest.main()
