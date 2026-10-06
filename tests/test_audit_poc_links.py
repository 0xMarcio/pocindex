from __future__ import annotations

import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import audit_poc_links
from update_cves import GitHubClient


class RepositorySurveyTests(unittest.TestCase):
    def repo(self, filename: str = "README.md") -> dict:
        return {
            "nameWithOwner": "owner/poc",
            "stargazerCount": 10,
            "pushedAt": "2026-10-06T12:00:00Z",
            "root": {"entries": [{"name": filename, "type": "blob"}]},
            "readmeMd": None,
        }

    def survey(self, payload: dict, names: list[str] | None = None) -> tuple:
        with patch.object(audit_poc_links, "http_json", return_value=payload):
            return audit_poc_links.survey(GitHubClient("test-token"), names or ["owner/poc"])

    def test_preserves_repository_when_readme_lookup_fails(self) -> None:
        self.assertEqual(self.survey({
            "data": {"r0": self.repo()},
            "errors": [{"type": "INTERNAL", "path": ["r0", "readmeMd"]}],
        }), (set(), {}))

    def test_nested_not_found_does_not_mean_repository_is_deleted(self) -> None:
        self.assertEqual(self.survey({
            "data": {"r0": self.repo("exploit.py")},
            "errors": [{"type": "NOT_FOUND", "path": ["r0", "readmeMd"]}],
        }), (set(), {}))

    def test_pathless_error_preserves_the_batch(self) -> None:
        self.assertEqual(self.survey({
            "data": {"r0": self.repo()},
            "errors": [{"type": "INTERNAL", "message": "Temporary failure"}],
        }), (set(), {}))

    def test_confirmed_missing_repository_is_removed(self) -> None:
        self.assertEqual(self.survey({
            "data": {"r0": None},
            "errors": [{"type": "NOT_FOUND", "path": ["r0"]}],
        }), ({"owner/poc"}, {}))

    def test_complete_bare_repository_is_removed(self) -> None:
        self.assertEqual(self.survey({"data": {"r0": self.repo()}}), ({"owner/poc"}, {}))

    def test_partial_failure_keeps_other_repository_metadata(self) -> None:
        self.assertEqual(self.survey({
            "data": {"r0": self.repo(), "r1": self.repo("exploit.py")},
            "errors": [{"type": "INTERNAL", "path": ["r0", "readmeMd"]}],
        }, ["owner/poc", "owner/healthy"]), (set(), {"owner/healthy": [10, "2026-10-06"]}))


class ReferenceAuditTests(unittest.TestCase):
    def test_head_not_found_keeps_reference_when_get_succeeds(self) -> None:
        url = "https://example.com/poc"
        for code in (404, 410):
            with self.subTest(code=code), patch.object(
                audit_poc_links.request,
                "urlopen",
                side_effect=[HTTPError(url, code, "No HEAD route", {}, None), io.BytesIO(b"PoC")],
            ) as fetch:
                self.assertEqual(audit_poc_links.dead_references([url], workers=1, timeout=1), set())
                self.assertEqual([call.args[0].method for call in fetch.call_args_list], ["HEAD", "GET"])

    def test_get_confirms_reference_is_missing(self) -> None:
        url = "https://example.com/poc"
        for code in (404, 410):
            with self.subTest(code=code), patch.object(
                audit_poc_links.request,
                "urlopen",
                side_effect=[HTTPError(url, code, "Missing", {}, None), HTTPError(url, code, "Missing", {}, None)],
            ) as fetch:
                self.assertEqual(audit_poc_links.dead_references([url], workers=1, timeout=1), {url})
                self.assertEqual([call.args[0].method for call in fetch.call_args_list], ["HEAD", "GET"])


if __name__ == "__main__":
    unittest.main()
