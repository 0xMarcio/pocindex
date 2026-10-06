from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

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


if __name__ == "__main__":
    unittest.main()
