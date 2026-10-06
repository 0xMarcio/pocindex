from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import sync_pocingithub
import update_cves


class GitHubResponseTests(unittest.TestCase):
    def readers(self):
        client = update_cves.GitHubClient("test")
        return (
            ("repo0", update_cves, lambda: client.fetch_readmes(["owner/repo"])),
            ("r0", sync_pocingithub, lambda: sync_pocingithub.describe(client, ["owner/repo"])),
        )

    def test_operational_graphql_errors_are_not_missing_repositories(self) -> None:
        for alias, module, read in self.readers():
            for error in (
                {"type": "RATE_LIMITED", "message": "Rate limited"},
                {"type": "INTERNAL", "message": "Internal error", "path": [alias]},
                {"type": "NOT_FOUND", "message": "Nested lookup failed", "path": [alias, "root"]},
            ):
                with self.subTest(reader=alias, error=error["message"]):
                    payload = {"data": {alias: None, "rateLimit": {"remaining": 100}}, "errors": [error]}
                    with patch.object(module, "http_json", return_value=payload):
                        with self.assertRaises(RuntimeError):
                            read()

    def test_missing_repository_is_tolerated(self) -> None:
        for alias, module, read in self.readers():
            with self.subTest(reader=alias):
                payload = {
                    "data": {alias: None, "rateLimit": {"remaining": 100}},
                    "errors": [{"type": "NOT_FOUND", "path": [alias], "message": "Repository missing"}],
                }
                with patch.object(module, "http_json", return_value=payload):
                    result = read()
                self.assertFalse(result[0] if isinstance(result, tuple) else result)

    def test_incomplete_response_is_not_a_missing_repository(self) -> None:
        for alias, module, read in self.readers():
            with self.subTest(reader=alias), patch.object(
                module, "http_json", return_value={"data": {"rateLimit": {"remaining": 100}}}
            ):
                with self.assertRaises(RuntimeError):
                    read()

    def test_deleted_repository_does_not_discard_other_batch_results(self) -> None:
        client = update_cves.GitHubClient("test")
        names = ["owner/deleted", "owner/repo"]
        for prefix, module, read in (
            ("repo", update_cves, lambda: client.fetch_readmes(names)),
            ("r", sync_pocingithub, lambda: sync_pocingithub.describe(client, names)),
        ):
            payload = {
                "data": {f"{prefix}0": None, f"{prefix}1": {"readmeMd": {"text": "PoC"}},
                         "rateLimit": {"remaining": 100}},
                "errors": [{"type": "NOT_FOUND", "path": [f"{prefix}0"]}],
            }
            with self.subTest(reader=prefix), patch.object(module, "http_json", return_value=payload):
                result = read()
                self.assertEqual(set(result[0] if isinstance(result, tuple) else result), {"owner/repo"})

    def test_near_exhausted_quota_aborts(self) -> None:
        for alias, module, read in self.readers():
            with self.subTest(reader=alias), patch.object(
                module, "http_json", return_value={"data": {alias: {}, "rateLimit": {"remaining": 0}}}
            ):
                with self.assertRaises(RuntimeError):
                    read()

    def test_batch_transport_failure_aborts_before_writes(self) -> None:
        with patch.object(sys, "argv", ["sync_pocingithub.py"]), patch.dict(
            os.environ, {"GITHUB_TOKEN": "test"}
        ), patch.object(
            sync_pocingithub, "candidates",
            return_value={"CVE-2026-1234": {"https://github.com/owner/repo"}},
        ), patch.object(sync_pocingithub, "already_linked", return_value={}), patch.object(
            sync_pocingithub, "describe", side_effect=RuntimeError("API unavailable")
        ), patch.object(sync_pocingithub, "ensure_cve_entries", return_value=(set(), set())) as ensure, patch.object(
            sync_pocingithub, "reconcile_inventory", return_value=(0, 0)
        ) as reconcile:
            with self.assertRaisesRegex(RuntimeError, "API unavailable"):
                sync_pocingithub.main()
            ensure.assert_not_called()
            reconcile.assert_not_called()


if __name__ == "__main__":
    unittest.main()
