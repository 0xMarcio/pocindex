from __future__ import annotations

import os
import sys
import tempfile
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

    def test_rate_limit_stops_queued_batches_before_another_request(self):
        for reader in ('discovery', 'collection'):
            client = update_cves.GitHubClient('test')
            module = update_cves if reader == 'discovery' else sync_pocingithub
            read = client.fetch_readmes if reader == 'discovery' else lambda names: sync_pocingithub.describe(client, names)
            payload = {'errors': [{'type': 'RATE_LIMITED', 'message': 'Quota exhausted'}]}
            with self.subTest(reader=reader), patch.object(module, 'http_json', return_value=payload) as fetch:
                for name in ('owner/first', 'owner/queued'):
                    with self.assertRaises(update_cves.GitHubRateLimitError):
                        read([name])
                fetch.assert_called_once()

    def test_both_importers_read_case_and_extension_variants_in_one_request(self):
        for alias, module, read in self.readers():
            for field, path in update_cves.README_PATHS.items():
                candidate = {'nameWithOwner': 'owner/repo', field: {'text': 'Reproducer for CVE-2026-1234'},
                             'root': {'entries': [{'name': path, 'type': 'blob'}, {'name': 'exploit.py', 'type': 'blob'}]}}
                payload = {'data': {alias: candidate, 'rateLimit': {'remaining': 100}}}
                with self.subTest(reader=alias, path=path), patch.object(module, 'http_json', return_value=payload) as fetch:
                    result = read()
                    fetch.assert_called_once()
                    self.assertIn('HEAD:' + path, fetch.call_args.kwargs['data']['query'])
                    text = result[1]['owner/repo'] if isinstance(result, tuple) else update_cves.readme_text(result['owner/repo'])
                    self.assertIn('CVE-2026-1234', text)
                self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), {'CVE-2026-1234'})

    def test_readme_case_does_not_promote_general_tools_or_placeholders(self):
        for field, path in update_cves.README_PATHS.items():
            for text, entries in (
                ('# Tool usage\n```sh\npython parser.py CVE-2026-1234\n```', ['parser.py', path]),
                ('PoC for CVE-2026-1234 coming soon', [path]),
            ):
                candidate = {'nameWithOwner': 'owner/tool', field: {'text': text},
                             'root': {'entries': [{'name': name, 'type': 'blob'} for name in entries]}}
                self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), set())

    def test_batch_transport_failure_reports_incomplete_refresh(self) -> None:
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
            self.assertEqual(sync_pocingithub.main(), 1)
            self.assertEqual(ensure.call_args.args[0], {})
            self.assertEqual(reconcile.call_args.args[2], {})

    def test_failed_batch_keeps_successful_sibling_publication(self) -> None:
        cve = "CVE-2026-1234"
        name = "healthy/widget-poc"
        url = f"https://github.com/{name}"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / f"{cve}.md"
            path.write_text("#### Github\nNo PoCs found on GitHub currently.\n")
            def describe(client, names):
                if names == ["failed/widget-poc"]:
                    raise TimeoutError("API unavailable")
                return {name: {"nameWithOwner": name, "url": url, "description": f"PoC for {cve}",
                               "root": {"entries": [{"name": "poc.py"}]},
                               "readmeMd": {"text": f"Reproducer for {cve}"}}}
            with patch.object(sys, "argv", ["sync"]), patch.dict(os.environ, {"GITHUB_TOKEN": "test"}), \
                    patch.object(sync_pocingithub, "BATCH", 1), \
                    patch.object(sync_pocingithub, "candidates", return_value={cve: {url, "https://github.com/failed/widget-poc"}}), \
                    patch.object(sync_pocingithub, "already_linked", return_value={cve: (path, set())}), \
                    patch.object(sync_pocingithub, "describe", side_effect=describe), \
                    patch.object(sync_pocingithub, "ensure_cve_entries", return_value=(set(), set())), \
                    patch.object(sync_pocingithub, "reconcile_inventory", return_value=(1, 0)):
                self.assertEqual(sync_pocingithub.main(), 1)
            self.assertIn(url, path.read_text())


if __name__ == "__main__":
    unittest.main()
