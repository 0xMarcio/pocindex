from __future__ import annotations

import io
import hashlib
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import sync_collections


class AuthorCollectionTests(unittest.TestCase):
    def archive(self, files: dict[str, str | bytes]) -> bytes:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as tar:
            for path, text in files.items():
                body = text if isinstance(text, bytes) else text.encode()
                member = tarfile.TarInfo("snapshot/" + path)
                member.size = len(body)
                tar.addfile(member, io.BytesIO(body))
        return output.getvalue()

    def test_author_sources_are_scheduled(self) -> None:
        repos = {repo for _, repo, _ in sync_collections.SOURCES}
        self.assertTrue({"tenable/poc", "pedrib/PoC"} <= repos)

    def test_tenable_uses_single_cve_code_paths_or_headers(self) -> None:
        found = sync_collections.collect("tenable/poc", "master", self.archive({
            "Qualcomm/cve-2019-10618.cpp": "// CVE-2019-10618\nint main() { return 0; }",
            "Rockwell/FTDiagViewer_dos.py": "# Exploit for CVE-2020-5807\nimport socket\n",
            "MAGMI/cve_2020_5776/csrf_poc.html": "<form method=POST></form>",
        }))
        self.assertEqual(found, {
            "CVE-2019-10618": ["https://github.com/tenable/poc/blob/master/Qualcomm/cve-2019-10618.cpp"],
            "CVE-2020-5807": ["https://github.com/tenable/poc/blob/master/Rockwell/FTDiagViewer_dos.py"],
            "CVE-2020-5776": ["https://github.com/tenable/poc/blob/master/MAGMI/cve_2020_5776/csrf_poc.html"],
        })

    def test_conflicting_ids_and_support_files_are_not_code_evidence(self) -> None:
        found = sync_collections.collect("tenable/poc", "master", self.archive({
            "cve_2018_8840_indusoft_rce.py": "# CVE-2019-3946\nimport socket\n",
            "cve-2020-12080.py": "# Historical CVE-2015-8277\nimport socket\n",
            "ambiguous.py": "# CVE-2020-5801 and CVE-2020-5802\nimport socket\n",
            "CVE-2020-5801/README.md": "# Advisory\nUpdate to the fixed version.",
            "CVE-2020-5802/setup.py": "from setuptools import setup\nsetup()",
            "CVE-2020-5806/tests/poc.py": "import socket\n",
            "CVE-2020-5807/empty.py": "",
            "CVE-2020-5807/comment_only.py": "#!/usr/bin/python\n# Exploit for CVE-2020-5807\n",
            "CVE-2020-5807/prose.py": "CVE-2020-5807\nUpload this ZIP to reproduce the issue.\n",
            "CVE-2020-5807/advisory.html": "<html><body>Install the fixed version.</body></html>",
        }))
        self.assertEqual(found, {})

    def test_pedrib_code_links_to_its_nested_file(self) -> None:
        found = sync_collections.collect("pedrib/PoC", "master", self.archive({
            "exploits/acsPwn/acsPwn.rb": "# Exploit for CVE-2017-5641\nrequire 'socket'\n",
            "advisories/example.py": "# CVE-2024-1001\nimport socket\n",
        }))
        self.assertEqual(found, {"CVE-2017-5641": [
            "https://github.com/pedrib/PoC/blob/master/exploits/acsPwn/acsPwn.rb",
        ]})

    def test_reviewed_conflict_requires_exact_repository_path_and_bytes(self) -> None:
        path = "SchneiderElectric/InduSoft/cve_2018_8840_indusoft_rce.py"
        source = b"# CVE-2019-3946\n# archived byte: \xff\nimport socket\n"
        reviews = [{"cve": "CVE-2018-8840", "repository": "tenable/poc", "path": path,
                    "sha256": hashlib.sha256(source).hexdigest()}]
        found = sync_collections.collect("tenable/poc", "master", self.archive({path: source}), reviews=reviews)
        self.assertEqual(found, {"CVE-2018-8840": [f"https://github.com/tenable/poc/blob/master/{path}"]})
        for changed_path, changed_source, changed_reviews in (
            (path, source + b"# changed\n", reviews),
            ("other/" + path, source, reviews),
            (path, source, [{**reviews[0], "repository": "unrelated/poc"}]),
        ):
            with self.subTest(path=changed_path, source=changed_source):
                self.assertEqual(sync_collections.collect(
                    "tenable/poc", "master", self.archive({changed_path: changed_source}), reviews=changed_reviews,
                ), {})

    def test_reviewed_chain_adds_only_its_explicit_cve_approvals(self) -> None:
        path = "advantech/webaccess_scada/webaccess_832_cve-2018-15705.py"
        source = b"# Exploits CVE-2018-15707 then CVE-2018-15705\nimport socket\n"
        reviews = [{"cve": cve, "repository": "tenable/poc", "path": path,
                    "sha256": hashlib.sha256(source).hexdigest()}
                   for cve in ("CVE-2018-15705", "CVE-2018-15707")]
        self.assertEqual(sync_collections.collect(
            "tenable/poc", "master", self.archive({path: source}), reviews=reviews,
        ), {cve: [f"https://github.com/tenable/poc/blob/master/{path}"] for cve in ("CVE-2018-15705", "CVE-2018-15707")})

    def test_embedded_reproducer_does_not_inherit_historical_cve_mentions(self) -> None:
        path = "advisories/ManageEngine/adselfpwnplus/adselfpwnplus.md"
        text = """A similar vulnerability was CVE-2020-11552.
## Appendix: Python server
```python
#!/usr/bin/env python3
# Python HTTP server for exploiting CVE-2023-35719
from http.server import HTTPServer
server = HTTPServer(('localhost', 8000), Handler)
server.serve_forever()
```
"""
        self.assertEqual(sync_collections.collect("pedrib/PoC", "master", self.archive({path: text})), {
            "CVE-2023-35719": [f"https://github.com/pedrib/PoC/blob/master/{path}"],
        })

    def test_single_cve_writeup_requires_runnable_reproduction_section(self) -> None:
        found = sync_collections.collect("pedrib/PoC", "master", self.archive({
            "advisories/Cisco/DCNMPwn.md": """The deserialization flaw is CVE-2017-5641.
### Full Exploit
```bash
#!/bin/bash
# Run the supplied reproduction
java -jar exploit.jar
```
""",
            "advisories/CVE-2024-1001.md": """# CVE-2024-1001
## Mitigation
```bash
curl https://example.com/update.sh
```
""",
            "advisories/CVE-2024-1002.md": """# CVE-2024-1002
## Exploitation
No public reproducer is available.
## Mitigation
```bash
curl https://example.com/update.sh
```
""",
            "advisories/CVE-2024-1003.md": """# CVE-2024-1004
## Full Exploit
```python
# Exploit for CVE-2024-1004
import socket
```
""",
        }))
        self.assertEqual(found, {"CVE-2017-5641": [
            "https://github.com/pedrib/PoC/blob/master/advisories/Cisco/DCNMPwn.md",
        ]})


class ResearchCollectionTests(unittest.TestCase):
    def setUp(self) -> None:
        patcher = patch.object(sync_collections.releases, "record_collection_snapshot")
        self.release_hook = patcher.start()
        self.addCleanup(patcher.stop)

    def tree(self, *paths: str) -> dict:
        return {"truncated": False, "tree": [
            {"path": path, "type": "blob", "mode": "100644", "size": 100}
            for path in paths
        ]}

    def test_source_head_requires_a_complete_matching_commit_ref(self) -> None:
        good = {"ref": "refs/heads/master", "object": {"type": "commit", "sha": "a" * 40}}
        with patch.object(sync_collections, "http_json", return_value=good):
            self.assertEqual(sync_collections.source_head("tenable/poc", "master"), "a" * 40)
        for payload in ({}, [], {"ref": "refs/heads/main", "object": good["object"]},
                        {"ref": good["ref"], "object": {"type": "tree", "sha": "a" * 40}},
                        {"ref": good["ref"], "object": {"type": "commit", "sha": ""}}):
            with self.subTest(payload=payload), patch.object(sync_collections, "http_json", return_value=payload):
                with self.assertRaises(ValueError):
                    sync_collections.source_head("tenable/poc", "master")

    def test_cve_directory_requires_its_own_artifact(self) -> None:
        payload = self.tree(
            "pocs/linux/CVE-2024-1001/exploit/lts/exploit.c",
            "pocs/linux/CVE-2024-1001/docs/exploit.md",
            "pocs/linux/CVE-2024-1002/README.md",
            "pocs/linux/CVE-2024-1002/Makefile",
            "pocs/linux/CVE-2024-1002/helpers.c",
            "pocs/linux/CVE-2024-1002/tests/poc.py",
            "pocs/linux/CVE-2024-1002/docs/poc.py",
            "pocs/linux/CVE-2024-1003-and-CVE-2024-1004/exploit.c",
            "pocs/linux/CVE-2024-1005/CVE-2024-1006/exploit.c",
            "advisories/CVE-2024-1007/exploit.c",
        )
        self.assertEqual(sync_collections.collect_research_tree(
            "google/security-research", "master", "pocs/", payload,
        ), {"CVE-2024-1001": [
            "https://github.com/google/security-research/tree/master/pocs/linux/CVE-2024-1001",
        ]})

    def test_security_lab_reproduction_files_and_code_qualify(self) -> None:
        paths = (
            "SecurityExploits/libcue/track_set_index_CVE-2023-43641/CVE-2023-43641-poc-simple.cue",
            "SecurityExploits/poppler/CVE-2025-52885/bug.pdf",
            "SecurityExploits/poppler/CVE-2025-52886/pdfgen.cpp",
            "SecurityExploits/DjVuLibre/CVE-2025-53367/fuzzer-poc.djvu",
            "SecurityExploits/libssh2/CVE-2019-17498/server/home/poc.bin",
            "SecurityExploits/unknown/CVE-2024-1001/writeup.pdf",
        )
        found = sync_collections.collect_research_tree(
            "github/securitylab", "main", "SecurityExploits/", self.tree(*paths),
        )
        self.assertEqual(set(found), {
            "CVE-2023-43641", "CVE-2025-52885", "CVE-2025-52886", "CVE-2025-53367", "CVE-2019-17498",
        })

    def test_truncated_or_missing_tree_is_not_a_complete_source(self) -> None:
        for payload in ({"truncated": True, "tree": []}, {"tree": []}, {"truncated": False}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                sync_collections.collect_research_tree("google/security-research", "master", "pocs/", payload)

    def test_reviewed_exploit_patches_qualify_but_generic_text_does_not(self) -> None:
        payload = self.tree(
            "SecurityExploits/libssh/pubkey-auth-bypass-CVE-2023-2283/attacker/home/diff.txt",
            "SecurityExploits/libssh2/out_of_bounds_read_kex_CVE-2019-13115/server/home/diff.txt",
            "SecurityExploits/strongSwan/CVE-2018-5388/stroke_patch.txt",
            "SecurityExploits/unknown/CVE-2024-1001/diff.txt",
            "SecurityExploits/unknown/CVE-2024-1002/exploit.patch",
            "SecurityExploits/unknown/CVE-2024-1003/stroke_patch.txt",
        )
        found = sync_collections.collect_research_tree("github/securitylab", "main", "SecurityExploits/", payload)
        self.assertEqual(set(found), {"CVE-2023-2283", "CVE-2019-13115", "CVE-2018-5388"})

    def test_failed_research_source_stops_before_any_index_mutation(self) -> None:
        with patch.object(sys, "argv", ["sync_collections.py"]), \
             patch.object(sync_collections, "SOURCES", ()), \
             patch.object(sync_collections, "source_head", return_value="a" * 40), \
             patch.object(sync_collections, "load_source_state", return_value={}), \
             patch.object(sync_collections, "download_tree", return_value={"truncated": True, "tree": []}), \
             patch.object(sync_collections, "ensure_cve_entries") as ensure:
            self.assertEqual(sync_collections.main(), 1)
            ensure.assert_not_called()

    def test_research_links_merge_with_existing_collection_sources(self) -> None:
        cid = "CVE-2024-1001"
        payload = self.tree(f"pocs/linux/{cid}/exploit.c")
        old_url = "https://github.com/chaitin/xray/blob/master/pocs/example.yml"
        new_url = f"https://github.com/google/security-research/tree/master/pocs/linux/{cid}"
        with patch.object(sys, "argv", ["sync_collections.py"]), \
             patch.object(sync_collections, "SOURCES", (("xray", "chaitin/xray", "master"),)), \
             patch.object(sync_collections, "TREE_SOURCES", (("google", "google/security-research", "master", "pocs/"),)), \
             patch.object(sync_collections, "source_head", return_value="a" * 40), \
             patch.object(sync_collections, "load_source_state", return_value={}), \
             patch.object(sync_collections, "write_source_state"), \
             patch.object(sync_collections, "download", return_value=b"archive"), \
             patch.object(sync_collections, "collect", return_value={cid: [old_url]}), \
             patch.object(sync_collections, "download_tree", return_value=payload), \
             patch.object(sync_collections, "ensure_cve_entries", return_value=(set(), set())), \
             patch.object(sync_collections, "apply_links", return_value="unchanged") as apply, \
             patch.object(sync_collections, "CVES") as cves:
            cves.glob.return_value = []
            self.assertEqual(sync_collections.main(), 0)
            apply.assert_called_once_with(cid, sorted([old_url, new_url]), dry_run=False)


class CollectionCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.state_file = root / "collection_source_state.json"
        self.cves = root / "cves"
        self.cve = "CVE-2024-1001"
        self.path = self.cves / "2024" / f"{self.cve}.md"
        self.path.parent.mkdir(parents=True)
        self.repo = "tenable/poc"
        self.url = f"https://github.com/{self.repo}/blob/master/{self.cve}/poc.py"
        self.original = f"# {self.cve}\n\n#### Collections\n- {self.url}\n"
        self.path.write_text(self.original)
        self.revision = "a" * 40
        self.links = {self.cve: [self.url]}
        self.state = {"version": 1, "sources": {self.repo: {
            "revision": self.revision, "branch": "master", "prefix": None, "links": self.links,
            "observed_at": "2026-10-01T00:00:00Z",
        }}}
        self.state_file.write_text(json.dumps(self.state) + "\n")
        self.before = self.state_file.read_bytes()
        for name, value in (
            ("SOURCE_STATE_FILE", self.state_file),
            ("SOURCE_CACHE_VERSION", 1),
            ("CVES", self.cves),
            ("SOURCES", (("tenable", self.repo, "master"),)),
            ("TREE_SOURCES", ()),
        ):
            mock = patch.object(sync_collections, name, value, create=True)
            mock.start()
            self.addCleanup(mock.stop)
        for target, kwargs in (
            ("source_head", {"return_value": self.revision, "create": True}),
            ("ensure_cve_entries", {"return_value": (set(), set())}),
        ):
            mock = patch.object(sync_collections, target, **kwargs)
            setattr(self, target, mock.start())
            self.addCleanup(mock.stop)
        argv = patch.object(sys, "argv", ["sync_collections.py"])
        argv.start()
        self.addCleanup(argv.stop)
        registry = patch.object(sync_collections.source_artifacts, "load_reviews", return_value=[])
        self.reviews = registry.start()
        self.addCleanup(registry.stop)
        release_hook = patch.object(sync_collections.releases, "record_collection_snapshot")
        self.release_hook = release_hook.start()
        self.addCleanup(release_hook.stop)

    def test_unchanged_head_reuses_links_and_still_retries_base_records(self) -> None:
        pending = "CVE-2024-1002"
        self.links[pending] = [self.url.replace(self.cve, pending)]
        self.state_file.write_text(json.dumps(self.state) + "\n")
        self.before = self.state_file.read_bytes()
        self.ensure_cve_entries.return_value = (set(), {pending})
        with patch.object(sync_collections, "download", return_value=b"archive") as download, \
             patch.object(sync_collections, "collect", return_value=self.links) as collect:
            self.assertEqual(sync_collections.main(), 0)
            download.assert_not_called()
            collect.assert_not_called()
        self.ensure_cve_entries.assert_called_once_with(self.links, dry_run=False, cvelist_dir=None)
        self.assertEqual(self.state_file.read_bytes(), self.before)
        self.assertEqual(self.path.read_text(), self.original)

    def test_changed_head_downloads_exact_revision_and_updates_state_after_apply(self) -> None:
        self.source_head.return_value = "b" * 40
        new_url = f"https://github.com/{self.repo}/blob/master/{self.cve}/new.py"
        with patch.object(sync_collections, "download", return_value=b"archive") as download, \
             patch.object(sync_collections, "collect", return_value={self.cve: [new_url]}):
            self.assertEqual(sync_collections.main(), 0)
            download.assert_called_once_with(self.repo, "b" * 40)
        saved = json.loads(self.state_file.read_text())
        self.assertEqual(saved["sources"][self.repo]["revision"], "b" * 40)
        self.assertEqual(saved["sources"][self.repo]["links"], {self.cve: [new_url]})
        self.assertIn(new_url, self.path.read_text())
        self.assertNotIn(self.url, self.path.read_text())

    def test_parser_version_change_reparses_unchanged_head(self) -> None:
        with patch.object(sync_collections, "SOURCE_CACHE_VERSION", 2), \
             patch.object(sync_collections, "download", return_value=b"archive") as download, \
             patch.object(sync_collections, "collect", return_value=self.links):
            self.assertEqual(sync_collections.main(), 0)
            download.assert_called_once_with(self.repo, self.revision)
        self.assertEqual(json.loads(self.state_file.read_text())["version"], 2)

    def test_review_changes_invalidate_only_the_affected_source(self) -> None:
        row = {"repository": self.repo, "cve": self.cve, "path": "poc.py", "sha256": "c" * 64}
        with patch.object(sync_collections, "download", return_value=b"archive") as download, \
             patch.object(sync_collections, "collect", return_value=self.links):
            self.reviews.return_value = [{**row, "repository": "unrelated/poc"}]
            self.assertEqual(sync_collections.main(), 0)
            download.assert_not_called()
            self.reviews.return_value.append(row)
            self.assertEqual(sync_collections.main(), 0)
            download.assert_called_once_with(self.repo, self.revision)
            download.reset_mock()
            self.assertEqual(sync_collections.main(), 0)
            download.assert_not_called()
            self.reviews.return_value = []
            self.assertEqual(sync_collections.main(), 0)
            download.assert_called_once_with(self.repo, self.revision)

    def test_unchanged_tree_skips_download_but_invalid_cache_is_rebuilt(self) -> None:
        repo = "google/security-research"
        path = f"pocs/linux/{self.cve}/exploit.c"
        url = f"https://github.com/{repo}/tree/master/pocs/linux/{self.cve}"
        entry = {"revision": self.revision, "branch": "master", "prefix": "pocs/", "links": {self.cve: [url]}}
        self.state = {"version": 1, "sources": {repo: entry}}
        self.state_file.write_text(json.dumps(self.state) + "\n")
        with patch.object(sync_collections, "SOURCES", ()), \
             patch.object(sync_collections, "TREE_SOURCES", (("google", repo, "master", "pocs/"),)), \
             patch.object(sync_collections, "download_tree", return_value=ResearchCollectionTests().tree(path)) as download:
            self.assertEqual(sync_collections.main(), 0)
            download.assert_not_called()
            entry["links"] = {self.cve: ["https://example.com/unrelated"]}
            self.state_file.write_text(json.dumps(self.state) + "\n")
            self.assertEqual(sync_collections.main(), 0)
            download.assert_called_once_with(repo, self.revision)
        self.assertEqual(json.loads(self.state_file.read_text())["sources"][repo]["links"], {self.cve: [url]})

    def test_empty_or_failed_source_preserves_state_and_corpus(self) -> None:
        self.source_head.return_value = "b" * 40
        for result in ({}, RuntimeError("source unavailable")):
            self.ensure_cve_entries.reset_mock()
            with self.subTest(result=result), \
                 patch.object(sync_collections, "download", return_value=b"archive"), \
                 patch.object(sync_collections, "collect", **(
                     {"side_effect": result} if isinstance(result, Exception) else {"return_value": result}
                 )):
                self.assertEqual(sync_collections.main(), 1)
                self.ensure_cve_entries.assert_not_called()
                self.assertEqual(self.state_file.read_bytes(), self.before)
                self.assertEqual(self.path.read_text(), self.original)

    def test_later_truncated_tree_preserves_earlier_source_state_and_corpus(self) -> None:
        self.source_head.return_value = "b" * 40
        with patch.object(sync_collections, "TREE_SOURCES", (("google", "google/security-research", "master", "pocs/"),)), \
             patch.object(sync_collections, "download", return_value=b"archive"), \
             patch.object(sync_collections, "collect", return_value=self.links), \
             patch.object(sync_collections, "download_tree", return_value={"truncated": True, "tree": []}) as download_tree:
            self.assertEqual(sync_collections.main(), 1)
            download_tree.assert_called_once_with("google/security-research", "b" * 40)
        self.ensure_cve_entries.assert_not_called()
        self.assertEqual(self.state_file.read_bytes(), self.before)
        self.assertEqual(self.path.read_text(), self.original)

    def test_dry_run_and_application_failure_do_not_advance_state(self) -> None:
        self.source_head.return_value = "b" * 40
        with patch.object(sync_collections, "download", return_value=b"archive"), \
             patch.object(sync_collections, "collect", return_value=self.links):
            with patch.object(sys, "argv", ["sync_collections.py", "--dry-run"]):
                self.assertEqual(sync_collections.main(), 0)
            self.release_hook.assert_not_called()
            self.assertEqual(self.state_file.read_bytes(), self.before)
            with patch.object(sync_collections, "apply_links", side_effect=OSError("write failed")):
                with self.assertRaises(OSError):
                    sync_collections.main()
            self.assertEqual(self.state_file.read_bytes(), self.before)
        self.assertEqual(self.path.read_text(), self.original)


if __name__ == "__main__":
    unittest.main()
