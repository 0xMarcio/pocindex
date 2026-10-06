from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import sync_collections


class ResearchCollectionTests(unittest.TestCase):
    def tree(self, *paths: str) -> dict:
        return {"truncated": False, "tree": [
            {"path": path, "type": "blob", "mode": "100644", "size": 100}
            for path in paths
        ]}

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
             patch.object(sync_collections, "download", return_value=b"archive"), \
             patch.object(sync_collections, "collect", return_value={cid: [old_url]}), \
             patch.object(sync_collections, "download_tree", return_value=payload), \
             patch.object(sync_collections, "ensure_cve_entries", return_value=(set(), set())), \
             patch.object(sync_collections, "apply_links", return_value="unchanged") as apply, \
             patch.object(sync_collections, "CVES") as cves:
            cves.glob.return_value = []
            self.assertEqual(sync_collections.main(), 0)
            apply.assert_called_once_with(cid, sorted([old_url, new_url]), dry_run=False)


if __name__ == "__main__":
    unittest.main()
