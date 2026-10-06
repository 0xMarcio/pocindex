from __future__ import annotations

import copy
import io
import sys
import tempfile
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import build_site
import sync_cve_metadata as metadata
import update_cves


CVE = "CVE-2026-12345"
URL = "https://github.com/advisories/GHSA-abcd-efgh-2345"
SCORE = ["3.1", 8.1, "HIGH", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "CNA", "CVE Program CNA"]


class AdvisoryLifecycleTests(unittest.TestCase):
    def merge(self, entries: dict, cache: dict) -> None:
        with patch.object(metadata, "enrich_fallback_metrics"), patch.object(
            metadata, "load_vendor_entries", return_value={}
        ):
            metadata.merge_enrichment(entries, set(entries), cache)

    def test_revocation_removes_only_github_owned_exploit_evidence(self) -> None:
        for independent in (False, True):
            for withdrawn in (False, True):
                with self.subTest(independent=independent, withdrawn=withdrawn):
                    tags = ["Vendor Advisory", *(["Exploit"] if independent else [])]
                    entries = {CVE: {"advisories": [[URL, tags]]}}
                    self.merge(entries, {"GHSA": [CVE, URL, [], 1]})
                    self.assertTrue(build_site.reference_is_verified_poc(CVE, URL, entries, set()))
                    self.merge(entries, {} if withdrawn else {"GHSA": [CVE, URL, [], 0]})
                    self.assertEqual(
                        build_site.reference_is_verified_poc(CVE, URL, entries, set()), independent
                    )
                    self.assertIn("Vendor Advisory", entries[CVE]["advisories"][0][1])

    def test_legacy_cache_only_advisory_is_removed(self) -> None:
        entries = {CVE: {"advisories": [[URL, ["GitHub Advisory", "Exploit"]]]}}
        self.merge(entries, {})
        self.assertFalse(build_site.reference_is_verified_poc(CVE, URL, entries, set()))
        self.assertFalse(entries[CVE].get("advisories"))

    def test_legacy_mixed_source_evidence_is_preserved(self) -> None:
        entries = {CVE: {"advisories": [[URL, ["Vendor Advisory", "GitHub Advisory", "Exploit"]]]}}
        self.merge(entries, {})
        self.assertEqual(entries[CVE]["advisories"], [[URL, ["Vendor Advisory", "Exploit"]]])

    def test_withdrawal_prunes_only_unverified_github_owned_references(self) -> None:
        cves = [CVE, "CVE-2026-12346", "CVE-2026-12347"]
        entries = {cve: {"advisories": [[URL, ["GitHub Advisory", "Exploit"]]]} for cve in cves}
        entries[cves[2]]["advisories"][0][1].append("Vendor Advisory")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "2026").mkdir()
            for cve in cves:
                (root / "2026" / f"{cve}.md").write_text(
                    "### Description\n\nKeep this description.\n\n### POC\n\n"
                    f"#### Reference\n- {URL}\n- https://example.com/independent\n\n"
                    "#### Github\nNo PoCs found on GitHub currently.\n",
                    encoding="utf-8",
                )
            inventory = root / "references.txt"
            inventory.write_text("".join(f"{cve} - {URL}\n" for cve in cves), encoding="utf-8")
            verified = root / "reference_pocs.txt"
            verified.write_text(f"{cves[1]} - {URL}\n", encoding="utf-8")
            with patch.object(metadata, "CVES", root), patch.object(
                update_cves, "REFERENCE_LIST", inventory
            ), patch.object(update_cves, "VERIFIED_REFERENCE_LIST", verified):
                refreshed = run_sync(entries, [], dry_run=False, fallback=False)
            for index, cve in enumerate(cves):
                text = (root / "2026" / f"{cve}.md").read_text(encoding="utf-8")
                self.assertEqual(URL in text, index != 0)
                self.assertIn("Keep this description.", text)
                self.assertIn("https://example.com/independent", text)
                self.assertEqual(f"{cve} - {URL}" in inventory.read_text(), index != 0)
            self.assertEqual(verified.read_text(), f"{cves[1]} - {URL}\n")
            with patch.object(metadata, "CVES", root), patch.object(
                update_cves, "REFERENCE_LIST", inventory
            ), patch.object(update_cves, "VERIFIED_REFERENCE_LIST", verified):
                run_sync(refreshed, [{"cve": {"id": cves[2], "references": [
                    {"url": URL, "tags": ["Vendor Advisory"]}
                ]}}], dry_run=False, fallback=False)
            self.assertNotIn(URL, (root / "2026" / f"{cves[2]}.md").read_text())
            self.assertNotIn(f"{cves[2]} - {URL}", inventory.read_text())


def run_sync(entries: dict, feed: list, *, full: bool = False, dry_run: bool = True, fallback: bool = True) -> dict:
    with patch.object(metadata, "parse_args", return_value=Namespace(
        full=full, github_full=False, dry_run=dry_run, year=[] if full else [2026]
    )), patch.object(metadata, "sync_github_cache", return_value={}), patch.object(
        metadata, "sync_github_pocs"
    ), patch.object(metadata, "local_cves", return_value=set(entries)), patch.object(
        metadata, "load_advisory_rules", return_value=[]
    ), patch.object(metadata, "load_shards", return_value=copy.deepcopy(entries)), patch.object(
        metadata, "load_feed", return_value=feed
    ), patch.object(metadata, "load_vendor_entries", return_value={}), patch.object(
        metadata, "write_shards", return_value=(1, 0)
    ) as write, patch.object(
        metadata, "enrich_fallback_metrics",
        wraps=metadata.enrich_fallback_metrics if fallback else lambda *args, **kwargs: None,
    ), redirect_stdout(io.StringIO()):
        metadata.main()
    return write.call_args.args[0]


class FallbackLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.old = {CVE: {"cvss": [SCORE], "advisories": [["https://example.com/advisory", ["Vendor Advisory"]]]}}
        self.feed = [{"cve": {"id": CVE, "references": [
            {"url": "https://example.com/advisory", "tags": ["Vendor Advisory"]}
        ]}}]

    def test_failed_or_incomplete_refresh_preserves_scores_in_incremental_and_full_runs(self) -> None:
        for full in (False, True):
            for response in (TimeoutError("Source unavailable"), {}, {"cveMetadata": {"cveId": "CVE-2026-99999"}}):
                with self.subTest(full=full, response=response), patch.object(
                    metadata, "load_json_url",
                    side_effect=response if isinstance(response, Exception) else lambda *args, **kwargs: response,
                ):
                    result = run_sync(self.old, self.feed, full=full)
                    self.assertEqual(result[CVE].get("cvss"), [SCORE])

    def test_confirmed_removal_clears_stale_scores(self) -> None:
        empty_record = {"cveMetadata": {"cveId": CVE, "state": "PUBLISHED"}, "containers": {"cna": {}}}
        for full in (False, True):
            for response in (None, empty_record):
                with self.subTest(full=full, response=response), patch.object(metadata, "load_json_url", return_value=response):
                    result = run_sync(self.old, self.feed, full=full)
                    self.assertNotIn("cvss", result[CVE])

    def test_one_failed_source_keeps_prior_score(self) -> None:
        def fetch(url: str, **kwargs: object) -> None:
            if url.startswith(metadata.VULNRICHMENT_ROOT):
                raise TimeoutError("CISA unavailable")
            return None

        with patch.object(metadata, "load_json_url", side_effect=fetch):
            result = run_sync(self.old, self.feed, full=True)
        self.assertEqual(result[CVE]["cvss"], [SCORE])

    def test_successful_refresh_replaces_prior_score(self) -> None:
        record = {
            "cveMetadata": {"cveId": CVE, "state": "PUBLISHED"},
            "containers": {"cna": {"providerMetadata": {"shortName": "CNA"}, "metrics": [{
                "cvssV3_1": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            }]}},
        }
        with patch.object(metadata, "load_json_url", return_value=record):
            result = run_sync(self.old, self.feed, full=True)
        self.assertEqual([row[1] for row in result[CVE]["cvss"]], [9.8])


if __name__ == "__main__":
    unittest.main()
