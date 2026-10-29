from __future__ import annotations

import copy
import gzip
import io
import json
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
import sync_reference_pocs as references
import update_cves


CVE = "CVE-2026-12345"
URL = "https://github.com/advisories/GHSA-abcd-efgh-2345"
SCORE = ["3.1", 8.1, "HIGH", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "CNA", "CVE Program CNA"]


class FeedDownloadTests(unittest.TestCase):
    @staticmethod
    def response(body, headers, status=200):
        response = io.BytesIO(body)
        response.headers = headers
        response.status = status
        return response

    def setUp(self):
        self.feed = [{"cve": {"id": CVE}}]
        self.body = gzip.compress(json.dumps({"format": "NVD_CVE", "version": "2.0",
                                              "totalResults": 1, "vulnerabilities": self.feed}).encode())

    def test_cached_feed_is_reused_by_reference_discovery_without_network(self):
        url = "https://gist.github.com/researcher/1fe3fe58dd275edb77dcbe890fce2f2c"
        rows = [{"cve": {"id": CVE, "references": [{"url": url, "tags": ["Exploit"]}]}}]
        body = gzip.compress(json.dumps({"format": "NVD_CVE", "version": "2.0",
                                        "totalResults": 1, "vulnerabilities": rows}).encode())
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            with patch.object(metadata.urllib.request, "urlopen", return_value=io.BytesIO(body)) as fetch:
                self.assertEqual(metadata.load_feed("modified", cache_dir=cache), rows)
            fetch.assert_called_once()
            with patch.object(references.Budget, "read", side_effect=AssertionError("duplicate download")):
                self.assertEqual(references.load_feeds(cache), {CVE: [url]})

    def test_incomplete_feed_does_not_replace_cached_feed(self):
        body = gzip.compress(json.dumps({"format": "NVD_CVE", "version": "2.0",
                                        "totalResults": 2, "vulnerabilities": self.feed}).encode())
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            path = cache / "nvd-modified.json.gz"
            path.write_bytes(self.body)
            with patch.object(metadata.urllib.request, "urlopen", return_value=io.BytesIO(body)):
                with self.assertRaisesRegex(RuntimeError, "incomplete NVD"):
                    metadata.load_feed("modified", cache_dir=cache)
            self.assertEqual(path.read_bytes(), self.body)

    def test_truncated_gzip_restarts_download_and_returns_complete_feed(self):
        with patch.object(metadata.urllib.request, "urlopen", side_effect=[
            io.BytesIO(self.body[:-8]), io.BytesIO(self.body)
        ]) as fetch, patch.object(metadata.time, "sleep"), redirect_stdout(io.StringIO()):
            self.assertEqual(metadata.load_feed("modified"), self.feed)
        self.assertEqual(fetch.call_count, 2)

    def test_interrupted_transfer_resumes_only_the_same_feed_version(self):
        offset = len(self.body) - 8
        responses = [
            self.response(self.body[:offset], {"Content-Length": str(len(self.body)), "ETag": '"v1"'}),
            self.response(self.body[offset:], {"Content-Range": f"bytes {offset}-{len(self.body)-1}/{len(self.body)}", "ETag": '"v1"'}, 206),
        ]
        with patch.object(metadata.urllib.request, "urlopen", side_effect=responses) as fetch, \
                patch.object(metadata.time, "sleep"), redirect_stdout(io.StringIO()):
            self.assertEqual(metadata.load_feed("modified"), self.feed)
        self.assertEqual(fetch.call_args_list[1].args[0].get_header("Range"), f"bytes={offset}-")
        self.assertEqual(fetch.call_args_list[1].args[0].get_header("If-range"), '"v1"')

    def test_changed_feed_replaces_partial_download(self):
        rows = [{"cve": {"id": "CVE-2026-54321"}}]
        newer = gzip.compress(json.dumps({"format": "NVD_CVE", "version": "2.0",
                                         "totalResults": 1, "vulnerabilities": rows}).encode())
        responses = [
            self.response(self.body[:-8], {"Content-Length": str(len(self.body)), "ETag": '"v1"'}),
            self.response(newer, {"Content-Length": str(len(newer)), "ETag": '"v2"'}),
        ]
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            with patch.object(metadata.urllib.request, "urlopen", side_effect=responses), \
                    patch.object(metadata.time, "sleep"), redirect_stdout(io.StringIO()):
                self.assertEqual(metadata.load_feed("modified", cache_dir=cache), rows)
            self.assertEqual((cache / "nvd-modified.json.gz").read_bytes(), newer)

    def test_mismatched_resumed_response_restarts_without_using_its_bytes(self):
        offset = len(self.body) - 8
        for span, etag in [(f"bytes 0-{len(self.body)-1}/{len(self.body)}", '"v1"'),
                           (f"bytes {offset}-{len(self.body)-1}/{len(self.body)}", '"v2"')]:
            responses = [
                self.response(self.body[:offset], {"Content-Length": str(len(self.body)), "ETag": '"v1"'}),
                self.response(self.body[offset:], {"Content-Range": span, "ETag": etag}, 206),
                self.response(self.body, {}),
            ]
            with patch.object(metadata.urllib.request, "urlopen", side_effect=responses) as fetch, \
                    patch.object(metadata.time, "sleep"), redirect_stdout(io.StringIO()):
                self.assertEqual(metadata.load_feed("modified"), self.feed)
            self.assertIsNone(fetch.call_args_list[2].args[0].get_header("Range"))

    def test_range_not_satisfiable_restarts_but_other_client_errors_do_not(self):
        for code in (416, 401, 403, 404):
            responses = [
                self.response(self.body[:-8], {"Content-Length": str(len(self.body)), "ETag": '"v1"'}),
                metadata.urllib.error.HTTPError(metadata.feed_url("modified"), code, "rejected", {}, None),
                self.response(self.body, {}),
            ]
            with patch.object(metadata.urllib.request, "urlopen", side_effect=responses) as fetch, \
                    patch.object(metadata.time, "sleep"), redirect_stdout(io.StringIO()):
                if code == 416:
                    self.assertEqual(metadata.load_feed("modified"), self.feed)
                    self.assertIsNone(fetch.call_args_list[2].args[0].get_header("Range"))
                else:
                    with self.assertRaises(metadata.urllib.error.HTTPError):
                        metadata.load_feed("modified")
                    self.assertEqual(fetch.call_count, 2)

    def test_corrupt_resumed_gzip_restarts_before_caching(self):
        offset = len(self.body) - 8
        trailer = bytes([self.body[offset] ^ 1]) + self.body[offset + 1:]
        responses = [
            self.response(self.body[:offset], {"Content-Length": str(len(self.body)), "ETag": '"v1"'}),
            self.response(trailer, {"Content-Range": f"bytes {offset}-{len(self.body)-1}/{len(self.body)}", "ETag": '"v1"'}, 206),
            self.response(self.body, {}),
        ]
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            with patch.object(metadata.urllib.request, "urlopen", side_effect=responses) as fetch, \
                    patch.object(metadata.time, "sleep"), redirect_stdout(io.StringIO()):
                self.assertEqual(metadata.load_feed("modified", cache_dir=cache), self.feed)
            self.assertEqual((cache / "nvd-modified.json.gz").read_bytes(), self.body)
            self.assertIsNone(fetch.call_args_list[2].args[0].get_header("Range"))

    def test_partial_feed_without_strong_validator_restarts(self):
        for etag in (None, 'W/"v1"'):
            headers = {"Content-Length": str(len(self.body))}
            if etag:
                headers["ETag"] = etag
            responses = [self.response(self.body[:-8], headers), self.response(self.body, {})]
            with patch.object(metadata.urllib.request, "urlopen", side_effect=responses) as fetch, \
                    patch.object(metadata.time, "sleep"), redirect_stdout(io.StringIO()):
                self.assertEqual(metadata.load_feed("modified"), self.feed)
            self.assertIsNone(fetch.call_args_list[1].args[0].get_header("Range"))
            self.assertIsNone(fetch.call_args_list[1].args[0].get_header("If-range"))

    def test_repeated_truncation_fails_instead_of_publishing_partial_feed(self):
        with patch.object(metadata.urllib.request, "urlopen", side_effect=[
            io.BytesIO(self.body[:-8]) for _ in range(3)
        ]) as fetch, patch.object(metadata.time, "sleep"), redirect_stdout(io.StringIO()):
            with self.assertRaises(EOFError):
                metadata.load_feed("modified")
        self.assertEqual(fetch.call_count, 3)

    def test_missing_feed_is_not_retried(self):
        problem = metadata.urllib.error.HTTPError(metadata.feed_url("recent"), 404, "missing", {}, None)
        with patch.object(metadata.urllib.request, "urlopen", side_effect=problem) as fetch:
            with self.assertRaises(metadata.urllib.error.HTTPError):
                metadata.load_feed("recent")
        self.assertEqual(fetch.call_count, 1)


class DiscoveryEnrichmentTests(unittest.TestCase):
    def test_cna_and_adp_references_publish_without_nvd_or_poc_promotion(self):
        report = "https://research.example/report"
        product = "https://github.com/payloadcms/payload"
        patch_url = "https://github.com/vendor/product/commit/1234"
        record = {"cveMetadata": {"cveId": CVE, "state": "PUBLISHED"}, "containers": {
            "cna": {"references": [
                {"url": report, "tags": ["third-party-advisory"]},
                {"url": product, "tags": ["product"]},
                {"url": "javascript:alert(1)"},
                {"url": "https://user:password@example.org/private"},
                {"url": "https://[invalid"},
            ]},
            "adp": [{"references": [
                {"url": report}, {"url": patch_url, "tags": ["patch"]},
                {"url": "https://research.example/reproduction", "tags": ["exploit"]},
            ]}],
        }}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "2026.json"
            metadata.record_metrics({CVE: record}, dry_run=False, output=Path(directory))
            saved = json.loads(path.read_text())
            refs = dict(saved[CVE]["cve_references"])
            self.assertEqual(len(refs), 4)
            self.assertEqual(refs[report], ["Third Party Advisory", "CVE Record"])
            self.assertEqual(refs[product], ["Product", "CVE Record"])
            self.assertEqual(refs[patch_url], ["Patch", "CVE Record"])
            for url in refs:
                self.assertFalse(build_site.reference_is_verified_poc(CVE, url, saved, set()))
            with patch.object(build_site, "load_metadata", return_value=saved):
                published = build_site.build_metadata([{"cve": CVE}])
            self.assertEqual(dict(published[CVE]["advisories"]), refs)

    def test_cna_reference_correction_does_not_remove_nvd_references(self):
        record = {"cveMetadata": {"cveId": CVE, "state": "PUBLISHED"},
                  "containers": {"cna": {"references": []}}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "2026.json"
            stored = {CVE: {"advisories": [[URL, ["GitHub Advisory"]]],
                            "cve_references": [["https://old.example/report", ["CVE Record"]]]}}
            path.write_text(json.dumps(stored))
            pending = copy.deepcopy(record)
            pending["cveMetadata"]["state"] = "RESERVED"
            self.assertEqual(metadata.record_metrics({CVE: pending}, dry_run=False, output=Path(directory)), 0)
            incomplete = copy.deepcopy(record)
            incomplete["containers"]["cna"].pop("references")
            self.assertEqual(metadata.record_metrics({CVE: incomplete}, dry_run=False, output=Path(directory)), 0)
            metadata.record_metrics({CVE: record}, dry_run=False, output=Path(directory))
            self.assertEqual(json.loads(path.read_text()), {CVE: {"advisories": stored[CVE]["advisories"]}})

    def test_nvd_refresh_retains_cna_references_unless_cve_rejected(self):
        refs = [["https://research.example/report", ["CVE Record"]]]
        for rejected in (False, True):
            entries = {CVE: {"rejected": True} if rejected else {"cvss": [SCORE]}}
            with patch.object(metadata, "enrich_fallback_metrics"), patch.object(metadata, "load_vendor_entries", return_value={}):
                metadata.merge_enrichment(entries, {CVE}, {}, {CVE: {"cve_references": refs}})
            self.assertEqual(entries[CVE].get("cve_references"), None if rejected else refs)

    def test_successful_cna_references_survive_other_fallback_failure(self):
        record = {"cveMetadata": {"cveId": CVE, "state": "PUBLISHED"},
                  "containers": {"cna": {"references": [{"url": "https://research.example/report"}]}}}
        entries = {CVE: {}}
        with patch.object(metadata, "load_json_url", side_effect=[record, OSError("temporary outage")]), redirect_stdout(io.StringIO()):
            metadata.enrich_fallback_metrics(entries, {CVE})
        self.assertEqual(entries[CVE]["cve_references"], [["https://research.example/report", ["CVE Record"]]])

    def test_new_record_scores_publish_without_waiting_for_nvd(self):
        record = {"cveMetadata": {"cveId": CVE, "state": "PUBLISHED"}, "containers": {"cna": {
            "descriptions": [{"lang": "en", "value": "A new vulnerability"}],
            "providerMetadata": {"shortName": "CNA"},
            "metrics": [{"cvssV3_1": {"baseScore": 8.1, "vectorString": SCORE[3]}}],
        }}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "index").mkdir()
            with patch.multiple(update_cves, CVES=root / "cves", INDEX=root / "index",
                                RECORD_STATE_FILE=root / "index/state.json", DATES_FILE=root / "index/dates.json"):
                created, unavailable = update_cves.ensure_cve_entries(
                    {CVE}, dry_run=False, records={CVE: record}, fetch_missing=False)
            self.assertEqual((created, unavailable), ({CVE}, set()))
            saved = json.loads((root / "index/metadata/2026.json").read_text())
            self.assertEqual(saved[CVE]["cvss"], [SCORE])

    def test_cna_correction_preserves_other_providers_and_pending_does_not_erase(self):
        nvd = [*SCORE[:4], "nvd@nist.gov", "Primary"]
        record = {"cveMetadata": {"cveId": CVE, "state": "PUBLISHED"}, "containers": {"cna": {
            "providerMetadata": {"shortName": "CNA"},
            "metrics": [{"cvssV3_1": {"baseScore": 0.0, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}}],
        }}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "2026.json"
            path.write_text(json.dumps({CVE: {"cvss": [SCORE, nvd], "advisories": [[URL, ["Vendor Advisory"]]]}}))
            metadata.record_metrics({CVE: record}, dry_run=False, output=Path(directory))
            saved = path.read_text()
            entry = json.loads(saved)[CVE]
            self.assertIn(nvd, entry["cvss"])
            self.assertNotIn(SCORE, entry["cvss"])
            self.assertEqual(entry["cvss"][1][1:3], [0.0, "NONE"])
            self.assertEqual(entry["advisories"], [[URL, ["Vendor Advisory"]]])
            record["cveMetadata"]["state"] = "RESERVED"
            self.assertEqual(metadata.record_metrics({CVE: record}, dry_run=False, output=Path(directory)), 0)
            self.assertEqual(path.read_text(), saved)


class AdvisoryLifecycleTests(unittest.TestCase):
    def test_reference_status_tags_survive_merge_without_hiding_live_sources(self):
        for nvd_tag, cna_tag in (("Broken Link", "broken-link"), ("Not Applicable", "not-applicable")):
            for tagged_source in ("nvd", "cna"):
                entry = metadata.metadata_entry({"id": CVE, "references": [
                    {"url": URL, "tags": ["Exploit", *([nvd_tag] if tagged_source == "nvd" else [])]}
                ]}, [])
                entry['cve_references'] = metadata.cve_program_references({"containers": {"cna": {"references": [
                    {"url": URL, "tags": [cna_tag] if tagged_source == "cna" else []}
                ]}}})
                with patch.object(build_site, 'load_metadata', return_value={CVE: entry}):
                    published = build_site.build_metadata([{'cve': CVE}])
                    self.assertEqual(bool(published), nvd_tag == 'Broken Link')
                    with patch.object(build_site.link_health, 'unavailable', return_value=True):
                        self.assertEqual(build_site.build_metadata([{'cve': CVE}]), {})
                        self.assertFalse(build_site.reference_is_verified_poc(CVE, URL, {CVE: entry}, {(CVE, URL)}))
                self.assertEqual(build_site.reference_is_verified_poc(CVE, URL, {CVE: entry}, {(CVE, URL)}),
                                 nvd_tag == 'Broken Link')

    def test_exploit_only_reference_keeps_its_published_tag(self) -> None:
        url = "https://github.com/user-attachments/files/24473682/environment_newline_injection.sh"
        entry = metadata.metadata_entry({"id": CVE, "references": [
            {"url": url, "tags": ["Exploit"]},
            {"url": "https://example.com/unclassified", "tags": []},
        ]}, [])
        self.assertEqual(entry, {"advisories": [[url, ["Exploit"]], ["https://example.com/unclassified", ["Reference"]]]})
        self.assertFalse(build_site.reference_is_verified_poc(CVE, "https://example.com/unclassified", {CVE: entry}, set()))

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
        full=full, github_full=False, dry_run=dry_run, year=[] if full else [2026], feed_cache_dir=None
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
