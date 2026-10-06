from __future__ import annotations

import copy
import base64
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import releases

NOW = "2026-10-07T12:00:00Z"
CVE = "CVE-2026-12345"
URL = "https://github.com/researcher/CVE-2026-12345"


class ReleaseLedgerTests(unittest.TestCase):
    def test_import_is_unknown_without_observation_and_cannot_become_seen(self):
        ledger = releases.reconcile({}, [(CVE, URL)], import_mode=True, observed_at=NOW)
        row = ledger[releases.key(CVE, URL)]
        self.assertEqual((row["released"], row["basis"]), (None, "unknown"))
        self.assertNotIn("seen", row)
        releases.record(ledger, CVE, URL, {"absent": "2026-10-06T00:00:00Z", "absence_verified": True,
                                        "previous_head": "a" * 40}, observed_at=NOW)
        self.assertEqual(releases.landed(ledger, now=NOW), [])
        self.assertNotIn("seen", row)

    def test_first_observation_is_not_a_release_and_is_immutable(self):
        ledger = {}
        releases.record(ledger, CVE, URL, observed_at="2026-10-01T00:00:00Z")
        releases.record(ledger, CVE, URL, observed_at=NOW)
        row = ledger[releases.key(CVE, URL)]
        self.assertEqual(row["seen"], "2026-10-01T00:00:00Z")
        self.assertEqual(row["basis"], "unknown")

    def test_placeholder_first_real_artifact_and_later_update(self):
        ledger = {}
        evidence = {"created": "2025-01-01T00:00:00Z", "commit": "2026-10-06T10:00:00Z",
                    "commit_verified": True, "sha": "a" * 40, "pushed_at": "2026-10-06T11:00:00Z"}
        row = releases.record(ledger, CVE, URL, evidence, observed_at=NOW)
        self.assertEqual((row["released"], row["basis"]), (evidence["commit"], "commit"))
        row = releases.record(ledger, CVE, URL, {**evidence, "commit": "2026-10-07T11:00:00Z",
                                               "pushed_at": NOW, "sha": "b" * 40}, observed_at=NOW)
        self.assertEqual(row["released"], evidence["commit"])
        self.assertEqual(row["sha"], "a" * 40)

    def test_new_history_method_corrects_later_date_and_identity_without_reobserving(self):
        for imported in (False, True):
            with self.subTest(imported=imported):
                ledger = releases.Ledger()
                old = {"created": "2019-01-01T00:00:00Z", "commit": "2020-01-01T00:00:00Z",
                       "sha": "a" * 40, "commit_verified": True, "history_version": releases.HISTORY_VERSION - 1,
                       "paths": ["exploit-CVE-2020-9999.py"], "rev": "a" * 64, "blobs": ["b" * 40]}
                first = releases.record(ledger, CVE, URL, old, observed_at=NOW, import_mode=imported)
                provenance = first.get("seen"), first.get("imported")
                corrected = {**old, "commit": "2026-10-06T10:00:00Z", "sha": "c" * 40,
                             "history_version": releases.HISTORY_VERSION, "paths": [f"{CVE}.py"],
                             "rev": "d" * 64, "blobs": ["e" * 40]}
                row = releases.record(ledger, CVE, URL, corrected, observed_at=NOW)
                self.assertEqual(row["released"], corrected["commit"])
                for field in ("commit", "sha", "paths", "rev", "blobs", "history_version"):
                    self.assertEqual(row[field], corrected[field])
                self.assertEqual((row.get("seen"), row.get("imported")), provenance)
                # A routine update under the same method is still not a release.
                row = releases.record(ledger, CVE, URL, {**corrected, "commit": "2026-10-07T10:00:00Z",
                                      "paths": ["later.py"], "rev": "f" * 64}, observed_at=NOW)
                self.assertEqual(row["released"], corrected["commit"])
                self.assertEqual(row["paths"], corrected["paths"])

    def test_failed_new_history_method_preserves_valid_prior_evidence(self):
        ledger = releases.Ledger()
        original = {"created": "2019-01-01T00:00:00Z", "commit": "2020-01-01T00:00:00Z",
                    "sha": "a" * 40, "commit_verified": True, "history_version": releases.HISTORY_VERSION - 1,
                    "paths": ["exploit.py"], "rev": "b" * 64, "blobs": ["c" * 40]}
        first = copy.deepcopy(releases.record(ledger, CVE, URL, original, observed_at=NOW))
        row = releases.record(ledger, CVE, URL, {"error": "history failed", "history_version": releases.HISTORY_VERSION,
                    "commit": "2026-10-06T00:00:00Z", "commit_verified": True, "sha": "d" * 40,
                    "created": "2026-10-06T00:00:00Z", "paths": ["different.py"], "checked": NOW}, observed_at=NOW)
        self.assertEqual({k: v for k, v in row.items() if k != "checked"}, first)
        self.assertEqual(row["checked"], NOW)

    def test_unversioned_history_is_corrected_and_older_methods_cannot_restore_it(self):
        ledger = releases.Ledger()
        original = {"commit": "2020-01-01T00:00:00Z", "commit_verified": True,
                    "paths": ["exploit-CVE-2020-9999.py"], "rev": "a" * 64}
        releases.record(ledger, CVE, URL, original, observed_at=NOW, import_mode=True)
        corrected = {"commit": "2026-10-06T00:00:00Z", "commit_verified": True,
                     "history_version": releases.HISTORY_VERSION, "paths": [f"{CVE}.py"], "rev": "b" * 64}
        releases.record(ledger, CVE, URL, corrected, observed_at=NOW)
        for old_version in (None, releases.HISTORY_VERSION - 1):
            row = releases.record(ledger, CVE, URL, {**original, "history_version": old_version}, observed_at=NOW)
            self.assertEqual(row["released"], corrected["commit"])
            self.assertEqual(row["history_version"], releases.HISTORY_VERSION)
            self.assertEqual(row["paths"], corrected["paths"])
            self.assertNotIn("seen", row)

    def test_corrected_identity_clears_copy_relationships_that_no_longer_match(self):
        ledger = releases.Ledger()
        other = URL.replace("researcher", "aaa-copy-owner")
        original = {"commit": "2020-01-01T00:00:00Z", "commit_verified": True,
                    "history_version": releases.HISTORY_VERSION - 1, "rev": "a" * 64, "blobs": ["b" * 40]}
        for url in (URL, other):
            releases.record(ledger, CVE, url, original, observed_at=NOW, import_mode=True)
        releases.resolve_copies(ledger, now=NOW)
        self.assertIn("copy", ledger[releases.key(CVE, URL)])
        releases.record(ledger, CVE, other, {**original, "commit": "2026-10-06T00:00:00Z",
                        "history_version": releases.HISTORY_VERSION, "paths": [f"{CVE}.py"],
                        "rev": "c" * 64, "blobs": ["d" * 40]}, observed_at=NOW)
        releases.resolve_copies(ledger, now=NOW)
        self.assertTrue(all("copy" not in row for row in ledger.values()))
        self.assertEqual(ledger[releases.key(CVE, URL)]["released"], original["commit"])
        self.assertEqual(ledger[releases.key(CVE, other)]["released"], "2026-10-06T00:00:00Z")

    def test_prior_absence_dates_backdated_artifact_but_missing_mapping_does_not(self):
        evidence = {"commit": "2025-01-01T00:00:00Z", "commit_verified": True,
                    "pushed_at": "2026-10-07T11:00:00Z", "seen": NOW,
                    "absent": "2026-10-06T12:00:00Z", "previous_head": "a" * 40}
        self.assertEqual(releases.date_release(evidence, now=NOW), (evidence["commit"], "commit"))
        self.assertEqual(releases.date_release({**evidence, "absence_verified": True}, now=NOW), (NOW, "seen"))
        self.assertEqual(releases.date_release({**evidence, "absence_verified": True, "previous_head": None}, now=NOW),
                         (evidence["commit"], "commit"))

    def test_future_and_after_observation_client_clocks_are_discarded_not_clamped(self):
        for commit in ("2030-01-01T00:00:00Z", "2026-10-07T13:00:00Z", "2026-10-07T11:30:00Z"):
            evidence = {"created": "2020-01-01T00:00:00Z", "commit": commit, "commit_verified": True,
                        "seen": NOW, "pushed_at": "2026-10-07T11:00:00Z"}
            self.assertEqual(releases.date_release(evidence, now=NOW), (evidence["created"], "created"))

    def test_imported_history_uses_repository_creation_lower_bound(self):
        self.assertEqual(releases.date_release({"created": "2026-10-06T00:00:00Z",
                                               "commit": "2023-01-01T00:00:00Z", "commit_verified": True}, now=NOW),
                         ("2026-10-06T00:00:00Z", "created"))

    def test_directory_history_requires_verified_qualifying_artifact(self):
        evidence = {"created": "2020-01-01T00:00:00Z", "commit": "2026-10-06T00:00:00Z"}
        self.assertEqual(releases.date_release(evidence, now=NOW), (evidence["created"], "created"))

    def test_verified_kernelctf_and_poppler_imports_stay_historical(self):
        ledger = {}
        for cve, url, commit in (
            ("CVE-2026-53361", "https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2026-53361_lts", "2026-08-28T08:18:39Z"),
            ("CVE-2025-52885", "https://github.com/github/securitylab/tree/main/SecurityExploits/freedesktop/poppler-CVE-2025-52885", "2025-10-14T12:00:28Z"),
        ):
            row = releases.record(ledger, cve, url, {"commit": commit, "commit_verified": True},
                                  import_mode=True, observed_at=NOW)
            self.assertEqual(row["released"], commit)
            self.assertNotIn("seen", row)
        self.assertEqual(releases.landed(ledger, now=NOW), [])

    def test_tombstone_readdition_never_creates_a_new_observation_or_release(self):
        ledger = releases.reconcile({}, [(CVE, URL)], observed_at="2026-01-01T00:00:00Z")
        ledger = releases.reconcile(ledger, [], observed_at=NOW)
        self.assertIn("gone", ledger[releases.key(CVE, URL)])
        ledger = releases.reconcile(ledger, [(CVE, URL)], evidence={releases.key(CVE, URL): {
            "absent": "2026-10-06T00:00:00Z", "previous_head": "a" * 40, "absence_verified": True,
        }}, observed_at=NOW)
        row = ledger[releases.key(CVE, URL)]
        self.assertEqual(row["seen"], "2026-01-01T00:00:00Z")
        self.assertNotIn("gone", row)
        self.assertIsNone(row["released"])

    def test_renames_and_nontrivial_copies_inherit_without_collapsing_variants(self):
        ledger = {}
        original = {"repo": 12, "rev": "a" * 64, "blobs": ["b" * 40], "created": "2020-01-01T00:00:00Z"}
        first = releases.record(ledger, CVE, URL, original, observed_at=NOW)
        renamed = releases.record(ledger, CVE, URL.replace("researcher", "new-owner"),
                                  {**original, "created": "2026-10-06T00:00:00Z"}, observed_at=NOW)
        self.assertEqual(renamed["released"], first["released"])
        self.assertEqual(renamed["copy"], releases.key(CVE, URL))
        copied = releases.record(ledger, CVE, URL.replace("researcher", "copier"),
                                 {**original, "repo": 13, "created": "2026-10-06T00:00:00Z"}, observed_at=NOW)
        self.assertIn("copy", copied)
        for target in ("cos", "lts", "mitigation"):
            row = releases.record(ledger, CVE, URL + f"/tree/main/{CVE}_{target}",
                                  {"repo": 12, "rev": target}, observed_at=NOW)
            self.assertNotIn("copy", row)

    def test_trivial_blob_matches_do_not_label_foreign_repositories_as_copies(self):
        entries = [{"name": "exploit.py", "oid": "b" * 40, "size": 20}]
        evidence = releases.artifact_identity(entries, ["exploit.py"])
        self.assertNotIn("blobs", evidence)
        ledger = {}
        releases.record(ledger, CVE, URL, evidence, observed_at=NOW)
        row = releases.record(ledger, CVE, URL.replace("researcher", "other"), evidence, observed_at=NOW)
        self.assertNotIn("copy", row)

    def test_errors_are_pending_and_partial_reconciliation_does_not_remove_links(self):
        ledger = releases.reconcile({}, [(CVE, URL)], evidence={releases.key(CVE, URL): {
            "error": "rate limited", "created": "2026-10-06T00:00:00Z"}}, observed_at=NOW)
        self.assertEqual(ledger[releases.key(CVE, URL)]["basis"], "pending")
        self.assertNotIn("absent", ledger[releases.key(CVE, URL)])
        self.assertEqual(releases.reconcile(ledger, [], complete=False, observed_at=NOW), ledger)
        ledger = releases.reconcile(ledger, [(CVE, URL)], observed_at=NOW)
        self.assertEqual(ledger[releases.key(CVE, URL)]["basis"], "pending")
        self.assertIsNone(ledger[releases.key(CVE, URL)]["released"])

    def test_identity_enrichment_of_seeded_rows_detects_copies(self):
        other = URL.replace("researcher", "copy-owner")
        ledger = releases.reconcile({}, [(CVE, URL), (CVE, other)], import_mode=True, observed_at=NOW)
        identity = {"rev": "a" * 64, "blobs": ["b" * 40], "commit": "2020-01-01T00:00:00Z", "commit_verified": True}
        releases.record(ledger, CVE, URL, identity, observed_at=NOW)
        row = releases.record(ledger, CVE, other, {**identity, "created": "2026-10-06T00:00:00Z"}, observed_at=NOW)
        self.assertEqual(row["copy"], releases.key(CVE, URL))
        self.assertEqual(row["released"], identity["commit"])

    def test_batch_copy_resolution_is_independent_of_inspection_order(self):
        other = URL.replace("researcher", "copy-owner")
        results = []
        evidence = {"blobs": ["b" * 40], "rev": "a" * 64, "commit_verified": True,
                    "commit": "2023-01-01T00:00:00Z"}
        for order in ((URL, other), (other, URL)):
            ledger = releases.reconcile({}, [(CVE, URL), (CVE, other)], import_mode=True, observed_at=NOW)
            for url in order:
                releases.record(ledger, CVE, url, {**evidence, "created": (
                    "2020-01-01T00:00:00Z" if url == URL else "2026-10-06T00:00:00Z")}, observed_at=NOW)
            releases.resolve_copies(ledger, now=NOW)
            self.assertNotIn("copy", ledger[releases.key(CVE, URL)])
            self.assertEqual(ledger[releases.key(CVE, other)]["copy"], releases.key(CVE, URL))
            self.assertEqual(ledger[releases.key(CVE, other)]["released"], evidence["commit"])
            results.append(ledger)
        self.assertEqual(*results)

    def test_unknown_matching_row_cannot_steal_dated_original_and_shared_helpers_do_not_collapse_variants(self):
        ledger = releases.Ledger()
        evidence = {"blobs": ["b" * 40], "rev": "a" * 64}
        unknown = URL.replace("researcher", "aaa-unknown")
        releases.record(ledger, CVE, unknown, evidence, import_mode=True, observed_at=NOW)
        releases.record(ledger, CVE, URL, {**evidence, "created": "2020-01-01T00:00:00Z"}, import_mode=True, observed_at=NOW)
        variant = URL + "/tree/main/variant"
        releases.record(ledger, CVE, variant, {"blobs": ["b" * 40, "c" * 40], "rev": "d" * 64}, import_mode=True, observed_at=NOW)
        releases.resolve_copies(ledger, now=NOW)
        self.assertNotIn("copy", ledger[releases.key(CVE, URL)])
        self.assertEqual(ledger[releases.key(CVE, unknown)]["copy"], releases.key(CVE, URL))
        self.assertNotIn("copy", ledger[releases.key(CVE, variant)])

    def test_bulk_uses_distinct_cves_and_repository_identity(self):
        ledger = {}
        for number in range(10000, 10011):
            cve = f"CVE-2026-{number}"
            releases.record(ledger, cve, URL + f"/tree/main/{cve}", {"repo": 12, "sha": "a" * 40,
                            "commit": "2026-10-06T00:00:00Z", "commit_verified": True}, observed_at=NOW)
        releases.mark_bulk(ledger)
        self.assertTrue(all(row.get("bulk") for row in ledger.values()))
        self.assertEqual(releases.landed(ledger, now=NOW), [])

    def test_shards_are_monotonic_immutable_and_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            ledger = releases.reconcile({}, [(CVE, URL)], observed_at=NOW)
            releases.save_ledger(ledger, directory)
            path = directory / "2026.json"
            before, mtime = path.read_bytes(), path.stat().st_mtime_ns
            self.assertEqual(releases.load_ledger(directory), ledger)
            releases.save_ledger(ledger, directory)
            self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), (before, mtime))
            with self.assertRaises(ValueError):
                releases.save_ledger({}, directory)
            changed = copy.deepcopy(ledger)
            changed[releases.key(CVE, URL)]["seen"] = "2026-10-08T00:00:00Z"
            with self.assertRaises(ValueError):
                releases.save_ledger(changed, directory)
            self.assertEqual(path.read_bytes(), before)

    def test_canonical_keys_keep_variant_paths_queries_and_fragments(self):
        self.assertEqual(releases.key(CVE, URL), releases.key(CVE, URL.upper().replace("HTTPS", "https")))
        variants = [URL + f"/tree/main/{CVE}_{variant}" for variant in ("cos", "lts", "mitigation")]
        self.assertEqual(len({releases.key(CVE, url) for url in variants}), 3)
        self.assertNotEqual(releases.key(CVE, variants[0]), releases.key(CVE, variants[0] + "?view=1#payload"))


class ArtifactSelectionTests(unittest.TestCase):
    def test_real_code_is_not_hidden_behind_first_twelve_configs(self):
        entries = [{"name": f"a{index:02}.json", "type": "blob"} for index in range(15)]
        entries += [{"name": name, "type": "blob"} for name in ("setup.py", "README.md", "exploit.py")]
        self.assertEqual(releases.artifact_paths(entries, CVE), ["exploit.py"])

    def test_readme_reproduction_fallback_is_explicit(self):
        entries = [{"name": "README.md", "type": "blob"}]
        self.assertEqual(releases.artifact_paths(entries, CVE), [])
        self.assertEqual(releases.artifact_paths(entries, CVE, readme_path="README.md", readme_qualified=True), ["README.md"])

    def test_paperwork_and_build_edits_keep_content_identity(self):
        entries = [{"name": "exploit.py", "oid": "a" * 40, "size": 1000},
                   {"name": "package.json", "oid": "b" * 40, "size": 1000}]
        before = releases.artifact_identity(entries, releases.artifact_paths(entries, CVE))
        entries[1]["oid"] = "c" * 40
        after = releases.artifact_identity(entries, releases.artifact_paths(entries, CVE))
        self.assertEqual(before, after)
        entries[0]["name"] = "moved.py"
        moved = releases.artifact_identity(entries, releases.artifact_paths(entries, CVE))
        self.assertEqual(before["rev"], moved["rev"])


class PinnedHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.revision, self.stub_sha, self.real_sha = "a" * 40, "b" * 40, "c" * 40
        self.repository = "researcher/CVE-2026-12345"
        self.repo = {"full_name": self.repository, "id": 12, "revision": self.revision,
                     "created_at": "2020-01-01T00:00:00Z", "pushed_at": NOW}
        self.sources = {self.stub_sha: {"exploit.py": b"# Proof of concept will be published here shortly.\n"},
                        self.real_sha: {"exploit.py": b"import requests\ndef exploit():\n    requests.post('http://target/path', data={'payload': 'x'*4096})\n"}}
        self.sources[self.revision] = self.sources[self.real_sha]
        self.details = {self.real_sha: {"files": [{"filename": "exploit.py", "status": "added"}], "parents": []}}
        self.histories = {"exploit.py": [
            {"sha": self.real_sha, "commit": {"committer": {"date": "2026-10-06T10:00:00Z"}}},
            {"sha": self.stub_sha, "commit": {"committer": {"date": "2020-01-01T00:00:00Z"}}},
        ]}
        self.calls = []
        self.history = releases.GitHubHistory({}, fetch=self.fetch)

    def fetch(self, url, **kwargs):
        self.calls.append(url)
        parsed = urlsplit(url)
        path = unquote(parsed.path).split(self.repository, 1)[1]
        if "/git/trees/" in path:
            expression = path.split("/git/trees/", 1)[1]
            revision, _, scope = expression.partition(":")
            tree = []
            for name, source in self.sources[revision].items():
                if scope and not name.startswith(scope + "/"):
                    continue
                oid = hashlib.sha1(f"blob {len(source)}\0".encode() + source).hexdigest()
                tree.append({"path": name[len(scope) + 1:] if scope else name, "sha": oid, "size": len(source), "type": "blob", "mode": "100644"})
            return {"tree": tree, "truncated": False}
        if "/git/blobs/" in path:
            oid = path.rsplit("/", 1)[1]
            for sources in self.sources.values():
                for source in sources.values():
                    if hashlib.sha1(f"blob {len(source)}\0".encode() + source).hexdigest() == oid:
                        return {"encoding": "base64", "content": base64.b64encode(source).decode()}
        if path == "/commits":
            return self.histories[parse_qs(parsed.query)["path"][0]]
        if path.startswith("/commits/"):
            return self.details[path.rsplit("/", 1)[1]]
        raise AssertionError(url)

    def evidence(self, paths=None):
        return releases.current_repository_evidence(self.repo, paths or ["exploit.py"], {}, cve=CVE,
                    cache_dir=self.directory, observed_at=NOW, history=self.history)

    def test_filename_placeholder_does_not_date_first_actual_code(self):
        result = self.evidence()
        self.assertNotIn("error", result)
        self.assertEqual(result["commit"], "2026-10-06T10:00:00Z")
        self.assertEqual(result["sha"], self.real_sha)
        self.assertTrue(result["commit_verified"])
        count = len(self.calls)
        self.assertEqual(self.evidence(), result)
        self.assertEqual(len(self.calls), count)

    def test_history_method_version_invalidates_cached_evidence(self):
        first = self.evidence()
        self.assertEqual(first["history_version"], releases.HISTORY_VERSION)
        with patch.object(releases, "HISTORY_VERSION", releases.HISTORY_VERSION + 1), \
             patch.object(self.history, "introduction", wraps=self.history.introduction) as inspect:
            second = self.evidence()
        inspect.assert_called_once()
        self.assertEqual(second["history_version"], first["history_version"] + 1)
        self.assertEqual(len(list(self.directory.glob("*.json"))), 2)

    def test_historical_function_stub_is_not_the_current_poc_introduction(self):
        self.sources[self.stub_sha]["exploit.py"] = b"# CVE-2026-12345 proof of concept placeholder\nimport requests\ndef exploit():\n    pass\n"
        result = self.evidence()
        self.assertEqual(result["commit"], "2026-10-06T10:00:00Z")
        self.assertEqual(result["sha"], self.real_sha)
        for body in (b"# Placeholder for CVE-2026-12345 exploit\nclass Exploit:\n    pass\n",
                     b"# Placeholder for CVE-2026-12345 exploit\ndef exploit():\n    client.configure()\n"):
            self.assertFalse(releases.qualifying_content(self.repository, CVE, "exploit.py", body, []))

    def test_current_trigger_is_dated_instead_of_an_older_network_helper(self):
        helper = b"import requests\ndef login():\n    return requests.post('https://example.com/login', data={})\n"
        for revision in self.sources:
            self.sources[revision]["client.py"] = helper
        self.histories["client.py"] = [{"sha": self.stub_sha, "commit": {"committer": {"date": "2020-01-01T00:00:00Z"}}}]
        result = self.evidence(["client.py", "exploit.py"])
        self.assertEqual(result["paths"], ["exploit.py"])
        self.assertEqual(result["commit"], "2026-10-06T10:00:00Z")
        self.assertFalse(any("path=client.py" in call for call in self.calls))

    def test_foreign_cve_payload_cannot_date_the_target_cve(self):
        target, foreign = f"{CVE}.py", "exploit-CVE-2020-9999.py"
        body = self.sources[self.real_sha]["exploit.py"]
        self.sources = {self.revision: {target: body, foreign: body},
                        self.real_sha: {target: body, foreign: body}, self.stub_sha: {foreign: body}}
        self.histories = {
            target: [{"sha": self.real_sha, "commit": {"committer": {"date": "2026-10-06T10:00:00Z"}}}],
            foreign: [{"sha": self.stub_sha, "commit": {"committer": {"date": "2020-01-01T00:00:00Z"}}}],
        }
        self.details = {self.real_sha: {"files": [{"filename": target, "status": "added"}], "parents": []},
                        self.stub_sha: {"files": [{"filename": foreign, "status": "added"}], "parents": []}}
        result = self.evidence([target, foreign])
        self.assertEqual(result["commit"], "2026-10-06T10:00:00Z")
        self.assertEqual(result["paths"], [target])
        self.assertEqual(result["history_version"], releases.HISTORY_VERSION)
        self.assertFalse(any("path=exploit-CVE-2020-9999.py" in call for call in self.calls))

    def test_only_exact_reviewed_exception_overrides_foreign_path(self):
        path = "CVE-2020-9999/poc.py"
        body = self.sources[self.real_sha]["exploit.py"]
        self.assertFalse(releases.qualifying_content(self.repository, CVE, path, body, []))
        review = {"cve": CVE, "repository": self.repository, "path": path,
                  "sha256": hashlib.sha256(body).hexdigest()}
        self.assertTrue(releases.qualifying_content(self.repository, CVE, path, body, [review]))
        self.assertFalse(releases.qualifying_content(self.repository, CVE, path, body + b"\n", [review]))

    def test_readme_reproducer_is_verified_at_its_first_actual_payload(self):
        source = b"# CVE-2026-12345\n## Proof of concept\n```sh\ncurl -X POST http://target/vulnerable -d 'payload=AAAAAAAAAAAAAAAAAAAAAAAA'\n```\n"
        self.sources = {self.stub_sha: {"README.md": b"# CVE-2026-12345\nA PoC will be released here soon."},
                        self.real_sha: {"README.md": source}, self.revision: {"README.md": source}}
        self.histories["README.md"] = self.histories.pop("exploit.py")
        self.details[self.real_sha]["files"][0]["filename"] = "README.md"
        result = self.evidence(["README.md"])
        self.assertNotIn("error", result)
        self.assertEqual(result["sha"], self.real_sha)

    def test_explicit_file_rename_follows_original_history(self):
        old_sha = "d" * 40
        self.sources[old_sha] = {"old.py": self.sources[self.real_sha]["exploit.py"]}
        self.sources[self.stub_sha] = self.sources[old_sha]
        self.histories["exploit.py"] = self.histories["exploit.py"][:1]
        self.histories["old.py"] = [{"sha": old_sha, "commit": {"committer": {"date": "2021-02-03T00:00:00Z"}}}]
        self.details[self.real_sha] = {"files": [{"filename": "exploit.py", "status": "renamed", "previous_filename": "old.py"}], "parents": [{"sha": self.stub_sha}]}
        self.details[old_sha] = {"files": [{"filename": "old.py", "status": "added"}], "parents": []}
        self.assertEqual(self.evidence()["commit"], "2021-02-03T00:00:00Z")

    def test_rename_from_foreign_cve_path_dates_first_qualifying_current_path(self):
        cve = "CVE-2025-71384"
        target, foreign = cve + "-PoC.py", "CVE-2026-71384-PoC.py"
        body = self.sources[self.real_sha]["exploit.py"]
        self.sources = {self.revision: {target: body}, self.real_sha: {target: body}, self.stub_sha: {foreign: body}}
        self.histories = {
            target: [{"sha": self.real_sha, "commit": {"committer": {"date": "2026-07-02T12:29:05Z"}}}],
            foreign: [{"sha": self.stub_sha, "commit": {"committer": {"date": "2026-07-01T20:34:09Z"}}}],
        }
        self.details[self.real_sha] = {"files": [{"filename": target, "status": "renamed", "previous_filename": foreign}],
                                       "parents": [{"sha": self.stub_sha}]}
        result = releases.current_repository_evidence(self.repo, [target], {}, cve=cve,
                    cache_dir=self.directory, observed_at=NOW, history=self.history)
        self.assertNotIn("error", result)
        self.assertEqual(result["commit"], "2026-07-02T12:29:05Z")
        self.assertEqual(result["history_paths"], [target])
        self.assertFalse(any("path=" + foreign in call for call in self.calls))

    def test_failed_rename_parent_qualification_stays_pending(self):
        self.sources[self.stub_sha] = {"old.py": self.sources[self.real_sha]["exploit.py"]}
        self.histories["exploit.py"] = self.histories["exploit.py"][:1]
        self.details[self.real_sha] = {"files": [{"filename": "exploit.py", "status": "renamed", "previous_filename": "old.py"}],
                                       "parents": [{"sha": self.stub_sha}]}
        qualify = self.history.qualifying

        def inspect(repository, revision, paths, cve):
            if revision == self.stub_sha:
                raise TimeoutError("rename parent unavailable")
            return qualify(repository, revision, paths, cve)

        with patch.object(self.history, "qualifying", side_effect=inspect):
            result = self.evidence()
        self.assertIn("rename parent unavailable", result.get("error", ""))
        self.assertNotIn("commit_verified", result)
        self.assertEqual(list(self.directory.glob("*.json")), [])

    def test_failed_or_truncated_history_never_becomes_absence_or_cached_success(self):
        for issue in ({"tree": [], "truncated": True}, RuntimeError("rate limit")):
            with patch.object(self.history, "fetch", **({"side_effect": issue} if isinstance(issue, Exception) else {"return_value": issue})):
                self.history.cache.clear()
                result = self.evidence()
            self.assertIn("error", result)
            self.assertNotIn("absence_verified", result)
            self.assertEqual(list(self.directory.glob("*.json")), [])

    def test_exact_prior_tree_absence_requires_a_complete_tree(self):
        self.assertFalse(self.history.absent(self.repository, self.stub_sha, ["exploit.py"]))
        self.assertTrue(self.history.absent(self.repository, self.stub_sha, ["new.py"]))
        self.history.cache.clear()
        with patch.object(self.history, "fetch", return_value={"tree": [], "truncated": True}):
            with self.assertRaises(ValueError):
                self.history.absent(self.repository, self.stub_sha, ["new.py"])

    def test_request_budget_is_finite_and_exhaustion_remains_pending(self):
        result = releases.current_repository_evidence(self.repo, ["exploit.py"], {}, cve=CVE,
                    cache_dir=self.directory, observed_at=NOW, history=self.history, max_requests=1)
        self.assertIn("budget exhausted", result["error"])
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(list(self.directory.glob("*.json")), [])

    def test_expired_time_budget_makes_no_network_request(self):
        self.history.begin(budget_seconds=1)
        with patch.object(releases.time, "monotonic", return_value=self.history.budget.deadline + 1):
            with self.assertRaises(TimeoutError):
                self.history.get("/repos/example/repo")
        self.assertEqual(self.calls, [])


class CollectionReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.repository = "google/security-research"
        self.url = f"https://github.com/{self.repository}/tree/master/pocs/{CVE}"
        self.previous = {"sources": {self.repository: {"revision": "a" * 40,
                         "observed_at": "2026-10-06T00:00:00Z", "links": {}, "branch": "master"}}}
        self.current = {"sources": {self.repository: {"revision": "b" * 40,
                        "observed_at": NOW, "links": {CVE: [self.url]}, "branch": "master"}}}
        self.history = Mock()
        self.history.get.return_value = {"id": 12, "full_name": self.repository, "created_at": "2020-01-01T00:00:00Z"}
        self.evidence = {"paths": [f"pocs/{CVE}/exploit.c"], "commit": "2025-01-01T00:00:00Z", "commit_verified": True}

    def snapshot(self, *, limit=8):
        releases.record_collection_snapshot(self.previous, self.current, [(CVE, self.url)],
                    directory=self.directory, observed_at=NOW, history=self.history, limit=limit)
        return releases.load_ledger(self.directory)[releases.key(CVE, self.url)]

    def test_missing_old_mapping_is_not_absence_when_prior_artifact_exists(self):
        self.history.absent.return_value = False
        with patch.object(releases, "current_repository_evidence", return_value=self.evidence):
            row = self.snapshot()
        self.assertEqual(row["released"], self.evidence["commit"])
        self.assertFalse(row["absence_verified"])
        self.history.absent.assert_called_once_with(self.repository, "a" * 40, self.evidence["paths"])

    def test_exact_prior_head_absence_dates_new_backdated_artifact(self):
        self.history.absent.return_value = True
        with patch.object(releases, "current_repository_evidence", return_value=self.evidence):
            row = self.snapshot()
        self.assertEqual((row["released"], row["basis"]), (NOW, "seen"))

    def test_deferred_lookup_retries_original_absence_after_source_head_advances(self):
        with patch.object(releases, "current_repository_evidence") as helper:
            row = self.snapshot(limit=0)
            helper.assert_not_called()
        self.assertEqual(row["basis"], "pending")
        self.previous = copy.deepcopy(self.current)
        self.history.absent.return_value = True
        with patch.object(releases, "current_repository_evidence", return_value=self.evidence):
            row = self.snapshot()
        self.assertEqual((row["released"], row["basis"]), (NOW, "seen"))
        self.history.absent.assert_called_once_with(self.repository, "a" * 40, self.evidence["paths"])

    def test_initial_snapshot_and_later_available_cve_are_historical(self):
        for previous in ({"sources": {}}, self.current):
            with self.subTest(previous=previous), tempfile.TemporaryDirectory() as temporary:
                self.directory = Path(temporary)
                self.previous = previous
                with patch.object(releases, "current_repository_evidence", return_value=self.evidence):
                    row = self.snapshot()
                self.assertTrue(row["imported"])
                self.assertNotIn("seen", row)
                self.assertEqual(row["released"], self.evidence["commit"])

    def test_unchanged_collection_preserves_independent_reference_paths(self):
        reference = self.url.replace("/pocs/", "/research/")
        ledger = releases.Ledger()
        releases.record(ledger, CVE, reference, import_mode=True, observed_at=NOW)
        releases.save_ledger(ledger, self.directory)
        with patch.object(releases, "published_pairs") as published:
            self.snapshot(limit=0)
        self.assertNotIn("gone", releases.load_ledger(self.directory)[releases.key(CVE, reference)])
        published.assert_not_called()

    def test_removed_collection_link_remains_active_when_another_source_publishes_it(self):
        shared, removed = self.url + "-shared", self.url + "-removed"
        self.previous["sources"][self.repository]["links"] = {CVE: [self.url, shared, removed]}
        ledger = releases.Ledger()
        for url in (shared, removed):
            releases.record(ledger, CVE, url, import_mode=True, observed_at=NOW)
        releases.save_ledger(ledger, self.directory)
        with patch.object(releases, "published_pairs", return_value=[(CVE, self.url), (CVE, shared)]):
            self.snapshot(limit=0)
        ledger = releases.load_ledger(self.directory)
        self.assertNotIn("gone", ledger[releases.key(CVE, shared)])
        self.assertEqual(ledger[releases.key(CVE, removed)]["gone"], NOW)

    def test_pending_checks_rotate_unattempted_then_oldest_attempt(self):
        cves = [CVE, "CVE-2026-12346", "CVE-2026-12347"]
        pairs = [(cve, self.url.replace(CVE, cve)) for cve in cves]
        ledger = releases.Ledger()
        for (cve, url), checked in zip(pairs, ("2026-10-07T06:00:00Z", "2026-10-07T00:00:00Z", None)):
            evidence = {"error": "pending", **({"checked": checked} if checked else {})}
            releases.record(ledger, cve, url, evidence, observed_at=NOW, import_mode=True)
        releases.save_ledger(ledger, self.directory)
        with patch.object(releases, "current_repository_evidence", return_value={"error": "still pending"}) as inspect:
            for hour in (12, 18, 23):
                releases.record_collection_snapshot(self.previous, self.current, pairs, directory=self.directory,
                            observed_at=f"2026-10-07T{hour}:00:00Z", history=self.history, limit=1)
        self.assertEqual([call.kwargs["cve"] for call in inspect.call_args_list], list(reversed(cves)))

    def test_metadata_failure_records_attempt_but_deferred_work_does_not(self):
        other = "CVE-2026-12346"
        pairs = [(CVE, self.url), (other, self.url.replace(CVE, other))]
        self.history.get.side_effect = TimeoutError("metadata timed out")
        with patch.object(releases, "current_repository_evidence") as inspect:
            releases.record_collection_snapshot(self.previous, self.current, pairs, directory=self.directory,
                        observed_at=NOW, history=self.history, limit=1)
        inspect.assert_not_called()
        ledger = releases.load_ledger(self.directory)
        attempted, deferred = (ledger[releases.key(*pair)] for pair in pairs)
        self.assertEqual(attempted.get("checked"), NOW)
        self.assertEqual(attempted.get("head"), "b" * 40)
        self.assertNotIn("checked", deferred)
        self.assertTrue(all(row["basis"] == "pending" and row["released"] is None for row in ledger.values()))


if __name__ == "__main__":
    unittest.main()
