from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import update_cves
import build_site
import sync_cve_metadata


class RepositoryClassificationTests(unittest.TestCase):
    def repo(self, name: str, description: str = "", readme: str = "") -> dict:
        return {
            "nameWithOwner": name,
            "url": f"https://github.com/{name}",
            "description": description,
            "isFork": False,
            "isArchived": False,
            "repositoryTopics": {"nodes": []},
            "readmeMd": {"text": readme},
        }

    def test_accepts_cve_named_repository(self) -> None:
        repo = self.repo(
            "AcmeSecurity/CVE-2026-31431-PoC",
            "Proof of concept for Linux privilege escalation",
            "CVE-2026-31431 proof of concept.",
        )
        self.assertEqual(
            update_cves.qualifying_repo_cves(repo, 2026, []),
            {"CVE-2026-31431"},
        )

    def test_rejects_generic_readme_reference(self) -> None:
        repo = self.repo(
            "AcmeSecurity/kernel-notes",
            "Linux security notes",
            "A linked exploit mentions CVE-2026-31431 as a proof of concept.",
        )
        repo["root"] = {"entries": [{"name": "index.js"}]}
        self.assertEqual(update_cves.qualifying_repo_cves(repo, 2026, []), set())

    def test_accepts_readme_poc_with_repository_intent(self) -> None:
        repo = self.repo(
            "AcmeSecurity/kernel-exploits",
            "Linux exploit research",
            "Proof of concept for CVE-2026-31431 with reproduction steps.",
        )
        self.assertEqual(
            update_cves.qualifying_repo_cves(repo, 2026, []),
            {"CVE-2026-31431"},
        )

    def test_rejects_related_repository_links(self) -> None:
        repo = self.repo(
            "AcmeSecurity/CVE-2026-31431-PoC",
            "Proof of concept for CVE-2026-31431",
            "Related exploit: CVE-2026-41940 PoC https://github.com/AcmeSecurity/other",
        )
        self.assertEqual(
            update_cves.qualifying_repo_cves(repo, 2026, []),
            {"CVE-2026-31431"},
        )

    def test_accepts_multiple_pocs_implemented_in_one_repository(self) -> None:
        repo = self.repo(
            "AcmeSecurity/CVE-2026-31431-PoC",
            "Proof of concept for CVE-2026-31431",
            "This repository also includes a proof of concept for CVE-2026-41940.",
        )
        repo["root"] = {"entries": [{"name": "CVE-2026-41940.py"}]}
        self.assertEqual(
            update_cves.qualifying_repo_cves(repo, 2026, []),
            {"CVE-2026-31431", "CVE-2026-41940"},
        )

    def test_rejects_readme_reference_when_repository_names_another_cve(self) -> None:
        repo = self.repo(
            "AcmeSecurity/CVE-2026-20841-PoC",
            "Proof of concept for CVE-2026-20841",
            "The approach resembles the CVE-2016-0856 exploit.",
        )
        repo["repositoryTopics"] = {
            "nodes": [
                {"topic": {"name": "cve-2016-0856"}},
                {"topic": {"name": "cve-2026-20841"}},
            ]
        }
        repo["root"] = {"entries": [{"name": "PoC.md"}]}
        self.assertEqual(update_cves.qualifying_repo_cves(repo, 2016, []), set())
        self.assertEqual(
            update_cves.qualifying_repo_cves(repo, 2026, []),
            {"CVE-2026-20841"},
        )

    def test_rejects_profile_and_checker_repositories(self) -> None:
        profile = self.repo(
            "AcmeSecurity/AcmeSecurity",
            "Security engineer profile",
            "Proof of concept for CVE-2026-31431.",
        )
        checker = self.repo(
            "AcmeSecurity/CVE-2026-31431-checker",
            "Safe vulnerability checker",
            "Checks whether CVE-2026-31431 is present.",
        )
        self.assertEqual(update_cves.qualifying_repo_cves(profile, 2026, []), set())
        self.assertEqual(update_cves.qualifying_repo_cves(checker, 2026, []), set())

    def test_rejects_large_cve_collection(self) -> None:
        entries = "\n".join(
            f"Proof of concept for CVE-2026-{number:04d}"
            for number in range(1000, 1027)
        )
        repo = self.repo("AcmeSecurity/exploit-collection", "Exploit collection", entries)
        self.assertEqual(update_cves.qualifying_repo_cves(repo, 2026, []), set())

    def test_rejects_cve_corpora_and_datasets(self) -> None:
        corpus = self.repo(
            "AcmeSecurity/vulnerability-corpus",
            "Machine-readable PoC corpus",
            "CVE-2026-31431 proof-of-concept metadata.",
        )
        dataset = self.repo(
            "AcmeSecurity/exploit-dataset",
            "CVE exploit dataset",
            "CVE-2026-31431 proof-of-concept metadata.",
        )
        self.assertEqual(update_cves.qualifying_repo_cves(corpus, 2026, []), set())
        self.assertEqual(update_cves.qualifying_repo_cves(dataset, 2026, []), set())

    def test_rejects_poc_indexes_and_defensive_tools(self) -> None:
        index = self.repo(
            "AcmeSecurity/searchpoc",
            "Search for proof-of-concept links by CVE ID",
            "CVE-2026-31431 PoC: https://github.com/example/repository",
        )
        shield = self.repo(
            "AcmeSecurity/http-shield",
            "Blocks exploitation attempts",
            "Protects against CVE-2026-31431 exploit traffic.",
        )
        self.assertEqual(update_cves.qualifying_repo_cves(index, 2026, []), set())
        self.assertEqual(update_cves.qualifying_repo_cves(shield, 2026, []), set())

    def test_keeps_specific_cve_poc_scanner(self) -> None:
        repo = self.repo(
            "AcmeSecurity/CVE-2026-31431-PoC-Scanner",
            "Proof-of-concept scanner for CVE-2026-31431",
        )
        repo["root"] = {"entries": [{"name": "scan.py"}]}
        self.assertEqual(
            update_cves.qualifying_repo_cves(repo, 2026, []),
            {"CVE-2026-31431"},
        )

    def test_blacklist_matches_exact_owner_and_repository(self) -> None:
        blacklist = ["mirror-org/poc-corpus"]
        self.assertTrue(update_cves.is_blacklisted_repo("mirror-org/poc-corpus", blacklist))
        self.assertFalse(update_cves.is_blacklisted_repo("source-org/poc-corpus", blacklist))


class ReferenceAndMarkdownTests(unittest.TestCase):
    def record(self) -> dict:
        return {
            "cveMetadata": {"cveId": "CVE-2026-31431", "state": "PUBLISHED"},
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "Linux kernel vulnerability."}],
                    "affected": [
                        {
                            "product": "Linux",
                            "versions": [{"version": "4.14", "status": "affected"}],
                        }
                    ],
                    "problemTypes": [],
                    "references": [
                        {"url": "https://research.example/copy-fail", "tags": ["exploit"]},
                        {"url": "https://vendor.example/advisory", "tags": ["vendor-advisory"]},
                    ],
                },
                "adp": [
                    {
                        "references": [
                            {
                                "url": "https://database.example/CVE-2026-31431-exploit",
                                "tags": ["exploit"],
                            }
                        ]
                    }
                ],
            },
        }

    def test_uses_cna_and_adp_poc_references(self) -> None:
        self.assertEqual(
            update_cves.poc_references(self.record()),
            [
                "https://research.example/copy-fail",
                "https://database.example/CVE-2026-31431-exploit",
            ],
        )

    def test_excludes_blacklisted_github_references(self) -> None:
        record = self.record()
        record["containers"]["cna"]["references"].append(
            {"url": "https://github.com/AcmeSecurity/poc-index", "tags": ["exploit"]}
        )
        self.assertEqual(
            update_cves.poc_references(record, {"acmesecurity/poc-index"}),
            [
                "https://research.example/copy-fail",
                "https://database.example/CVE-2026-31431-exploit",
            ],
        )

    def test_excludes_explicitly_unaffected_products_and_vendors(self) -> None:
        for versions in ([], [{
            "version": "All",
            "status": "unaffected",
            "changes": [{"at": "2", "status": "unaffected"}],
        }]):
            with self.subTest(versions=versions):
                record = self.record()
                record["containers"]["cna"]["affected"].append({
                    "vendor": "Unaffected vendor",
                    "product": "Unaffected product",
                    "defaultStatus": "unaffected",
                    "versions": versions,
                })
                details = update_cves.details_from_record(record)
                self.assertEqual(details.products, ["Linux"])
                self.assertEqual(details.vendors, [])
                self.assertEqual(details.versions, ["4.14"])

    def test_keeps_products_with_affected_or_incomplete_statuses(self) -> None:
        cases = [
            {"defaultStatus": "affected", "versions": [{"status": "unaffected"}]},
            {"defaultStatus": "unaffected", "versions": [{"status": "affected"}]},
            {"defaultStatus": "unaffected", "versions": [{
                "status": "unaffected", "changes": [{"at": "2", "status": "affected"}],
            }]},
            {"defaultStatus": "unknown", "versions": [{"status": "unaffected"}]},
            {"versions": [{"status": "unaffected"}]},
            {"defaultStatus": "unaffected", "versions": [{"status": "unknown"}]},
            {"defaultStatus": "unaffected", "versions": [{"version": "1"}]},
            {"defaultStatus": "unaffected", "versions": [{
                "status": "unaffected", "changes": [{"at": "2", "status": "unknown"}],
            }]},
            {"defaultStatus": "unaffected", "versions": [{
                "status": "unaffected", "changes": [{"at": "2"}],
            }]},
            {},
        ]
        for statuses in cases:
            with self.subTest(statuses=statuses):
                record = self.record()
                record["containers"]["cna"]["affected"] = [{
                    "vendor": "Example vendor", "product": "Example product", **statuses,
                }]
                details = update_cves.details_from_record(record)
                self.assertEqual(details.products, ["Example product"])
                self.assertEqual(details.vendors, ["Example vendor"])

    def test_preserves_markdown_layout(self) -> None:
        details = update_cves.details_from_record(self.record())
        self.assertIsNotNone(details)
        details.description = "Linux kernel vulnerability. \r\n\tAdditional context.\t"
        markdown = update_cves.build_markdown(
            "CVE-2026-31431",
            details,
            ["https://github.com/AcmeSecurity/CVE-2026-31431-PoC"],
            ["https://research.example/copy-fail"],
        )
        self.assertIn(
            "### [CVE-2026-31431](https://www.cve.org/CVERecord?id=CVE-2026-31431)",
            markdown,
        )
        self.assertIn(
            "### Description\n\nLinux kernel vulnerability.\n    Additional context.",
            markdown,
        )
        self.assertIn("#### Reference\n- https://research.example/copy-fail", markdown)
        self.assertIn(
            "#### Github\n- https://github.com/AcmeSecurity/CVE-2026-31431-PoC",
            markdown,
        )
        self.assertTrue(markdown.endswith("\n"))
        self.assertFalse(markdown.endswith("\n\n"))

    def test_existing_markdown_changes_only_poc_sections(self) -> None:
        original = """### [CVE-2026-31431](https://cve.mitre.org/)
![](existing-badge)

### Description

Keep this description unchanged.

### POC

#### Reference
No PoCs from references.

#### Github
No PoCs found on GitHub currently.

"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "CVE-2026-31431.md"
            path.write_text(original, encoding="utf-8")
            changed = update_cves.update_existing_markdown(
                path,
                ["https://github.com/AcmeSecurity/CVE-2026-31431-PoC"],
                ["https://research.example/copy-fail"],
                dry_run=False,
            )
            updated = path.read_text(encoding="utf-8")
        self.assertTrue(changed)
        self.assertIn("![](existing-badge)", updated)
        self.assertIn("Keep this description unchanged.", updated)
        self.assertIn("#### Reference\n- https://research.example/copy-fail\n\n#### Github", updated)
        self.assertTrue(updated.endswith("\n\n"))


class MetadataSourceTests(unittest.TestCase):
    def test_uses_vector_prefix_when_source_field_is_mislabeled(self) -> None:
        row = sync_cve_metadata.published_metric(
            {
                "version": "3.1",
                "vectorString": "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:N/A:N",
                "baseScore": 4.1,
                "baseSeverity": "MEDIUM",
            },
            "3.1",
            "CISA-ADP",
            "CISA Vulnrichment",
        )
        self.assertIsNotNone(row)
        self.assertEqual(row[:3], ["3.0", 4.1, "MEDIUM"])

    def test_keeps_every_published_cvss_generation(self) -> None:
        record = {
            "containers": {
                "cna": {
                    "providerMetadata": {"shortName": "Acme CNA"},
                    "metrics": [
                        {
                            "cvssV4_0": {
                                "vectorString": "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
                                "baseScore": 6.8,
                                "baseSeverity": "MEDIUM",
                            }
                        },
                        {
                            "cvssV3_1": {
                                "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
                                "baseScore": 5.5,
                                "baseSeverity": "MEDIUM",
                            }
                        },
                        {
                            "cvssV2_0": {
                                "vectorString": "AV:L/AC:L/Au:S/C:N/I:N/A:C",
                                "baseScore": 4.6,
                                "baseSeverity": "MEDIUM",
                            }
                        },
                    ],
                }
            }
        }
        rows = sync_cve_metadata.cve_program_metrics(record)
        self.assertEqual([row[0] for row in rows], ["4.0", "3.1", "2.0"])

    def test_positive_assessment_outranks_conflicting_zero(self) -> None:
        rows = sync_cve_metadata.merge_metrics(
            [[
                "4.0",
                0.0,
                "NONE",
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
                "Wikimedia Foundation",
                "CVE Program CNA",
            ]],
            [[
                "3.1",
                6.1,
                "MEDIUM",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "nvd@nist.gov",
                "Primary",
            ]],
        )
        self.assertEqual(rows[0][1:3], [6.1, "MEDIUM"])

    def test_github_advisory_requires_reproducible_poc_material(self) -> None:
        advisory = """### POC

1. Create `poc.py` with this application:
```python
from pathlib import Path
from nicegui import app, ui
app.add_media_files('/media', Path('media'))
ui.run(port=8080)
```
2. Run `python3 poc.py`.
3. Send `curl http://localhost:8080/media/%2e%2e/etc/hosts`.
"""
        mention = "The reporter says a PoC exists, but no reproduction material was published."
        self.assertTrue(sync_cve_metadata.advisory_has_poc(advisory))
        self.assertFalse(sync_cve_metadata.advisory_has_poc(mention))


class PublishedLinkDeduplicationTests(unittest.TestCase):
    def test_unverified_reference_is_not_a_poc(self) -> None:
        cve_id = "CVE-2024-41968"
        url = "https://cert.vde.com/en/advisories/VDE-2024-047"
        self.assertFalse(build_site.reference_is_verified_poc(cve_id, url, {}, set()))

    def test_exact_exploit_tag_makes_reference_a_poc(self) -> None:
        cve_id = "CVE-2025-66645"
        url = "https://github.com/advisories/GHSA-hxp3-63hc-5366"
        metadata = {
            cve_id: {
                "advisories": [[url, ["GitHub Advisory", "Exploit"]]],
            }
        }
        self.assertTrue(build_site.reference_is_verified_poc(cve_id, url, metadata, set()))

    def test_one_repository_is_one_poc_and_keeps_the_useful_path(self) -> None:
        links = [
            "https://github.com/Helson-S/FuzzyTesting/blob/main/hicolor/cp_dynamic",
            "https://github.com/Helson-S/FuzzyTesting/blob/main/hicolor/cp_dynamic/poc/sample.png",
            "https://github.com/Helson-S/FuzzyTesting/blob/main/hicolor/cp_dynamic/vulDescription.md",
            "https://github.com/AcmeSecurity/CVE-2024-41443",
        ]
        self.assertEqual(
            build_site.dedupe_source_links(links, "CVE-2024-41443"),
            [
                "https://github.com/Helson-S/FuzzyTesting/blob/main/hicolor/cp_dynamic/vulDescription.md",
                "https://github.com/AcmeSecurity/CVE-2024-41443",
            ],
        )

    def test_advisory_deduplication_prefers_exploit_evidence(self) -> None:
        rows = [
            ["https://github.com/Helson-S/FuzzyTesting", ["Product"]],
            [
                "https://github.com/Helson-S/FuzzyTesting/blob/main/vulDescription.md",
                ["Third Party Advisory", "Exploit"],
            ],
        ]
        self.assertEqual(build_site.dedupe_advisories(rows, "CVE-2024-41443"), [rows[1]])

    def test_distinct_global_github_advisories_are_not_merged(self) -> None:
        rows = [
            ["https://github.com/advisories/GHSA-hxp3-63hc-5366", ["GitHub Advisory"]],
            ["https://github.com/advisories/GHSA-5hgx-prqh-5qmp", ["GitHub Advisory"]],
        ]
        self.assertEqual(build_site.dedupe_advisories(rows, "CVE-2025-66645"), rows)


if __name__ == "__main__":
    unittest.main()
