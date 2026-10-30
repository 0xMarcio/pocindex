from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import patch

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

    def test_accepts_readme_poc_with_repository_intent_and_artifact(self) -> None:
        repo = self.repo(
            "AcmeSecurity/kernel-exploits",
            "Linux exploit research",
            "Proof of concept for CVE-2026-31431 with reproduction steps.",
        )
        repo["root"] = {"entries": [{"name": "poc.py", "type": "blob"}]}
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

    def test_poc_artifacts_survive_contextual_description_words(self) -> None:
        for description, path, kind in (
            ("Stored XSS PoC via profile picture upload", "poc.html", "blob"),
            ("Exploit for CVE-2026-31431 (fixed in 2.0)", "exploit", "tree"),
        ):
            with self.subTest(path=path):
                candidate = self.repo("researcher/CVE-2026-31431", description,
                                      f"PoC for CVE-2026-31431. Use {path} to reproduce the issue.")
                candidate["root"] = {"entries": [{"name": path, "type": kind}]}
                self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), {"CVE-2026-31431"})
                candidate["root"] = {"entries": [{"name": "README.md", "type": "blob"}]}
                self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), set())
                candidate["root"] = {"entries": None}
                self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), set())

    def test_non_code_artifacts_do_not_override_defensive_classification(self) -> None:
        cve = "CVE-2026-31431"
        for path, kind in ((f"{cve}.yml", "blob"), (f"{cve}.yar", "blob"), (f"{cve}.md", "blob"),
                           ("poc-notes.txt", "blob"), (cve, "tree"), (f"{cve}.html", "blob")):
            with self.subTest(path=path):
                candidate = self.repo(f"researcher/{cve}-sigma", f"Sigma rule detecting {cve} exploit attempts",
                                      f"Sigma rule for {cve} exploit attempts.\n" + "Detection notes. " * 100)
                candidate["root"] = {"entries": [{"name": path, "type": kind}]}
                self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), set())

    def test_analysis_and_lab_repositories_can_carry_specific_pocs(self) -> None:
        for name, description in [("researcher/widget-poc", "Exploit research and analysis"),
                                  ("researcher/widget-lab", "Vulnerable lab")]:
            candidate = self.repo(name, description + " for CVE-2026-31431",
                                  "PoCs for CVE-2026-31431. Run poc.py to reproduce the issue.")
            candidate["root"] = {"entries": [{"name": "poc.py", "type": "blob"}]}
            self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), {"CVE-2026-31431"})
            candidate["root"] = {"entries": [{"name": "README.md", "type": "blob"}]}
            self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), set())

    def test_defensive_verbs_do_not_claim_exploit_intent(self) -> None:
        for verb in ("Blocks", "Detects", "Mitigates", "Protects", "Prevents"):
            candidate = self.repo("researcher/widget-guard", f"{verb} exploitation of CVE-2026-31431",
                                  "CVE-2026-31431 exploit traffic is blocked.")
            candidate["root"] = {"entries": [{"name": "guard.py", "type": "blob"}]}
            self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), set())

    def test_analysis_exception_does_not_approve_unrelated_readme_cves(self) -> None:
        candidate = self.repo("researcher/widget-analysis", "Exploit analysis",
                              "PoC for CVE-2026-1111, run CVE-2026-1111.py.\n\nNotes on the CVE-2026-2222 exploit chain.")
        candidate["root"] = {"entries": [{"name": "CVE-2026-1111.py", "type": "blob"}]}
        self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), {"CVE-2026-1111"})

    def test_vulnerability_description_does_not_override_specific_poc_evidence(self) -> None:
        cve = "CVE-2026-27607"
        for description in ("Missing post-policy validation in RustFS", "Bypass of file protection checks"):
            for path in ("exploit.js", "poc.js"):
                candidate = self.repo(f"researcher/{cve}", description,
                                      f"# {cve}\n\nProof of concept for {cve}. Run ./{path}.")
                candidate["root"] = {"entries": [{"name": path, "type": "blob"}]}
                self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), {cve})
                candidate["root"] = {"entries": [{"name": "check.js", "type": "blob"}]}
                self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), set())

    def test_cve_named_defensive_code_is_not_poc_evidence(self) -> None:
        cve = "CVE-2026-27607"
        for suffix in ("", "-scanner", "-honeypot"):
            for path in (f"{cve}.js", "exploit_detector.py", "patch.ps1"):
                candidate = self.repo(f"researcher/{cve}{suffix}", "Detects exploitation attempts",
                                      f"{cve}: scans without sending an exploit payload. Run {path}.")
                candidate["root"] = {"entries": [{"name": path, "type": "blob"}]}
                self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), set())

    def test_poc_description_can_qualify_code_with_a_specific_filename(self) -> None:
        cve = "CVE-2026-27607"
        candidate = self.repo(f"researcher/{cve}", "Exploit for missing post-policy validation in RustFS",
                              f"Proof of concept for {cve}. Run ./presign.js.")
        candidate["root"] = {"entries": [{"name": "presign.js", "type": "blob"}]}
        self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), {cve})

    def test_search_queries_are_not_a_poc(self) -> None:
        candidate = self.repo("researcher/CVE-2026-109618-Dorks", "Search queries for PHP hosts",
                              "CVE-2026-109618 exploitation research.\n```\nshodan search product:PHP\n```")
        candidate["root"] = {"entries": [{"name": "README.md", "type": "blob"}]}
        self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), set())

    def test_readme_example_cve_does_not_make_a_general_tool_a_poc(self) -> None:
        candidate = self.repo("researcher/tool", "Search and download public exploits",
                              "Find exploits for CVE-2024-1234 using the tool.")
        candidate["root"] = {"entries": [{"name": "src", "type": "tree"}, {"name": "setup.py", "type": "blob"}]}
        self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2024, []), set())

    def test_readme_only_reproducer_is_kept_without_a_cve_in_metadata(self) -> None:
        candidate = self.repo("researcher/widget-repro", "Widget research",
                              "PoC for CVE-2026-1234:\n```http\nPOST /vulnerable HTTP/1.1\nHost: localhost\n\npayload\n```")
        candidate["root"] = {"entries": [{"name": "README.md", "type": "blob"}]}
        self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), {"CVE-2026-1234"})
        candidate["readmeMd"]["text"] = "PoC for CVE-2026-1234:\n```sh\npython absent_exploit.py localhost\n```"
        self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), set())

    def test_readme_library_usage_is_not_a_reproducer(self) -> None:
        for code in (
            'import asyncio\nfrom cve_parser import gather_sources\n'
            'sources = asyncio.run(gather_sources("CVE-2026-111497"))\nprint(sources)',
            'def classify(cve):\n    return {"cve": cve}\nclassify("CVE-2026-111497")',
            '<?php\nprint("CVE-2026-111497");',
            '# requests.post(target, data=payload)\nprint("CVE-2026-111497")',
            'curl -X POST http://localhost/triage -d \'{"cve":"CVE-2026-111497"}\'',
            'GET /api/cves/CVE-2026-111497/pocs HTTP/1.1\nHost: localhost',
        ):
            with self.subTest(code=code):
                candidate = self.repo("researcher/cve-parser", "",
                                      'Static PoC triage; it never reports "no PoCs".\n```\n' + code + '\n```')
                candidate["root"] = {"entries": [{"name": "src", "type": "tree"}]}
                self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), set())
                candidate["description"] = "Query data for CVE-2026-111497"
                self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), set())

    def test_inline_payload_actions_remain_discoverable(self) -> None:
        for code in (
            'import requests\nrequests.post(target, data=payload)',
            'import socket\nsock.sendall(payload)',
            '#include <string.h>\nint main() { char dst[4]; strcpy(dst, "AAAAAAAAAAAA"); }',
            '<?php\nunserialize($payload);',
            '<script>alert(document.domain)</script>',
            'curl -X POST http://localhost/vulnerable -d payload=AAAAAAAAAAAA',
            'import brotli\nbrotli.decompress(crafted)',
            'from nicegui import app, ui\napp.add_media_files("/media", Path("media"))\nui.run()',
            'import yaml\nyaml.load(open("CVE-2026-1234.yml"))',
            'from redkit.modules import cve_2026_1234\ncve_2026_1234.exploit(target)',
            'import brotli\nprint("CVE-2026-1234")\nbrotli.decompress(crafted)',
            '<?php\nsystem($payload);',
        ):
            with self.subTest(code=code):
                candidate = self.repo("researcher/widget-repro", "",
                                      'PoC for CVE-2026-1234.\n```\n' + code + '\n```')
                candidate["root"] = {"entries": [{"name": "README.md", "type": "blob"}]}
                self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), {"CVE-2026-1234"})

    def test_defensive_tooling_with_cve_metadata_is_not_a_poc(self) -> None:
        for name, description, path in (
            ("widget-hunting-pack", "Hunting for exploitation of CVE-2026-1234", "scripts"),
            ("widget-tools", "Read-only triage tools for CVE-2026-1234", "logscan.py"),
        ):
            with self.subTest(name=name):
                candidate = self.repo("researcher/" + name, description,
                                      'Find exploitation attempts for CVE-2026-1234.')
                candidate["root"] = {"entries": [{"name": path}]}
                self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), set())

    def test_poc_triage_filename_is_not_reproduction_evidence(self) -> None:
        candidate = self.repo("researcher/tool", "", "Static PoC triage for CVE-2026-1234.")
        candidate["root"] = {"entries": [{"name": "poc_triage.py", "type": "blob"}]}
        self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), set())
        candidate["root"]["entries"].append({"name": "exploit.py", "type": "blob"})
        self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), {"CVE-2026-1234"})

    def test_defensive_tool_labels_can_still_carry_a_reproducer(self) -> None:
        for name in ("guard", "hunting", "triage"):
            candidate = self.repo("researcher/widget-" + name, "Proof of concept for CVE-2026-1234",
                                  'PoC for CVE-2026-1234; run exploit.py.')
            candidate["root"] = {"entries": [{"name": "exploit.py", "type": "blob"}]}
            self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), {"CVE-2026-1234"})

    def test_cve_inputs_in_other_code_blocks_are_not_context(self) -> None:
        candidate = self.repo("researcher/tool", "", 'PoC lookup tool:\n'
                              '```\nlookup CVE-2026-1234\n```\n'
                              '```python\nimport client\nclient.query(cve)\n```')
        self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), set())

    def test_cve_comments_can_describe_an_inline_reproducer(self) -> None:
        for text in ('```python\n# CVE-2026-1234 PoC\nimport brotli\nbrotli.decompress(crafted)\n```',
                     '<pre><code>// CVE-2026-1234 PoC\nfunction trigger() { vulnerable(payload); }</code></pre>',
                     'Reproducer:\n```python\nimport brotli\nbrotli.decompress(crafted)  # CVE-2026-1234\n```',
                     'Reproducer:\n```js\nfunction trigger() { vulnerable(payload); } // CVE-2026-1234\n```',
                     'Exploit:\n```python\nfrom widget import parse\ndef cve_2026_1234():\n    parse(crafted)\n```'):
            candidate = self.repo("researcher/widget", "", text)
            self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), {"CVE-2026-1234"})

    def test_inline_lookup_commands_are_not_poc_captions(self) -> None:
        for query in ('`cve-tool CVE-2026-1234 --triage`', '~~~\ncve-tool CVE-2026-1234 --triage\n~~~'):
            candidate = self.repo("researcher/tool", "", 'Static PoC triage: ' + query +
                                  '\n```python\nimport client\nclient.query(cve)\n```')
            self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), set())
        for text in ('PoC for `CVE-2026-1234`:\n```python\nimport brotli\nbrotli.decompress(crafted)\n```',
                     'PoC for CVE-2026-1234:\n~~~python\nimport brotli\nbrotli.decompress(crafted)\n~~~'):
            candidate = self.repo("researcher/widget", "", text)
            self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), {"CVE-2026-1234"})

    def test_product_names_and_bug_classes_are_not_helper_filenames(self) -> None:
        for path in ("download_exploit.py", "catalog_exploit.py", "finder_exploit.py", "index_exploit.py"):
            candidate = self.repo("researcher/widget", "", 'Exploit for CVE-2026-1234.')
            candidate["root"] = {"entries": [{"name": path, "type": "blob"}]}
            self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), {"CVE-2026-1234"})

    def test_cve_specific_crash_triage_can_supply_a_poc(self) -> None:
        candidate = self.repo("researcher/CVE-2026-1234-triage", "", "PoC for CVE-2026-1234.")
        candidate["root"] = {"entries": [{"name": "main.py", "type": "blob"}]}
        self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), {"CVE-2026-1234"})

    def test_long_setup_block_does_not_mask_a_poc_caption(self) -> None:
        candidate = self.repo("researcher/widget", "", "Setup:\n```yaml\n" + "x: 1\n" * 80 +
                              "```\nPoC for CVE-2026-1234:\n```python\nimport brotli\nbrotli.decompress(crafted)\n```")
        candidate["root"] = {"entries": [{"name": "README.md", "type": "blob"}]}
        self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), {"CVE-2026-1234"})

    def test_cve_named_hunting_queries_still_need_a_poc_artifact(self) -> None:
        candidate = self.repo("researcher/CVE-2026-1234-hunting", "",
                              "Hunting queries for exploitation of CVE-2026-1234.")
        candidate["root"] = {"entries": [{"name": "hunt.py", "type": "blob"}]}
        self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), set())

    def test_generic_code_and_binary_poc_artifacts_are_kept(self) -> None:
        for path in ("main.py", "payload.bin"):
            candidate = self.repo("researcher/CVE-2026-1234", "", "Reproducer for CVE-2026-1234.")
            candidate["root"] = {"entries": [{"name": path, "type": "blob"}]}
            self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), {"CVE-2026-1234"})

    def test_owner_name_does_not_establish_repository_intent(self) -> None:
        candidate = self.repo("exploit-research/tool", "CVE-2026-1234 metadata client", "CVE-2026-1234 metadata.")
        candidate["root"] = {"entries": [{"name": "client.py", "type": "blob"}]}
        self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), set())
        candidate = self.repo("triage-lab/widget", "", "PoC for CVE-2026-1234; run poc_lab.py.")
        candidate["root"] = {"entries": [{"name": "poc_lab.py", "type": "blob"}]}
        self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), {"CVE-2026-1234"})

    def test_multi_year_collection_is_not_reclassified_as_one_cve_per_year(self) -> None:
        candidate = self.repo("researcher/POC", "Proof of concept exploits",
                              "PoCs: " + " ".join(f"CVE-{year}-1234" for year in range(2020, 2027)))
        candidate["root"] = {"entries": [{"name": "pocs", "type": "tree"}]}
        self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), set())
        candidate["root"]["entries"].append({"name": "CVE-2026-1234.py", "type": "blob"})
        self.assertEqual(update_cves.qualifying_repo_cves(candidate, 2026, []), {"CVE-2026-1234"})


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

    def test_empty_reference_section_does_not_consume_following_poc_sections(self) -> None:
        for newline in ('\n', '\r\n'):
            for spacer in ('', newline):
                github = 'https://github.com/owner/poc'
                nuclei = 'https://github.com/projectdiscovery/nuclei-templates/blob/main/poc.yaml'
                original = f'### POC{newline}#### Reference{newline}{spacer}#### Github{newline}- {github}{newline}{newline}#### Nuclei{newline}- {nuclei}{newline}'
                self.assertEqual(update_cves.section_links(original, '#### Reference'), [])
                updated, changed = update_cves.merge_section(original, '#### Reference', ['https://example.org/poc'], '')
                self.assertTrue(changed)
                self.assertEqual(update_cves.section_links(updated, '#### Reference'), ['https://example.org/poc'])
                self.assertEqual(update_cves.section_links(updated, '#### Github'), [github])
                self.assertEqual(update_cves.section_links(updated, '#### Nuclei'), [nuclei])
                self.assertTrue(updated.endswith(newline))


class DiscoveryFailureTests(unittest.TestCase):
    def test_failed_older_search_partition_preserves_newer_results(self):
        client = update_cves.GitHubClient('test')
        fresh = {'nameWithOwner': 'owner/CVE-2024-1234-poc'}
        def search(query, cursor=None):
            if '2026-10-20..2026-10-29' in query:
                return {'repositoryCount': 1500}
            if '2026-10-20..2026-10-24' in query:
                raise TimeoutError('older partition unavailable')
            self.assertIn('2026-10-25..2026-10-29', query)
            return {'repositoryCount': 1, 'nodes': [fresh], 'pageInfo': {'hasNextPage': False}}
        seen = []
        with patch.object(client, 'search_page', side_effect=search):
            with self.assertRaisesRegex(TimeoutError, 'older partition unavailable'):
                seen.extend(update_cves.search_range(client, 'CVE-2024', 'pushed', date(2026, 10, 20), date(2026, 10, 29)))
        self.assertEqual(seen, [fresh])

    def test_short_search_is_retried_in_smaller_complete_windows(self):
        client = update_cves.GitHubClient('test')
        calls = []
        def search(query, cursor=None):
            calls.append(query)
            if '2026-10-20..2026-10-21' in query:
                raise update_cves.IncompleteSearch('incomplete response data', 2)
            name = 'owner/older' if '2026-10-20..2026-10-20' in query else 'owner/newer'
            return {'repositoryCount': 1, 'nodes': [{'nameWithOwner': name}], 'pageInfo': {'hasNextPage': False}}
        with patch.object(client, 'search_page', side_effect=search):
            rows = list(update_cves.search_range(client, 'CVE-2024', 'pushed', date(2026, 10, 20), date(2026, 10, 21)))
        self.assertCountEqual([r['nameWithOwner'] for r in rows], ['owner/older', 'owner/newer'])
        self.assertEqual(len(calls), 3)

    def test_one_day_overflow_uses_nonoverlapping_timestamp_windows(self):
        client = update_cves.GitHubClient('test')
        calls = []
        def search(query, cursor=None):
            calls.append(query)
            if 'T' not in query:
                return {'repositoryCount': 1500}
            start, end = query.split('pushed:')[1].split('..')
            return {'repositoryCount': 1, 'nodes': [{'nameWithOwner': start}], 'pageInfo': {'hasNextPage': False}}
        with patch.object(client, 'search_page', side_effect=search):
            rows = list(update_cves.search_range(client, 'CVE-2026', 'pushed', date(2026, 10, 20), date(2026, 10, 20)))
        self.assertEqual(len(rows), 2)
        self.assertTrue(any('00:00:00+00:00..2026-10-20T11:59:59+00:00' in q for q in calls))
        self.assertTrue(any('12:00:00+00:00..2026-10-20T23:59:59+00:00' in q for q in calls))

    def test_authentication_failure_does_not_fan_out_search_windows(self):
        client = update_cves.GitHubClient('test')
        with patch.object(client, 'search_page', side_effect=update_cves.error.HTTPError('url', 403, 'limited', {}, None)) as search:
            with self.assertRaises(update_cves.error.HTTPError):
                list(update_cves.search_range(client, 'CVE-2026', 'pushed', date(2026, 10, 1), date(2026, 10, 29)))
        search.assert_called_once()

    def test_direct_cve_search_overflow_falls_back_to_complete_date_partitions(self):
        client = update_cves.GitHubClient('test')
        rows = [{'nameWithOwner': 'owner/poc'}]
        with patch.object(client, 'search_page', return_value={'repositoryCount': 1200}), \
                patch.object(update_cves, 'search_range', return_value=iter(rows)) as partition:
            self.assertEqual(list(update_cves.search_without_range(client, 'CVE-2021-44228')), rows)
        self.assertEqual(partition.call_args.args[1:4], ('CVE-2021-44228', 'created', date(2008, 1, 1)))

    def test_saturated_hour_still_reports_incomplete_discovery(self):
        start = update_cves.datetime(2026, 10, 20, tzinfo=update_cves.timezone.utc)
        client = update_cves.GitHubClient('test')
        with patch.object(client, 'search_page', return_value={'repositoryCount': 1500}) as search:
            with self.assertRaisesRegex(update_cves.IncompleteSearch, 'more than 1000'):
                list(update_cves.search_range(client, 'CVE-2026', 'pushed', start, start + update_cves.timedelta(minutes=59, seconds=59)))
        search.assert_called_once()

    def test_rate_limits_stop_partition_fanout(self):
        for failure in (update_cves.GitHubRateLimitError('quota exhausted'),
                        update_cves.error.HTTPError('url', 429, 'limited', {}, None),
                        update_cves.error.HTTPError('url', 403, 'limited', {}, None)):
            client = update_cves.GitHubClient('test')
            with self.subTest(failure=failure), patch.object(client, 'search_page', side_effect=[
                    {'repositoryCount': 1500}, failure]) as search:
                with self.assertRaises(type(failure)):
                    list(update_cves.search_range(client, 'CVE-2026', 'pushed', date(2026, 10, 1), date(2026, 10, 29)))
                self.assertEqual(search.call_count, 2)

    def test_rate_limit_stops_all_years_without_advancing_or_loading_readmes(self):
        failures, completed = [], set()
        with patch.object(update_cves.GitHubClient, 'search_page', side_effect=update_cves.GitHubRateLimitError('quota exhausted')) as search, \
                patch.object(update_cves.GitHubClient, 'fetch_readmes') as readmes:
            result = update_cves.discover_github_pocs('test', years=[2025, 2026], lookback_days=3,
                     backfill=False, cve_filter=set(), failures=failures, completed_years=completed)
        self.assertEqual(result, {})
        self.assertEqual(completed, set())
        self.assertEqual(len(failures), 1)
        search.assert_called_once()
        readmes.assert_not_called()

    def test_http_429_is_not_retried_before_retry_after(self):
        failure = update_cves.error.HTTPError('url', 429, 'limited', {'Retry-After': '120'}, None)
        with patch.object(update_cves.request, 'urlopen', side_effect=failure) as fetch, \
                patch.object(update_cves.time, 'sleep') as sleep:
            with self.assertRaises(update_cves.error.HTTPError):
                update_cves.http_json('https://api.github.com/graphql')
        fetch.assert_called_once()
        sleep.assert_not_called()

    def test_repeated_repository_does_not_count_as_complete_search(self):
        for ranged in (False, True):
            client = update_cves.GitHubClient('test')
            client.rest_queries.add(update_cves.build_search_query('CVE-2026', 'pushed', date(2026, 10, 20), date(2026, 10, 20))
                                    if ranged else 'CVE-2026 is:public fork:false')
            page = {'repositoryCount': 2, 'nodes': [{'nameWithOwner': 'owner/poc'}, {'nameWithOwner': 'OWNER/POC'}],
                    'pageInfo': {'hasNextPage': False}}
            with self.subTest(ranged=ranged), patch.object(client, 'search_page', return_value=page):
                with self.assertRaisesRegex(RuntimeError, 'only 1 of 2'):
                    list(update_cves.search_range(client, 'CVE-2026', 'pushed', date(2026, 10, 20), date(2026, 10, 20))
                         if ranged else update_cves.search_without_range(client, 'CVE-2026'))

    def test_graphql_timeout_and_null_nodes_restart_complete_rest_query(self):
        rest = {'total_count': 1, 'incomplete_results': False, 'items': [self.rest_repo(0)]}
        for failure in ({'errors': [{'type': 'INTERNAL', 'message': 'Query timeout'}]},
                        {'data': {'search': {'repositoryCount': 1, 'nodes': [None]}, 'rateLimit': {'remaining': 100}}}):
            with self.subTest(failure=failure), patch.object(update_cves, 'http_json', side_effect=[failure, rest]) as fetch:
                page = update_cves.GitHubClient('test').search_page('CVE-2026')
            self.assertEqual(page['nodes'][0]['nameWithOwner'], 'owner/poc-0')
            self.assertEqual(fetch.call_count, 2)
            self.assertIn('page=1', fetch.call_args.args[0])

    def test_official_description_headings_do_not_hide_or_create_source_links(self) -> None:
        description = "Summary.\n\n### Description\nImpact.\n\n### POC\n#### Github\nhttps://example.org/mentioned\nDetails."
        details = update_cves.CVEDetails(description, [], [], [])
        content = update_cves.build_markdown("CVE-2026-45067", details, ["https://github.com/owner/poc"], [])
        sections = build_site.parse_sections(content)
        self.assertEqual(sections['### Description'], description)
        self.assertEqual(build_site.collect_links(sections['#### Github']), ["https://github.com/owner/poc"])
        self.assertEqual(update_cves.section_links(content, '#### Github'), ["https://github.com/owner/poc"])
        updated, changed = update_cves.replace_section(content, '#### Github', [], 'No PoCs found on GitHub currently.')
        self.assertTrue(changed)
        self.assertEqual(build_site.parse_sections(updated)['### Description'], description)

    @staticmethod
    def rest_repo(number: int) -> dict:
        return {"full_name": f"owner/poc-{number}", "html_url": f"https://github.com/owner/poc-{number}",
                "private": False, "fork": False, "topics": ["poc"]}

    def test_short_graphql_results_retry_complete_rest_search(self) -> None:
        partial = {"data": {"search": {"repositoryCount": 2, "nodes": [{"nameWithOwner": "owner/poc-0"}],
                   "pageInfo": {"hasNextPage": False}}, "rateLimit": {"remaining": 100}}}
        rest = {"total_count": 2, "incomplete_results": False, "items": [self.rest_repo(n) for n in range(2)]}
        for ranged in (False, True):
            client = update_cves.GitHubClient("test")
            with self.subTest(ranged=ranged), patch.object(update_cves, "http_json", side_effect=[partial, rest]) as fetch, \
                    patch.object(update_cves.time, "sleep"):
                rows = list(update_cves.search_range(client, "CVE-2026", "pushed", date(2026, 10, 20), date(2026, 10, 29))
                            if ranged else update_cves.search_without_range(client, "CVE-2026"))
            self.assertEqual({row["nameWithOwner"] for row in rows}, {"owner/poc-0", "owner/poc-1"})
            self.assertEqual(fetch.call_count, 2)
            self.assertIn("api.github.com/search/repositories?", fetch.call_args.args[0])

    def test_unranged_search_rejects_repeated_pagination_cursor(self) -> None:
        client = update_cves.GitHubClient("test")
        page = {"repositoryCount": 3, "nodes": [{"nameWithOwner": "owner/poc"}],
                "pageInfo": {"hasNextPage": True, "endCursor": "same"}}
        with patch.object(client, "search_page", return_value=page) as fetch:
            with self.assertRaisesRegex(RuntimeError, "invalid pagination cursor"):
                list(update_cves.search_without_range(client, "CVE-2026"))
        self.assertEqual(fetch.call_count, 2)

    def test_server_failure_restarts_query_without_translating_graphql_cursor(self) -> None:
        first = {"data": {"search": {"repositoryCount": 3, "nodes": [{"nameWithOwner": "owner/poc-0"}],
                 "pageInfo": {"hasNextPage": True, "endCursor": "graphql-cursor"}}, "rateLimit": {"remaining": 100}}}
        failure = update_cves.error.HTTPError("url", 502, "bad gateway", {}, None)
        rest = {"total_count": 3, "incomplete_results": False, "items": [self.rest_repo(n) for n in range(3)]}
        client = update_cves.GitHubClient("test")
        with patch.object(update_cves, "http_json", side_effect=[first, failure, rest]) as fetch, \
                patch.object(update_cves.time, "sleep"):
            rows = list(update_cves.search_without_range(client, "CVE-2026"))
        self.assertEqual({row["nameWithOwner"] for row in rows}, {f"owner/poc-{n}" for n in range(3)})
        self.assertIn("page=1", fetch.call_args.args[0])
        self.assertNotIn("graphql-cursor", fetch.call_args.args[0])
        self.assertEqual(rows[-1]["repositoryTopics"]["nodes"], [{"topic": {"name": "poc"}}])
        self.assertNotIn("defaultBranchRef", rows[-1])

    def test_rest_fallback_reads_every_page(self) -> None:
        failure = update_cves.error.HTTPError("url", 503, "unavailable", {}, None)
        pages = [{"total_count": 101, "incomplete_results": False,
                  "items": [self.rest_repo(n) for n in range(start, end)]} for start, end in ((0, 100), (100, 101))]
        with patch.object(update_cves, "http_json", side_effect=[failure, *pages]) as fetch, \
                patch.object(update_cves.time, "sleep"):
            rows = list(update_cves.search_without_range(update_cves.GitHubClient("test"), "CVE-2026"))
        self.assertEqual(len(rows), 101)
        self.assertEqual(rows[-1]["nameWithOwner"], "owner/poc-100")
        self.assertIn("page=2", fetch.call_args.args[0])

    def test_rest_fallback_never_accepts_incomplete_or_short_results(self) -> None:
        for payload in [
            {"total_count": 1, "incomplete_results": True, "items": [self.rest_repo(0)]},
            {"total_count": 2, "incomplete_results": False, "items": [self.rest_repo(0)]},
        ]:
            failure = update_cves.error.HTTPError("url", 502, "bad gateway", {}, None)
            with self.subTest(payload=payload), patch.object(update_cves, "http_json", side_effect=[failure, payload]), \
                    patch.object(update_cves.time, "sleep"):
                with self.assertRaisesRegex(RuntimeError, "incomplete response"):
                    update_cves.GitHubClient("test").search_page("CVE-2026")

    def test_authentication_failure_does_not_trigger_rest_fallback(self) -> None:
        failure = update_cves.error.HTTPError("url", 403, "forbidden", {}, None)
        with patch.object(update_cves, "http_json", side_effect=failure) as fetch:
            with self.assertRaises(update_cves.error.HTTPError):
                update_cves.GitHubClient("test").search_page("CVE-2026")
        self.assertEqual(fetch.call_count, 1)

    def test_search_does_not_accept_partial_graphql_results(self) -> None:
        payload = {
            "data": {"search": {"repositoryCount": 1, "nodes": []}, "rateLimit": {"remaining": 100}},
            "errors": [{"type": "FORBIDDEN", "message": "Search unavailable"}],
        }
        with patch.object(update_cves, "http_json", return_value=payload):
            with self.assertRaisesRegex(RuntimeError, "Search unavailable"):
                update_cves.GitHubClient("test").search_page("CVE-2026")

    def test_readme_batch_failure_aborts_discovery(self) -> None:
        repo = {
            "nameWithOwner": "owner/CVE-2026-1234-poc",
            "url": "https://github.com/owner/CVE-2026-1234-poc",
        }
        with patch.object(update_cves.source_artifacts, "pending_reviewed_names", return_value=[]), \
                patch.object(update_cves, "search_range", return_value=[repo]), patch.object(
            update_cves.GitHubClient, "fetch_readmes", side_effect=RuntimeError("API unavailable")
        ):
            with self.assertRaisesRegex(RuntimeError, "API unavailable"):
                update_cves.discover_github_pocs(
                    "test", years=[2026], lookback_days=3, backfill=False, cve_filter=set()
                )

    def test_qualified_repository_survives_an_unverified_reference(self) -> None:
        cve = "CVE-2026-1234"
        url = "https://github.com/owner/CVE-2026-1234-poc"
        details = update_cves.CVEDetails("A vulnerability.", [], [], [])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "2026" / f"{cve}.md"
            path.parent.mkdir()
            path.write_text(update_cves.build_markdown(cve, details, [], [url]), encoding="utf-8")
            update_cves.update_existing_markdown(path, [url], [], dry_run=False)
            with patch.object(build_site, "CVES", root), patch.object(
                build_site, "load_metadata", return_value={}
            ), patch.object(build_site, "load_dates", return_value={}), patch("archive_pocs.load_records", return_value={}), patch.object(
                build_site, "load_verified_references", return_value=set()
            ):
                entries, _ = build_site.build_cve_list(set())
        self.assertEqual([(entry["cve"], entry["poc"]) for entry in entries], [(cve, [url])])


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
    def test_repository_advisory_survives_its_collection_source(self) -> None:
        cve = "CVE-2021-22555"
        base = "https://github.com/google/security-research"
        advisory = base + "/security/advisories/GHSA-xxx5-8mvq-3528"
        collection = base + "/tree/master/pocs/linux/cve-2021-22555"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "2021" / f"{cve}.md"
            path.parent.mkdir()
            path.write_text(f"### Description\nA vulnerability.\n\n#### Reference\n- {advisory}\n"
                            f"\n#### Collections\n- {collection}\n")
            with patch.object(build_site, "CVES", root), patch.object(build_site, "load_metadata", return_value={}), \
                    patch.object(build_site, "load_dates", return_value={}), \
                    patch("archive_pocs.load_records", return_value={}), \
                    patch.object(build_site, "load_verified_references", return_value={(cve, build_site.link_key(advisory))}):
                entries, _ = build_site.build_cve_list(set())
        self.assertEqual(entries[0]["poc"], [advisory])
        self.assertEqual(entries[0]["collections"], [collection])
        self.assertEqual(build_site.repo_from_url(advisory), "")
        self.assertEqual(build_site.repo_from_url(advisory.upper()), "")
        self.assertEqual(build_site.repo_from_url(collection), "google/security-research")

    def test_curated_artifact_variants_survive_publication(self) -> None:
        cve = "CVE-2024-26642"
        base = "https://github.com/google/security-research"
        variants = [f"{base}/tree/master/pocs/linux/kernelctf/{cve}_{kind}" for kind in ("lts", "mitigation")]
        template = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/Test.yaml?version=One#Request"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "2024" / f"{cve}.md"
            path.parent.mkdir()
            path.write_text(
                "### Description\nA vulnerability.\n\n#### Github\n- " + base
                + "\n\n#### Collections\n" + "\n".join(f"- {url}" for url in [*variants, variants[0].replace("google/security-research", "GOOGLE/Security-Research")])
                + "\n\n#### Nuclei\n" + "\n".join(f"- {url}" for url in [template, template.replace("Test.yaml", "test.yaml")]) + "\n",
                encoding="utf-8",
            )
            with patch.object(build_site, "CVES", root), patch.object(build_site, "load_metadata", return_value={}), \
                    patch.object(build_site, "load_dates", return_value={}), \
                    patch("archive_pocs.load_records", return_value={}), \
                    patch.object(build_site, "load_verified_references", return_value=set()):
                entries, _ = build_site.build_cve_list(set())
        self.assertEqual(entries[0]["collections"], variants)
        self.assertEqual(entries[0]["nuclei"], [template, template.replace("Test.yaml", "test.yaml")])
        self.assertEqual(entries[0]["poc"], [])

    def test_published_links_require_absolute_http_urls(self) -> None:
        valid = [
            "https://Example.com/PoC.py?Version=One#Example",
            "http://example.com/poc",
            "HTTPS://example.com/CaseSensitive",
        ]
        invalid = [
            "javascript:alert(1)",
            "data:text/html,test",
            "//example.com/poc",
            "/relative/poc",
            "https:///missing-host",
            "https://[invalid/poc",
            "ordinary description text",
        ]
        block = "\n".join(f"- {url}" for url in [*invalid, *valid])
        self.assertEqual(build_site.collect_links(block), valid)

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

    def test_advisories_preserve_distinct_paths_within_one_repository(self) -> None:
        rows = [
            ["https://github.com/Helson-S/FuzzyTesting", ["Product"]],
            [
                "https://github.com/Helson-S/FuzzyTesting/blob/main/vulDescription.md",
                ["Third Party Advisory", "Exploit"],
            ],
            ["https://github.com/Helson-S/FuzzyTesting/commit/abc123", ["Patch"]],
            ["https://github.com/Helson-S/FuzzyTesting/issues/42", ["Issue Tracking"]],
            ["https://github.com/Helson-S/FuzzyTesting/releases/tag/v1.2", ["Release Notes"]],
        ]
        self.assertEqual(build_site.dedupe_advisories(rows, "CVE-2024-41443"), rows)

    def test_duplicate_advisory_tags_are_merged_without_mutating_input(self) -> None:
        url = "https://github.com/Helson-S/FuzzyTesting/issues/42"
        rows = [[url, ["Issue Tracking"]], [url, ["Exploit", "Issue Tracking"]]]
        self.assertEqual(build_site.dedupe_advisories(rows, "CVE-2024-41443"),
                         [[url, ["Issue Tracking", "Exploit"]]])
        self.assertEqual(rows[0], [url, ["Issue Tracking"]])

    def test_advisory_identity_preserves_case_sensitive_paths_and_fragments(self) -> None:
        urls = ["https://github.com/owner/repo/blob/main/Advisory.md#first",
                "https://github.com/OWNER/Repo/blob/main/Advisory.md#first",
                "https://github.com/owner/repo/blob/main/advisory.md#first",
                "https://github.com/owner/repo/blob/main/Advisory.md#second"]
        rows = [[url, ["Third Party Advisory"]] for url in urls]
        self.assertEqual(build_site.dedupe_advisories(rows, "CVE-2024-41443"),
                         [rows[0], *rows[2:]])

    def test_distinct_global_github_advisories_are_not_merged(self) -> None:
        rows = [
            ["https://github.com/advisories/GHSA-hxp3-63hc-5366", ["GitHub Advisory"]],
            ["https://github.com/advisories/GHSA-5hgx-prqh-5qmp", ["GitHub Advisory"]],
        ]
        self.assertEqual(build_site.dedupe_advisories(rows, "CVE-2025-66645"), rows)


if __name__ == "__main__":
    unittest.main()
