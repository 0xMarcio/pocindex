#!/usr/bin/env python3
"""Take candidate PoC repositories from PoC-in-GitHub and judge them here.

GitHub discovery only sees repositories pushed in the last few days, so a PoC
published years ago for an old CVE is unreachable no matter how long the job
runs. nomi-sec/PoC-in-GitHub has been collecting them daily since 1999 and
publishes one JSON file per CVE.

It collects without filtering, exactly as the workflow this index replaced
did, so nothing here is trusted on arrival: every candidate goes through
qualifying_repo_cves, the same gate a repository found by search must pass.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import sys
import tarfile
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import source_artifacts

from update_cves import (
    GITHUB_LIST,
    GITHUB_GRAPHQL_URL,
    CVES,
    GitHubClient,
    github_repo_from_url,
    github_repository_data,
    http_json,
    is_blacklisted_repo,
    load_blacklist,
    ensure_cve_entries,
    qualifying_repo_cves,
    attach_source_artifacts,
    reconcile_inventory,
    replace_section,
    section_links,
)

TARBALL = "https://codeload.github.com/nomi-sec/PoC-in-GitHub/tar.gz/refs/heads/master"
SECTION = "#### Github"
EMPTY = "No PoCs found on GitHub currently."
CVE_NAME = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
BATCH = 10
USER_AGENT = "0xMarcio-cve-poc-in-github"

FIELDS = """
  defaultBranchRef { target { oid } }
  nameWithOwner url description isFork isArchived
  repositoryTopics(first: 20) { nodes { topic { name } } }
  readmeMd: object(expression: "HEAD:README.md") { ... on Blob { text } }
  readmeUpper: object(expression: "HEAD:README.MD") { ... on Blob { text } }
  readmeRst: object(expression: "HEAD:README.rst") { ... on Blob { text } }
  readmeBare: object(expression: "HEAD:README") { ... on Blob { text } }
  root: object(expression: "HEAD:") { ... on Tree { entries { name type } } }
"""


def candidates() -> dict[str, set[str]]:
    """CVE to the repository URLs the collection lists for it."""
    request = urllib.request.Request(TARBALL, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=600) as response:
        archive = response.read()
    found: dict[str, set[str]] = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        for member in tar:
            if not member.isfile() or not member.name.endswith(".json"):
                continue
            cve = member.name.rsplit("/", 1)[-1][:-5].upper()
            if not CVE_NAME.match(cve):
                continue
            handle = tar.extractfile(member)
            if handle is None:
                continue
            try:
                listed = json.loads(handle.read())
            except (ValueError, UnicodeDecodeError):
                continue
            urls = {
                str(item.get("html_url") or "").rstrip("/")
                for item in listed
                if item.get("html_url")
            }
            if urls:
                found[cve] = urls
    return found


def candidates_from_file(path: Path) -> dict[str, set[str]]:
    """CVE repository pairs from a local trending payload."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get("items") if isinstance(payload, dict) else payload
    found: dict[str, set[str]] = {}
    for item in rows or []:
        if not isinstance(item, dict):
            continue
        cve = str(item.get("cve") or "").upper()
        url = str(item.get("url") or "").rstrip("/")
        if CVE_NAME.match(cve) and url:
            found.setdefault(cve, set()).add(url)
    return found


def already_linked() -> dict[str, tuple[Path, set[str]]]:
    """What each entry in this index already lists under GitHub."""
    held: dict[str, tuple[Path, set[str]]] = {}
    for path in sorted(CVES.glob("[12][0-9][0-9][0-9]/CVE-*.md")):
        text = path.read_text(encoding="utf-8", errors="replace")
        held[path.stem.upper()] = (path, {url.rstrip("/") for url in section_links(text, SECTION)})
    return held


def describe(client: GitHubClient, names: list[str]) -> dict[str, dict]:
    """Metadata, README and root listing for a batch, as the classifier expects."""
    aliases = " ".join(
        f"r{index}: repository(owner: {json.dumps(name.split('/', 1)[0])}, "
        f"name: {json.dumps(name.split('/', 1)[1])}) {{ {FIELDS} }}"
        for index, name in enumerate(names)
    )
    payload = http_json(
        GITHUB_GRAPHQL_URL,
        headers=client.headers,
        data={"query": "query { " + aliases + " rateLimit { remaining resetAt } }"},
    )
    data = github_repository_data(payload, {f"r{index}" for index in range(len(names))})
    described: dict[str, dict] = {}
    for index, name in enumerate(names):
        repo = data.get(f"r{index}")
        if repo:
            described[name] = repo
    return described


def main() -> int:
    parser = argparse.ArgumentParser(description="Judge PoC-in-GitHub candidates against this index")
    parser.add_argument("--limit", type=int, default=0, help="Repositories to judge this run")
    parser.add_argument("--dry-run", action="store_true", help="Report without writing files")
    parser.add_argument("--cvelist-dir", type=Path, help="Local CVE List V5 root for a large backfill")
    parser.add_argument("--input", type=Path, help="Use a local trending JSON file instead of the upstream archive")
    args = parser.parse_args()

    listed = candidates_from_file(args.input) if args.input else candidates()
    held = already_linked()
    print(f"{len(listed):,} CVEs listed upstream | {len(held):,} entries in this index")

    # One repository can be offered for several CVEs; judge it once per pair.
    blacklist = load_blacklist()
    pending: dict[str, set[str]] = {}
    for cve, urls in listed.items():
        entry = held.get(cve)
        existing = entry[1] if entry is not None else set()
        for url in urls - existing:
            full_name = github_repo_from_url(url)
            if full_name and "/" in full_name and not is_blacklisted_repo(full_name, blacklist):
                pending.setdefault(full_name, set()).add(cve)

    names = sorted(pending)
    if args.limit:
        names = names[: args.limit]
    print(f"{sum(len(pending[n]) for n in names):,} candidate links across {len(names):,} repositories")

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    client = GitHubClient(token)
    accepted: dict[str, set[str]] = {}
    judged = kept = 0

    batches = [names[i : i + BATCH] for i in range(0, len(names), BATCH)]
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(describe, client, batch): batch for batch in batches}
        for future in as_completed(futures):
            batch = futures[future]
            try:
                described = future.result()
            except Exception as problem:
                for pending_future in futures:
                    pending_future.cancel()
                raise RuntimeError(f"Repository batch starting at {batch[0]} failed: {problem}") from problem
            for full_name in batch:
                judged += 1
                repo = described.get(full_name)
                if repo is None:
                    continue
                attach_source_artifacts(repo, client.headers, blacklist, cves=pending[full_name], persist=not args.dry_run)
                for cve in pending[full_name]:
                    year = int(cve.split("-")[1])
                    if cve in qualifying_repo_cves(repo, year, blacklist):
                        links = source_artifacts.approved_artifact_links(repo, cve) or [str(repo.get("url") or "").rstrip("/")]
                        accepted.setdefault(cve, set()).update(links)
                        kept += 1
            if judged % 2000 < BATCH:
                print(f"  judged {judged:,} of {len(names):,}")

    created, unavailable = ensure_cve_entries(
        accepted,
        dry_run=args.dry_run,
        cvelist_dir=args.cvelist_dir,
    )
    if created or unavailable:
        verb = "would create" if args.dry_run else "created"
        print(f"base entries: {len(created):,} {verb}, {len(unavailable):,} unpublished or unavailable")
    for cve in created:
        path = CVES / cve.split("-")[1] / f"{cve}.md"
        if path.exists():
            held[cve] = (path, set(section_links(path.read_text(encoding="utf-8"), SECTION)))

    written = 0
    for cve, urls in sorted(accepted.items()):
        if cve not in held:
            continue
        path, existing = held[cve]
        merged = section_links(path.read_text(encoding="utf-8", errors="replace"), SECTION)
        merged = merged + sorted(url for url in urls if url.rstrip("/") not in existing)
        with path.open("r", encoding="utf-8", newline="") as handle:
            text = handle.read()
        updated, changed = replace_section(text, SECTION, merged, EMPTY)
        if changed and not args.dry_run:
            with path.open("w", encoding="utf-8", newline="") as handle:
                handle.write(updated)
        written += bool(changed)

    indexed = {cve: urls for cve, urls in accepted.items() if cve in held}
    inventory_added, inventory_removed = reconcile_inventory(
        GITHUB_LIST,
        SECTION,
        indexed,
        dry_run=args.dry_run,
    )

    print(f"accepted {kept:,} links for {len(accepted):,} CVEs | {written:,} entries updated")
    print(f"GitHub inventory changes: +{inventory_added:,}/-{inventory_removed:,}")
    print(f"rejected {sum(len(pending[n]) for n in names) - kept:,} candidates that did not pass the gate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
