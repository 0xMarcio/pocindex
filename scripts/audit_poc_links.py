#!/usr/bin/env python3
"""Prune PoC links to deleted repositories and refresh the metadata the site shows."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date
from pathlib import Path
from typing import Iterable
from urllib import error, request
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

from update_cves import (
    readme_text,
    repo_is_bare,
    GITHUB_GRAPHQL_URL,
    kev_badge,
    USER_AGENT,
    GitHubClient,
    github_repo_from_url,
    http_json,
    is_blacklisted_repo,
    is_valid_cve,
    load_blacklist,
    replace_section,
    section_links,
)

ROOT = Path(__file__).resolve().parents[1]
CVES = ROOT / "cves"
INDEX = ROOT / "index"
STATE_FILE = ROOT / ".github" / "link_audit_state.json"
GITHUB_LIST = INDEX / "github.txt"
REFERENCE_LIST = INDEX / "references.txt"
REPO_META = INDEX / "repo_meta.json"
KEV_FILE = INDEX / "kev.json"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
GITHUB_SECTION = "#### Github"
REFERENCE_SECTION = "#### Reference"
SECTION_EMPTY = {
    GITHUB_SECTION: "No PoCs found on GitHub currently.",
    REFERENCE_SECTION: "No PoCs from references.",
}
GITHUB_EMPTY = "No PoCs found on GitHub currently."
BATCH = 20


def collect_repositories() -> tuple[dict[str, list[tuple[Path, str]]], set[str]]:
    """Map prunable links to their entries, and name every repository the site shows.

    Only the GitHub section is prunable; a reference comes from the CVE record
    itself, so it stays even when it rots. Both sections need star counts.
    """
    prunable: dict[str, list[tuple[Path, str]]] = {}
    referenced: set[str] = set()
    for path in sorted(CVES.glob("[12][0-9][0-9][0-9]/CVE-*.md")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for url in section_links(text, GITHUB_SECTION):
            full_name = github_repo_from_url(url)
            if full_name and "/" in full_name:
                prunable.setdefault(full_name, []).append((path, url))
                referenced.add(full_name)
        for url in section_links(text, REFERENCE_SECTION):
            full_name = github_repo_from_url(url)
            if full_name and "/" in full_name:
                referenced.add(full_name)
    return prunable, referenced


REPO_FIELDS = (
    "{ nameWithOwner stargazerCount pushedAt "
    'readmeMd: object(expression: "HEAD:README.md") { ... on Blob { text } } '
    'readmeUpper: object(expression: "HEAD:README.MD") { ... on Blob { text } } '
    'readmeRst: object(expression: "HEAD:README.rst") { ... on Blob { text } } '
    'readmeBare: object(expression: "HEAD:README") { ... on Blob { text } } '
    'root: object(expression: "HEAD:") { ... on Tree { entries { name type } } } }'
)


def survey(client: GitHubClient, names: list[str]) -> tuple[set[str], dict[str, list]]:
    """Return the repositories to drop, and stars/last push for the rest.

    Dropped means GitHub reports NOT_FOUND, or the repository is bare: no code,
    no directory, no artifact and a README with nothing runnable in it, which
    the discovery gate would reject today. Anything else, a network error or a
    throttle or an unexpected response, leaves the repository out of both
    results, so an audit failure never drops a link.
    """
    batches = [names[index : index + BATCH] for index in range(0, len(names), BATCH)]
    missing: set[str] = set()
    metadata: dict[str, list] = {}
    checked = 0

    def check(batch: list[str]) -> tuple[set[str], dict[str, list]]:
        aliases = " ".join(
            f"r{index}: repository(owner: {json.dumps(name.split('/', 1)[0])}, "
            f"name: {json.dumps(name.split('/', 1)[1])}) "
            f"{REPO_FIELDS}"
            for index, name in enumerate(batch)
        )
        payload = http_json(
            GITHUB_GRAPHQL_URL,
            headers=client.headers,
            data={"query": "query { " + aliases + " rateLimit { remaining resetAt } }"},
        )
        gone: set[str] = set()
        failed_aliases: set[str] = set()
        for entry in payload.get("errors") or []:
            path = entry.get("path") or []
            if not path:
                return set(), {}
            alias = str(path[0])
            failed_aliases.add(alias)
            index = alias[1:]
            if (
                str(entry.get("type") or "") == "NOT_FOUND"
                and len(path) == 1
                and alias.startswith("r")
                and index.isdigit()
                and int(index) < len(batch)
            ):
                gone.add(batch[int(index)])
        found: dict[str, list] = {}
        data = payload.get("data") or {}
        for index, name in enumerate(batch):
            alias = f"r{index}"
            # A failed README or root lookup is not evidence of a bare repo.
            if alias in failed_aliases:
                continue
            repo = data.get(alias)
            if not repo:
                continue
            if repo_is_bare(repo, readme_text(repo)):
                gone.add(name)
                continue
            pushed = str(repo.get("pushedAt") or "")[:10]
            found[name.lower()] = [
                int(repo.get("stargazerCount") or 0),
                pushed,
            ]
        return gone, found

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(check, batch): batch for batch in batches}
        for future in as_completed(futures):
            batch = futures[future]
            try:
                gone, found = future.result()
                missing |= gone
                metadata.update(found)
            except Exception as exc:
                print(f"Kept {len(batch)} repositories after a failed check: {exc}", file=sys.stderr)
            checked += len(batch)
            if checked % 5000 < len(batch):
                print(f"Checked {checked} of {len(names)} repositories")
    return missing, metadata


def save_metadata(metadata: dict[str, list], alive: set[str], *, dry_run: bool) -> int:
    """Merge this run's readings over the stored ones and forget deleted repositories."""
    try:
        stored = json.loads(REPO_META.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        stored = {}
    stored.update(metadata)
    stored = {name: value for name, value in stored.items() if name.lower() in alive}
    if not dry_run:
        REPO_META.write_text(
            json.dumps(stored, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
    return len(stored)


def prune_entries(
    references: dict[str, list[tuple[Path, str]]],
    missing: Iterable[str],
    *,
    dry_run: bool,
) -> tuple[int, int, set[str]]:
    dead_by_path: dict[Path, set[str]] = {}
    dead_urls: set[str] = set()
    for full_name in missing:
        for path, url in references.get(full_name, []):
            dead_by_path.setdefault(path, set()).add(url)
            dead_urls.add(url)

    for path, urls in sorted(dead_by_path.items()):
        with path.open("r", encoding="utf-8", newline="") as handle:
            text = handle.read()
        kept = [url for url in section_links(text, GITHUB_SECTION) if url not in urls]
        updated, changed = replace_section(text, GITHUB_SECTION, kept, GITHUB_EMPTY)
        if changed and not dry_run:
            with path.open("w", encoding="utf-8", newline="") as handle:
                handle.write(updated)
    removals = sum(len(urls) for urls in dead_by_path.values())
    return len(dead_by_path), removals, dead_urls


def prune_inventory(dead_urls: set[str], *, dry_run: bool) -> int:
    if not GITHUB_LIST.exists() or not dead_urls:
        return 0
    lines = GITHUB_LIST.read_text(encoding="utf-8").splitlines()
    kept = [line for line in lines if line.rsplit(" - ", 1)[-1].strip() not in dead_urls]
    if not dry_run and len(kept) != len(lines):
        GITHUB_LIST.write_text("\n".join(kept) + "\n", encoding="utf-8")
    return len(lines) - len(kept)


def collect_references() -> dict[str, list[tuple[Path, str]]]:
    """Every link that is not a GitHub repository, and where it appears."""
    references: dict[str, list[tuple[Path, str]]] = {}
    for path in sorted(CVES.glob("[12][0-9][0-9][0-9]/CVE-*.md")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for header in (REFERENCE_SECTION, GITHUB_SECTION):
            for url in section_links(text, header):
                if not github_repo_from_url(url):
                    references.setdefault(url, []).append((path, header))
    return references


def interleave_by_host(urls: list[str]) -> list[str]:
    """Round-robin the hosts so a slice does not hammer one server in a burst."""
    hosts: dict[str, list[str]] = {}
    for url in urls:
        host = urlsplit(url).netloc.lower()
        hosts.setdefault(host, []).append(url)
    queues = list(hosts.values())
    ordered: list[str] = []
    while queues:
        for queue in list(queues):
            ordered.append(queue.pop(0))
            if not queue:
                queues.remove(queue)
    return ordered


def dead_references(urls: list[str], *, workers: int, timeout: int) -> set[str]:
    """URLs the web answers 404 or 410 for. Everything else keeps its link."""
    dead: set[str] = set()
    checked = 0

    def check(url: str) -> tuple[str, bool]:
        headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        for method in ("HEAD", "GET"):
            try:
                req = request.Request(url, method=method, headers=headers)
                with request.urlopen(req, timeout=timeout) as response:
                    if method == "GET":
                        response.read(1)
                    return url, False
            except error.HTTPError as exc:
                code = exc.code
                exc.close()
                # a server that dislikes HEAD is not a server without the page
                if method == "GET" or code not in {403, 404, 405, 410, 501}:
                    return url, code in {404, 410}
            except Exception:
                # a timeout or a refused connection keeps the link, and asking
                # the same unreachable host a second time only doubles the wait
                return url, False
        return url, False

    with ThreadPoolExecutor(max_workers=workers) as executor:
        for url, gone in executor.map(check, urls):
            if gone:
                dead.add(url)
            checked += 1
            if checked % 2000 == 0:
                print(f"Checked {checked} of {len(urls)} references")
    return dead


def prune_references(
    references: dict[str, list[tuple[Path, str]]],
    dead: set[str],
    *,
    dry_run: bool,
) -> tuple[int, int]:
    by_path: dict[Path, dict[str, set[str]]] = {}
    for url in dead:
        for path, header in references.get(url, []):
            by_path.setdefault(path, {}).setdefault(header, set()).add(url)

    removed = 0
    for path, headers in sorted(by_path.items()):
        with path.open("r", encoding="utf-8", newline="") as handle:
            text = path_text = handle.read()
        for header, urls in headers.items():
            empty = SECTION_EMPTY[header]
            kept = [url for url in section_links(text, header) if url not in urls]
            removed += len(section_links(text, header)) - len(kept)
            text, _ = replace_section(text, header, kept, empty)
        if text != path_text and not dry_run:
            with path.open("w", encoding="utf-8", newline="") as handle:
                handle.write(text)

    lines = REFERENCE_LIST.read_text(encoding="utf-8").splitlines() if REFERENCE_LIST.exists() else []
    kept_lines = [line for line in lines if line.rsplit(" - ", 1)[-1].strip() not in dead]
    if not dry_run and len(kept_lines) != len(lines):
        REFERENCE_LIST.write_text("\n".join(kept_lines) + "\n", encoding="utf-8")
    return removed, len(lines) - len(kept_lines)


def refresh_kev(*, dry_run: bool) -> int:
    """Store CISA's known-exploited catalogue: the CVEs attackers actually use.

    Keeps only what the page shows, so the whole catalogue costs a few tens of
    kilobytes. A failure leaves the previous file in place rather than
    dropping the badge off every entry.
    """
    try:
        payload = http_json(KEV_URL)
        if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
            raise ValueError("Missing KEV vulnerability list")
        vulnerabilities = payload["vulnerabilities"]
        if type(payload.get("count")) is not int or payload["count"] != len(vulnerabilities):
            raise ValueError("KEV count does not match its vulnerability list")
        if not vulnerabilities:
            raise ValueError("Empty KEV catalogue")
        entries = {}
        for item in vulnerabilities:
            if not isinstance(item, dict):
                raise ValueError("Invalid KEV entry")
            cve_id = str(item.get("cveID") or "").upper()
            if not is_valid_cve(cve_id) or cve_id in entries:
                raise ValueError("Invalid or duplicate KEV CVE ID")
            added = str(item.get("dateAdded") or "")
            if date.fromisoformat(added).isoformat() != added:
                raise ValueError("Invalid KEV dateAdded")
            ransomware = str(item.get("knownRansomwareCampaignUse") or "Unknown").lower()
            if ransomware not in {"known", "unknown"}:
                raise ValueError("Invalid KEV ransomware status")
            entries[cve_id] = [added, 1 if ransomware == "known" else 0]
    except Exception as exc:
        print(f"Kept the stored KEV catalogue after a failed fetch: {exc}", file=sys.stderr)
        return 0
    if not dry_run:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=KEV_FILE.parent, delete=False) as handle:
            handle.write(json.dumps(entries, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
            temporary = Path(handle.name)
        try:
            temporary.replace(KEV_FILE)
        finally:
            temporary.unlink(missing_ok=True)
    return len(entries)


KEV_MARKER = "label=CISA%20KEV"


def sync_kev_badges(*, dry_run: bool) -> tuple[int, int]:
    """Put the known-exploited badge on the entries CISA lists, and only those.

    The site shows KEV in a search result, but the repository is what most
    people read, and nothing in the markdown said a vulnerability was under
    active attack.
    """
    try:
        catalogue = json.loads(KEV_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0, 0

    added = removed = 0
    for path in sorted(CVES.glob("[12][0-9][0-9][0-9]/CVE-*.md")):
        cve_id = path.stem.upper()
        wanted = kev_badge(cve_id, catalogue)
        with path.open("r", encoding="utf-8", newline="") as handle:
            text = handle.read()
        has = KEV_MARKER in text
        if not wanted and not has:
            continue

        newline = "\r\n" if "\r\n" in text else "\n"
        lines = text.split(newline)
        lines = [line for line in lines if KEV_MARKER not in line]
        if wanted:
            anchor = next((i for i, line in enumerate(lines) if line.strip() == "### Description"), None)
            if anchor is None:
                continue
            insert = anchor
            while insert > 0 and not lines[insert - 1].strip():
                insert -= 1
            lines.insert(insert, wanted)

        updated = newline.join(lines)
        if updated == text:
            continue
        added += 1 if wanted else 0
        removed += 1 if has and not wanted else 0
        if not dry_run:
            with path.open("w", encoding="utf-8", newline="") as handle:
                handle.write(updated)
    return added, removed


def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def save_state(state: dict, *, dry_run: bool) -> None:
    if dry_run:
        return
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def slice_after(items: list[str], cursor: str, limit: int) -> list[str]:
    """The next `limit` items after the cursor, wrapping once at the end.

    A limit of zero, or one larger than the list, means everything -- capped so
    that wrapping can never hand back the same item twice.
    """
    limit = len(items) if not limit else min(limit, len(items))
    start = next((i for i, item in enumerate(items) if item > cursor), 0) if cursor else 0
    window = items[start : start + limit]
    if len(window) < limit:
        window += items[: limit - len(window)]
    return window


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Drop PoC links to deleted repositories and refresh repo_meta.json"
    )
    parser.add_argument("--limit", type=int, default=0, help="Repositories to check this run")
    parser.add_argument("--references", type=int, default=0,
                        help="Reference links to check this run (0 skips them, -1 checks all)")
    parser.add_argument("--workers", type=int, default=16, help="Concurrent reference requests")
    parser.add_argument("--timeout", type=int, default=8, help="Seconds per reference request")
    parser.add_argument("--kev-only", action="store_true", help="Refresh CISA KEV without auditing links")
    parser.add_argument("--dry-run", action="store_true", help="Report without writing files")
    args = parser.parse_args()

    if args.kev_only:
        print(f"KEV catalogue: {refresh_kev(dry_run=args.dry_run)} known-exploited CVEs")
        return 0

    references, referenced = collect_repositories()
    names = sorted(referenced)
    print(
        f"{sum(len(v) for v in references.values())} prunable links | "
        f"{len(names)} repositories to survey"
    )

    state = load_state()
    scope = slice_after(names, str(state.get("cursor") or ""), args.limit)
    print(f"Checking {len(scope)} repositories starting after {state.get('cursor') or 'the beginning'}")

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    blocked = {
        name for name in references
        if is_blacklisted_repo(name, load_blacklist())
    }
    missing, metadata = survey(
        GitHubClient(token),
        [name for name in scope if name not in blocked],
    )
    print(f"{len(missing)} repositories no longer exist or hold nothing runnable")
    if blocked:
        print(f"Pruning {len(blocked)} explicitly blacklisted repositories")
    missing |= blocked

    entries, links, dead_urls = prune_entries(references, missing, dry_run=args.dry_run)
    inventory = prune_inventory(dead_urls, dry_run=args.dry_run)
    alive = {name.lower() for name in names if name not in missing}
    tracked = save_metadata(metadata, alive, dry_run=args.dry_run)
    state["cursor"] = scope[-1] if scope else ""

    print(f"Removed {links} links from {entries} entries | {inventory} inventory lines")
    print(f"Refreshed stars and last-push for {len(metadata)} repositories | {tracked} tracked")

    if args.references:
        references = collect_references()
        urls = sorted(references)
        window = slice_after(urls, str(state.get("reference_cursor") or ""),
                             0 if args.references < 0 else args.references)
        print(f"Checking {len(window)} of {len(urls)} reference links")
        gone = dead_references(
            interleave_by_host(window), workers=args.workers, timeout=args.timeout
        )
        ref_links, ref_lines = prune_references(references, gone, dry_run=args.dry_run)
        state["reference_cursor"] = window[-1] if window else ""
        print(f"Reference links returning 404 or 410: {len(gone)} | "
              f"removed {ref_links} links, {ref_lines} inventory lines")

    save_state(state, dry_run=args.dry_run)
    print(f"KEV catalogue: {refresh_kev(dry_run=args.dry_run)} known-exploited CVEs")
    badged, unbadged = sync_kev_badges(dry_run=args.dry_run)
    print(f"KEV badges: {badged} written, {unbadged} withdrawn")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
