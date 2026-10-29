#!/usr/bin/env python3
"""Prune PoC links to deleted repositories and refresh the metadata the site shows."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

from update_cves import (
    readme_text,
    repo_is_bare,
    repository_is_nonpublic,
    GITHUB_GRAPHQL_URL,
    kev_badge,
    GitHubClient,
    http_json,
    is_blacklisted_repo,
    is_valid_cve,
    load_blacklist,
    replace_section,
    section_links,
)
import link_health

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
    "#### Nuclei": "No PoCs from Nuclei.",
    "#### ExploitDB": "No PoCs from ExploitDB.",
    "#### Metasploit": "No PoCs from Metasploit.",
    "#### Vulhub": "No PoCs from Vulhub.",
    "#### Collections": "No PoCs from collections.",
}
GITHUB_EMPTY = "No PoCs found on GitHub currently."
BATCH = 20


def collect_repositories() -> tuple[dict[str, list[tuple[Path, str]]], set[str]]:
    """Map prunable links to their entries, and name every repository the site shows.

    The GitHub section also has a content-quality check. Confirmed public
    availability failures are pruned from every section by prune_unavailable.
    """
    prunable: dict[str, list[tuple[Path, str]]] = {}
    referenced: set[str] = set()
    from build_site import CURATED, repo_from_url
    for path in sorted(CVES.glob("[12][0-9][0-9][0-9]/CVE-*.md")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for url in section_links(text, GITHUB_SECTION):
            full_name = repo_from_url(url)
            if full_name and "/" in full_name:
                prunable.setdefault(full_name, []).append((path, url))
                referenced.add(full_name)
        for url in section_links(text, REFERENCE_SECTION):
            full_name = repo_from_url(url)
            if full_name and "/" in full_name:
                referenced.add(full_name)
        for section, _ in CURATED:
            referenced.update(name for url in section_links(text, section)
                              if (name := repo_from_url(url)))
    return prunable, referenced


REPO_FIELDS = (
    "{ nameWithOwner databaseId createdAt description isFork isPrivate visibility stargazerCount pushedAt "
    "repositoryTopics(first: 20) { nodes { topic { name } } } "
    'readmeMd: object(expression: "HEAD:README.md") { ... on Blob { text } } '
    'readmeUpper: object(expression: "HEAD:README.MD") { ... on Blob { text } } '
    'readmeRst: object(expression: "HEAD:README.rst") { ... on Blob { text } } '
    'readmeBare: object(expression: "HEAD:README") { ... on Blob { text } } '
    'root: object(expression: "HEAD:") { ... on Tree { entries { name type } } } }'
)


def survey(client: GitHubClient, names: list[str], *, recovery: dict | None = None) -> tuple[set[str], dict[str, list], set[str]]:
    """Return the repositories to drop, and stars/last push for the rest.

    Dropped means GitHub reports NOT_FOUND, or the repository is bare: no code,
    no directory, no artifact and a README with nothing runnable in it, which
    the discovery gate would reject today. Anything else, a network error or a
    throttle or an unexpected response, leaves the repository out of both
    results, so an audit failure never drops a link.
    """
    batches = [names[index : index + BATCH] for index in range(0, len(names), BATCH)]
    missing: set[str] = set()
    unavailable: set[str] = set()
    metadata: dict[str, list] = {}
    checked = 0

    def check(batch: list[str]) -> tuple[set[str], dict[str, list], set[str]]:
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
        absent: set[str] = set()
        errors = payload.get("errors") or []
        if any(not entry.get("path") for entry in errors):
            return set(), {}, set()
        found: dict[str, list] = {}
        data = payload.get("data") or {}
        for index, name in enumerate(batch):
            alias = f"r{index}"
            # A failed README or root lookup is not evidence of a bare repo.
            problems = [entry for entry in errors if entry["path"][0] == alias]
            if problems:
                if (all(entry.get("type") == "NOT_FOUND" and len(entry["path"]) == 1
                        for entry in problems)
                        and link_health.check_url(f"https://github.com/{name}") is False):
                    gone.add(name)
                    absent.add(name)
                continue
            repo = data.get(alias)
            if not repo:
                continue
            if repository_is_nonpublic(repo):
                if link_health.check_url(f"https://github.com/{name}") is False:
                    gone.add(name)
                    absent.add(name)
                continue
            if repo.get("isPrivate") is not False or repo.get("visibility") != "PUBLIC":
                continue
            if recovery is not None and name.lower() in recovery:
                recovery[name.lower()] = repo
            if repo_is_bare(repo, readme_text(repo)):
                gone.add(name)
                continue
            if type(repo.get("stargazerCount")) is not int or repo["stargazerCount"] < 0 or "pushedAt" not in repo:
                continue
            pushed = str(repo.get("pushedAt") or "")[:10]
            found[name.lower()] = [
                int(repo.get("stargazerCount") or 0),
                pushed,
            ]
        return gone, found, absent

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(check, batch): batch for batch in batches}
        for future in as_completed(futures):
            batch = futures[future]
            try:
                gone, found, absent = future.result()
                missing |= gone
                unavailable |= absent
                metadata.update(found)
            except Exception as exc:
                print(f"Kept {len(batch)} repositories after a failed check: {exc}", file=sys.stderr)
            checked += len(batch)
            if checked % 5000 < len(batch):
                print(f"Checked {checked} of {len(names)} repositories")
    return missing, metadata, unavailable


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
    """Exact artifact/reference URLs, including files inside healthy repositories."""
    references: dict[str, list[tuple[Path, str]]] = {}
    for path in sorted(CVES.glob("[12][0-9][0-9][0-9]/CVE-*.md")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for header in SECTION_EMPTY:
            for url in section_links(text, header):
                if not is_repository_url(url):
                    references.setdefault(url, []).append((path, header))
    return references


def is_repository_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return False
    return (parsed.hostname in {"github.com", "www.github.com"}
            and bool(link_health.repository(url))
            and len(parsed.path.strip("/").split("/")) == 2)


def restore_recovered(ledger: dict, repositories: dict, live_urls: set[str], *, dry_run: bool = False) -> int:
    """Restore previously published links after fresh availability and content checks."""
    from build_site import (CURATED, link_key, load_managed_references, load_metadata,
                            load_reference_exclusions, load_source_exclusions,
                            load_verified_references, reference_is_verified_poc)
    from update_cves import (append_inventory, load_record_state, markdown_record_status,
                             qualifying_repo_cves, reference_is_poc)
    from releases import timestamp
    blacklist, metadata, states = load_blacklist(), load_metadata(), load_record_state()
    excluded, source_excluded = load_reference_exclusions(), load_source_exclusions()
    managed, verified = load_managed_references(), load_verified_references()
    live = {link_health.url_key(url) for url in live_urls}
    headers = {field: header for header, field in CURATED}
    github, references = {}, {}
    manual = {}
    restored = 0
    for row in ledger.values():
        if row.get("gone_reason") != "unavailable":
            continue
        cve, url = row["cve"], row["url"]
        name, pair = link_health.repository(url), (cve, link_key(url))
        if (link_health.unavailable(url) or pair in excluded
                or (cve, name) in source_excluded
                or name and is_blacklisted_repo(name, blacklist)
                or (metadata.get(cve) or {}).get("rejected")
                or (states.get(cve) or {}).get("status") == "REJECTED"):
            continue
        repo = repositories.get(name)
        if name:
            if (not repo or repo.get("isPrivate") is not False or repo.get("visibility") != "PUBLIC"
                    or (row.get("repo") and row["repo"] != repo.get("databaseId"))):
                continue
            if not row.get("repo"):
                created, removed = timestamp(repo.get("createdAt")), timestamp(row.get("gone"))
                if not created or not removed or created > removed:
                    continue
        if is_repository_url(url):
            if cve not in qualifying_repo_cves(repo, int(cve.split("-")[1]), blacklist):
                continue
            header = GITHUB_SECTION
        else:
            if link_health.url_key(url) not in live:
                continue
            header = headers.get(row.get("field"), REFERENCE_SECTION)
        header = row.get("section") or header
        if header not in SECTION_EMPTY:
            continue
        manual_approval = bool(row.get("reference_verified") or reference_is_poc({"url": url}, blacklist, cve))
        if header == REFERENCE_SECTION:
            if pair in managed and pair not in verified:
                continue
            if not (manual_approval or reference_is_verified_poc(cve, url, metadata, verified)):
                continue
        path = CVES / cve.split("-")[1] / f"{cve}.md"
        if not path.exists():
            continue
        with path.open(encoding="utf-8", newline="") as handle:
            text = handle.read()
        if markdown_record_status(text) in {"REJECTED", "ABSENT"}:
            continue
        existing = section_links(text, header)
        updated, changed = replace_section(text, header, [*existing, url], SECTION_EMPTY[header])
        if not changed and url not in existing:
            continue
        restored += int(changed)
        if changed and not dry_run:
            with path.open("w", encoding="utf-8", newline="") as handle:
                handle.write(updated)
        if header == GITHUB_SECTION:
            github.setdefault(cve, []).append(url)
        elif header == REFERENCE_SECTION:
            references.setdefault(cve, []).append(url)
            if manual_approval and pair not in managed:
                manual.setdefault(cve, []).append(url)
    append_inventory(GITHUB_LIST, github, dry_run=dry_run)
    append_inventory(REFERENCE_LIST, references, dry_run=dry_run)
    append_inventory(INDEX / "reference_pocs.txt", manual, dry_run=dry_run)
    print(f"Restored {restored} previously unavailable PoC links")
    return restored


def prune_unavailable(*, dry_run: bool = False) -> tuple[int, int]:
    """Apply confirmed findings to every source, inventory and front-page cache."""
    if not any(link_health.load().values()):
        return 0, 0
    changed = removed = 0
    for path in sorted(CVES.glob("[12][0-9][0-9][0-9]/CVE-*.md")):
        with path.open(encoding="utf-8", newline="") as handle:
            original = text = handle.read()
        for header, empty in SECTION_EMPTY.items():
            links = section_links(text, header)
            kept = [url for url in links if not link_health.unavailable(url)]
            if len(kept) != len(links):
                removed += len(links) - len(kept)
                text, _ = replace_section(text, header, kept, empty)
        if text != original:
            changed += 1
            if not dry_run:
                with path.open("w", encoding="utf-8", newline="") as handle:
                    handle.write(text)
    for path in (GITHUB_LIST, REFERENCE_LIST, INDEX / "reference_pocs.txt"):
        if path.exists():
            lines = path.read_text(encoding="utf-8").splitlines()
            kept = [line for line in lines if not link_health.unavailable(line.rsplit(" - ", 1)[-1].strip())]
            if len(kept) != len(lines) and not dry_run:
                path.write_text("\n".join(kept) + "\n", encoding="utf-8")
    trending = INDEX / "trending.json"
    if trending.exists():
        rows = json.loads(trending.read_text(encoding="utf-8"))
        kept = [row for row in rows if not link_health.unavailable(row.get("url") or "")]
        if len(kept) != len(rows) and not dry_run:
            trending.write_text(json.dumps(kept, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    readme = ROOT / "README.md"
    if readme.exists():
        lines = readme.read_text(encoding="utf-8").splitlines(keepends=True)
        kept = [line for line in lines if not (line.startswith("|") and any(
            link_health.unavailable(url) for url in re.findall(r"\]\((https?://[^\s)]+)\)", line)))]
        if kept != lines and not dry_run:
            readme.write_text("".join(kept), encoding="utf-8")
    print(f"Confirmed unavailable links: {removed} removed from {changed} CVE entries")
    return changed, removed


def interleave_by_host(urls: list[str]) -> list[str]:
    """Round-robin the hosts so a slice does not hammer one server in a burst."""
    hosts: dict[str, list[str]] = {}
    for url in urls:
        try:
            host = urlsplit(url).netloc.lower()
        except ValueError:
            host = ""
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
    return link_health.survey_urls(urls, workers=workers, timeout=timeout)[0]


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
    rotating = slice_after(names, str(state.get("cursor") or ""), args.limit)
    from releases import load_ledger
    ledger = load_ledger()
    recoverable = [row for row in ledger.values() if row.get("gone_reason") == "unavailable"]
    recovery_urls = (slice_after(sorted(set(link_health.load()["urls"]) | {
        link_health.url_key(row["url"]) for row in recoverable if not is_repository_url(row["url"])}),
        str(state.get("recovery_cursor") or ""), 1000) if args.references else [])
    recovery_names = slice_after(sorted({name for row in recoverable
                                        if (name := link_health.repository(row["url"]))}),
                                 str(state.get("repository_recovery_cursor") or ""), 1000)
    recovery = dict.fromkeys(set(recovery_names) | {name for url in recovery_urls
                                                   if (name := link_health.repository(url))})
    scope = sorted(set(rotating) | set(link_health.load()["repositories"]) | recovery.keys())
    print(f"Checking {len(scope)} repositories starting after {state.get('cursor') or 'the beginning'}")

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    blocked = {
        name for name in references
        if is_blacklisted_repo(name, load_blacklist())
    }
    missing, metadata, unavailable = survey(
        GitHubClient(token),
        [name for name in scope if name not in blocked],
        recovery=recovery,
    )
    print(f"{len(missing)} repositories no longer exist or hold nothing runnable")
    if not args.dry_run:
        link_health.record(missing=unavailable, healthy=metadata)
    if blocked:
        print(f"Pruning {len(blocked)} explicitly blacklisted repositories")
    missing |= blocked
    deferred = set(scope) - missing - metadata.keys()
    if deferred:
        print(f"::warning::{len(deferred)} repository checks were inconclusive; existing links retained")

    entries, links, dead_urls = prune_entries(references, missing, dry_run=args.dry_run)
    inventory = prune_inventory(dead_urls, dry_run=args.dry_run)
    alive = {name.lower() for name in names if name not in missing} | metadata.keys()
    tracked = save_metadata(metadata, alive, dry_run=args.dry_run)
    state["cursor"] = rotating[-1] if rotating else ""
    state["repository_recovery_cursor"] = recovery_names[-1] if recovery_names else ""

    print(f"Removed {links} links from {entries} entries | {inventory} inventory lines")
    print(f"Refreshed stars and last-push for {len(metadata)} repositories | {tracked} tracked")

    live = set()
    if args.references:
        references = collect_references()
        urls = sorted(references)
        window = slice_after(urls, str(state.get("reference_cursor") or ""),
                             0 if args.references < 0 else args.references)
        # Recovery gets a separate bounded rotation, so historical failures
        # cannot consume the entire audit and starve the still-published URLs.
        selected = sorted(set(window) | set(recovery_urls))
        print(f"Checking {len(selected)} of {len(urls)} artifact/reference links")
        gone, live = link_health.survey_urls(
            interleave_by_host(selected), workers=args.workers, timeout=args.timeout)
        if not args.dry_run:
            link_health.record(dead_urls=gone, live_urls=live)
        ref_links, ref_lines = prune_references(references, gone, dry_run=args.dry_run)
        state["reference_cursor"] = window[-1] if window else ""
        state["recovery_cursor"] = recovery_urls[-1] if recovery_urls else ""
        print(f"Reference links returning 404 or 410: {len(gone)} | "
              f"removed {ref_links} links, {ref_lines} inventory lines")

    restore_recovered(ledger, recovery, live, dry_run=args.dry_run)
    prune_unavailable(dry_run=args.dry_run)
    state["checked"] = datetime.now(timezone.utc).isoformat()
    save_state(state, dry_run=args.dry_run)
    print(f"KEV catalogue: {refresh_kev(dry_run=args.dry_run)} known-exploited CVEs")
    badged, unbadged = sync_kev_badges(dry_run=args.dry_run)
    print(f"KEV badges: {badged} written, {unbadged} withdrawn")
    return int(bool(deferred))


if __name__ == "__main__":
    raise SystemExit(main())
