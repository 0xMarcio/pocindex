#!/usr/bin/env python3
"""Fold nuclei templates into the index.

A template is a runnable check for one CVE, which makes it a proof of concept
in its own right, and it carries the severity, CVSS, EPSS and CWE the markdown
entries never had. Both are picked up here: the template link joins the PoC
list for its CVE, and the ratings land in nuclei.json for the site to read.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import tarfile
import urllib.request
from collections import defaultdict
from pathlib import Path
from urllib.parse import quote

import releases
import link_health
from update_cves import ensure_cve_entries

ROOT = Path(__file__).resolve().parents[1]
CVES = ROOT / "cves"
INDEX = ROOT / "index"
OUTPUT = INDEX / "nuclei.json"
def source(repo: str, branch: str = "main", *, scoped: bool = False) -> tuple:
    """A template repository: where to fetch it and how to link into it.

    ProjectDiscovery keeps templates for everything, so only its cves/ tree
    counts. The community repositories below are nothing but CVE templates,
    where that scoping would throw the whole repository away.
    """
    return (
        repo,
        f"https://codeload.github.com/{repo}/tar.gz/refs/heads/{branch}",
        f"https://github.com/{repo}/blob/{branch}/",
        scoped,
    )


# Source order determines metadata precedence; all qualifying links are kept.
SOURCES = (
    source("projectdiscovery/nuclei-templates", scoped=True),
    source("topscoder/nuclei-wordfence-cve"),
    source("linuxadi/40k-nuclei-templates"),
    source("CharanRayudu/Custom-Nuclei-Templates"),
    source("geeknik/the-nuclei-templates"),
    source("Akokonunes/Private-Nuclei-Templates"),
)
SECTION = "#### Nuclei"
EMPTY = "No nuclei template."
# ProjectDiscovery names a template for its CVE and nothing else. Wordfence
# appends the plugin slug and an advisory uuid, so the id is a prefix there.
TEMPLATE_NAME = re.compile(r"^(CVE-\d{4}-\d{4,7})(?:[-_.][^/]*)?\.ya?ml$", re.IGNORECASE)
USER_AGENT = "0xMarcio-cve-nuclei"

# The fields wanted are plain scalars on their own line inside info:, so they
# are read directly rather than pulling a YAML parser into a stdlib-only job.
FIELDS = {
    "name": re.compile(r"^  name:\s*(.+?)\s*$", re.M),
    "severity": re.compile(r"^\s{2,4}severity:\s*([a-z]+)\s*$", re.M),
    "cvss": re.compile(r"^\s+cvss-score:\s*([0-9.]+)\s*$", re.M),
    "cvss_vector": re.compile(r"^\s+cvss-metrics:\s*(\S+)\s*$", re.M),
    "cwe": re.compile(r"^\s+cwe-id:\s*(CWE-\d+)\s*$", re.M | re.I),
}


def download(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=900) as response:
        return response.read()


# A template that only fetches a plugin's readme and compares the version it
# finds has not proven anything: it reports that a vulnerable release is
# installed. Wordfence publishes tens of thousands of these, and filing one as
# a proof of concept claims something the file does not do.
PROTOCOL = re.compile(
    r"\n(?:requests|http|code|network|javascript|dns|file|headless|ssl|websocket|tcp):"
)
METADATA_PATH = re.compile(r"(readme\.txt|readme\.md|style\.css|changelog\.txt)\s*$", re.I)
REQUEST_PATH = re.compile(r'''-\s*["']?\{\{BaseURL\}\}([^"'\n]*)''')
EXERCISES_BUG = re.compile(r"\braw:|\bmethod:\s*(?:POST|PUT|PATCH|DELETE)|payloads:|\bbody:|fuzzing:")


def version_probe_only(text: str) -> bool:
    """True when the template only reads a version string."""
    parts = PROTOCOL.split(text, maxsplit=1)
    if len(parts) < 2:
        return False
    body = parts[1]
    if EXERCISES_BUG.search(body):
        return False
    paths = REQUEST_PATH.findall(body)
    request_paths = re.findall(r'''(?m)^\s*-\s*["']?(?:\{\{[^}]+\}\}|https?://)''', body)
    if len(PROTOCOL.findall(text)) != 1 or len(request_paths) != len(paths) or not paths:
        return False
    if all(METADATA_PATH.search(path) for path in paths):
        return True
    if all(re.fullmatch(r'/wp-content/plugins/[^/?#]+/languages/[^/?#]+\.pot\s*', path) for path in paths) and re.search(
        r'compare_versions\(\s*version\s*,', body,
    ):
        return True
    if (all(path in {"", "/", "/login", "/login.html", "/login.php"} for path in paths)
            and not re.search(r"\bheaders:|\bcookie:|\bcookies:|\bunsafe:|\brace:", body)
            and re.search(r"compare_versions\(\s*(?:version|detected_version)\s*,", body)
            and re.search(r"\bname:\s*(?:version|detected_version)\s*$", body, re.M)):
        return True
    # WordPress core probes extract versions from landing/install/feed pages.
    # A version comparison alongside an actual exploit request must stay.
    return all(
        path in {"", "/", "/wp-admin/install.php", "/feed/", "/?feed=rss2"} for path in paths
    ) and bool(re.search(r"compare_versions\(\s*version_by_(?:generator|js|css)\b", body)) and bool(
        re.search(r"\bname:\s*version_by_(?:generator|js|css)\b", body)
    )


def parse(text: str) -> dict:
    """Ratings for one template, dropping anything the template does not state."""
    head = text[:4000]
    found: dict[str, object] = {}
    for key, pattern in FIELDS.items():
        match = pattern.search(head)
        if not match:
            continue
        value = match.group(1).strip().strip('"\'')
        if key == "cvss":
            try:
                found[key] = round(float(value), 5)
            except ValueError:
                pass
        elif value:
            found[key] = value
    return found


def collect(archive: bytes, blob: str, scoped: bool, *, seen: set[tuple[str, str]] | None = None) -> dict[str, dict]:
    """Every CVE template in the tarball, keyed by CVE id."""
    templates: dict[str, dict] = {}
    urls: dict[str, set[str]] = defaultdict(set)
    if seen is None:
        seen = set()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        for member in tar:
            if not member.isfile():
                continue
            parts = Path(member.name).parts
            named = TEMPLATE_NAME.match(parts[-1])
            if not named:
                continue
            if scoped and "cves" not in parts:
                continue
            handle = tar.extractfile(member)
            if handle is None:
                continue
            text = handle.read().decode("utf-8", "replace")
            if version_probe_only(text):
                continue
            cve = named.group(1).upper()
            template_id = re.search(r"(?m)^id:\s*([^\n]+)", text)
            declared = set(re.findall(r"CVE-\d{4}-\d{4,7}", template_id[1].upper())) if template_id else set()
            if declared and cve not in declared:
                continue
            relative = "/".join(parts[1:])
            url = blob + quote(relative, safe="/")
            if link_health.unavailable(url):
                continue
            content = re.sub(r"(?m)^# digest:[^\n]*(?:\n|$)", "", text.replace("\r\n", "\n"))
            identity = (cve, hashlib.sha256(content.encode()).hexdigest())
            if identity in seen:
                continue
            seen.add(identity)
            entry = parse(text)
            entry["url"] = url
            urls[cve].add(entry["url"])
            if len(entry) >= len(templates.get(cve, {})):
                templates[cve] = entry
    for cve, entry in templates.items():
        entry["urls"] = sorted(urls[cve])
    return templates


def section_bounds(text: str, header: str) -> tuple[int, int] | None:
    start = text.find("\n" + header)
    if start < 0:
        return None
    body = start + 1 + len(header)
    nxt = text.find("\n#", body)
    return body, len(text) if nxt < 0 else nxt


def apply_to_markdown(cve: str, urls: list[str], dry_run: bool) -> str:
    """Replace the CVE's template links with the current qualifying set."""
    import link_health
    urls = list(dict.fromkeys(url for url in urls if not link_health.unavailable(url)))
    path = CVES / cve.split("-")[1] / f"{cve}.md"
    if not path.exists():
        return "absent"
    if not urls:
        return "added" if drop_section(path, dry_run) else "unchanged"
    original = path.read_text(encoding="utf-8")
    block = "\n" + "\n".join(f"- {url}" for url in urls) + "\n"
    bounds = section_bounds(original, SECTION)
    if bounds:
        start, end = bounds
        updated = original[:start] + block + original[end:]
    else:
        updated = original.rstrip("\n") + f"\n\n{SECTION}" + block
    if updated == original:
        return "unchanged"
    if not dry_run:
        path.write_text(updated, encoding="utf-8")
    return "added"


def drop_section(path: Path, dry_run: bool) -> bool:
    """Remove the nuclei section from an entry no template covers any more."""
    original = path.read_text(encoding="utf-8")
    bounds = section_bounds(original, SECTION)
    if not bounds:
        return False
    head = original.rfind("\n" + SECTION, 0, bounds[0] + 1)
    if head < 0:
        return False
    updated = (original[:head] + original[bounds[1]:]).rstrip("\n") + "\n"
    if not dry_run:
        path.write_text(updated, encoding="utf-8")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync nuclei templates into the index")
    parser.add_argument("--dry-run", action="store_true", help="report without writing")
    parser.add_argument("--cvelist-dir", type=Path, help="local CVE List V5 root for a large backfill")
    args = parser.parse_args()

    templates: dict[str, dict] = {}
    seen: set[tuple[str, str]] = set()
    failures: list[str] = []
    for repo, tarball, blob, scoped in SOURCES:
        try:
            found = collect(download(tarball), blob, scoped, seen=seen)
        except Exception as problem:
            print(f"{repo}: unavailable ({problem})")
            failures.append(repo)
            continue
        fresh = {cve: entry for cve, entry in found.items() if cve not in templates}
        for cve in templates.keys() & found.keys():
            templates[cve]["urls"] = list(dict.fromkeys(templates[cve]["urls"] + found[cve]["urls"]))
        templates.update(fresh)
        print(f"{repo}: {len(found):,} CVE templates, {len(fresh):,} not already covered")
    if failures:
        print(
            "No files changed because a source was unavailable: " + ", ".join(failures)
        )
        return 1
    print(f"{len(templates):,} CVEs templated in total")

    created, unavailable = ensure_cve_entries(
        templates,
        dry_run=args.dry_run,
        cvelist_dir=args.cvelist_dir,
    )
    if created or unavailable:
        verb = "would create" if args.dry_run else "created"
        print(f"base entries: {len(created):,} {verb}, {len(unavailable):,} unpublished or unavailable")

    tally = {"added": 0, "unchanged": 0, "absent": 0}
    for cve, entry in sorted(templates.items()):
        tally[apply_to_markdown(cve, entry["urls"], args.dry_run)] += 1

    # An entry whose template stopped qualifying is never visited above, so its
    # section would otherwise outlive the reason it was written.
    stale = 0
    for path in CVES.glob("[12][0-9][0-9][0-9]/CVE-*.md"):
        if path.stem in templates:
            continue
        if SECTION in path.read_text(encoding="utf-8", errors="replace"):
            stale += drop_section(path, args.dry_run)

    payload = {cve: entry for cve, entry in sorted(templates.items())}
    if not args.dry_run:
        with OUTPUT.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=0, sort_keys=True)
            handle.write("\n")

    if not args.dry_run:
        releases.save_ledger(releases.reconcile(releases.load_ledger(), releases.published_pairs()))

    rated = sum(1 for e in payload.values() if "cvss" in e)
    print(f"markdown: {tally['added']:,} links added, {tally['unchanged']:,} already there, "
          f"{tally['absent']:,} for CVEs not in the index, {stale:,} sections withdrawn")
    print(f"{OUTPUT.name}: {len(payload):,} CVEs, {rated:,} with CVSS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
