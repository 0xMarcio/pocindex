from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import re
import urllib.request
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Collection, Dict, Iterable, List, Optional
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parents[1]
CVES = ROOT / "cves"
INDEX = ROOT / "index"
DOCS_DIR = ROOT / "docs"
BLACKLIST = INDEX / "blacklist.txt"
TRENDING_INPUT = INDEX / "trending.json"
CVE_OUTPUT = DOCS_DIR / "CVE_list.json"
TRENDING_OUTPUT = DOCS_DIR / "trending_poc.json"
REPO_META = INDEX / "repo_meta.json"
REPO_META_OUTPUT = DOCS_DIR / "repo_meta.json"
KEV_INPUT = INDEX / "kev.json"
DATES_INPUT = INDEX / "cve_dates.json"
KEV_OUTPUT = DOCS_DIR / "kev.json"
NUCLEI_INPUT = INDEX / "nuclei.json"
NUCLEI_OUTPUT = DOCS_DIR / "nuclei.json"
METADATA_INPUT = INDEX / "metadata"
METADATA_OUTPUT = DOCS_DIR / "cve_metadata.json"
# The same metadata in the two halves the page loads apart: the CVSS rows the
# severity filter needs before anything can be searched, and the advisories
# only a rendered row shows. cve_metadata.json stays whole for API readers.
CVSS_OUTPUT = DOCS_DIR / "cvss.json"
ADVISORIES_OUTPUT = DOCS_DIR / "advisories.json"
VERIFIED_REFERENCES = INDEX / "reference_pocs.txt"
EPSS_OUTPUT = DOCS_DIR / "epss.json"
EPSS_FEED = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
GITHUB_NON_REPOS = {
    "advisories", "apps", "collections", "marketplace", "notifications",
    "orgs", "security", "settings", "sponsors", "topics", "user-attachments",
}
CODE_SUFFIXES = {
    ".c", ".cc", ".cpp", ".cs", ".go", ".java", ".js", ".md", ".nse",
    ".php", ".pl", ".ps1", ".py", ".rb", ".rs", ".sh", ".ts", ".txt",
    ".yaml", ".yml", ".zip",
}
MEDIA_SUFFIXES = {
    ".bmp", ".gif", ".jpeg", ".jpg", ".mov", ".mp4", ".pdf", ".png",
    ".svg", ".webm", ".webp",
}


def load_blacklist() -> set[str]:
    if not BLACKLIST.exists():
        return set()
    return {
        line.strip().lower()
        for line in BLACKLIST.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


def normalise_block(text: str) -> str:
    text = text.replace("\r\n", "\n")
    text = re.sub(r"\n{2,}", "\n", text.strip())
    lines = [
        re.sub(r"^#{1,6}\s+", "", line.lstrip("- ")).rstrip()
        for line in text.split("\n")
    ]
    return "\n".join(line for line in lines if line)


SECTION_HEADERS = ("### Description", "### POC", "#### Reference", "#### Github",
                   "#### Nuclei", "#### ExploitDB", "#### Metasploit", "#### Vulhub",
                   "#### Collections")
# Sections whose links are kept apart from the repository list, with the
# field each becomes in the published index.
CURATED = (
    ("#### Nuclei", "nuclei"),
    ("#### ExploitDB", "edb"),
    ("#### Metasploit", "msf"),
    ("#### Vulhub", "vulhub"),
    ("#### Collections", "collections"),
)


@lru_cache(maxsize=1)
def load_metadata() -> Dict[str, object]:
    """Canonical NVD metadata assembled from the tracked year shards."""
    entries: Dict[str, object] = {}
    if not METADATA_INPUT.exists():
        return entries
    for path in sorted(METADATA_INPUT.glob("[12][0-9][0-9][0-9].json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"{path} is not a CVE metadata object")
        entries.update(payload)
    return entries


@lru_cache(maxsize=1)
def load_verified_references() -> set[tuple[str, str]]:
    """CVE Program references with direct exploit evidence."""
    try:
        lines = VERIFIED_REFERENCES.read_text(encoding="utf-8").splitlines()
    except OSError:
        return set()
    verified: set[tuple[str, str]] = set()
    for line in lines:
        if " - " not in line:
            continue
        cve_id, url = line.split(" - ", 1)
        if cve_id and url:
            verified.add((cve_id, link_key(url)))
    return verified


BADGE = re.compile(r"!\[\]\(https://img\.shields\.io/static/v1\?label=(Vendor|Product)&message=([^&)]*)&")


def parse_preamble(content: str) -> tuple[str, List[str], List[str]]:
    """The record's title and its vendor and product badges, from above the description."""
    title = ""
    vendors: List[str] = []
    products: List[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped == "### Description":
            break
        if not title and len(stripped) > 4 and stripped.startswith("**") and stripped.endswith("**"):
            title = " ".join(stripped[2:-2].split())
            continue
        match = BADGE.match(stripped)
        if not match:
            continue
        value = " ".join(unquote(match.group(2)).split())
        if value and value.lower() != "n/a":
            (vendors if match.group(1) == "Vendor" else products).append(value)
    return title, vendors, products


def parse_sections(content: str) -> Dict[str, str]:
    """Split an entry on its own headings only.

    CVE text lifted from a GitHub advisory often opens with "### Impact" or
    "### Summary"; treating any heading as a boundary let a description end
    itself and vanish from the index.
    """
    sections: Dict[str, str] = {}
    current_header: Optional[str] = None
    buffer: List[str] = []

    for line in content.splitlines():
        header = line.strip()
        if header in SECTION_HEADERS:
            if current_header is not None:
                sections[current_header] = "\n".join(buffer).strip()
            current_header = header
            buffer = []
        else:
            buffer.append(line)

    if current_header is not None:
        sections[current_header] = "\n".join(buffer).strip()

    return sections


GITHUB_HOSTS = {"github.com", "www.github.com"}


def repo_from_url(url: str) -> str:
    """owner/repo for a GitHub URL, matching repoFromUrl in logic.js exactly.

    Two disagreements with the browser lived here. "github" as a substring of
    the host accepted notgithub.example.com as a repository, and a clone URL
    kept its .git suffix, so poc-rebar3.git and poc-rebar3 counted as two
    sources on the page and one in search. 273 CVEs disagreed across the two.
    """
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if host and host not in GITHUB_HOSTS:
            return ""
        path = parsed.path or url
    except Exception:
        path = url
    parts = path.strip("/").split("/")
    if len(parts) < 2 or parts[0].lower() in GITHUB_NON_REPOS:
        return ""
    owner, repo = parts[0].lower(), re.sub(r"\.git$", "", parts[1], flags=re.I).lower()
    return f"{owner}/{repo}" if repo else ""


def is_blacklisted(url: str, blacklist: Collection[str]) -> bool:
    full_name = repo_from_url(url)
    if not full_name:
        return False
    return full_name in blacklist


def link_key(url: str) -> str:
    parsed = urlparse(url)
    if (parsed.hostname or "").lower() not in {"github.com", "www.github.com"}:
        return url.rstrip("/")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        return url
    repo = f"{parts[0]}/{parts[1]}".lower()
    suffix = "/" + "/".join(parts[2:]) if len(parts) > 2 else ""
    return f"github:{repo}{suffix}?{parsed.query}#{parsed.fragment}"


def source_key(url: str) -> str:
    """Identity of one source, independent of a path inside its repository."""
    repo = repo_from_url(url)
    if repo and "/" in repo:
        return f"github:{repo}"
    return url.rstrip("/")


def poc_link_rank(url: str, cve_id: str) -> tuple[int, int]:
    """Choose the most useful path when one repository supplied several."""
    if not repo_from_url(url):
        return 0, len(url)
    parsed = urlparse(url)
    parts = [part for part in parsed.path.split("/") if part]
    suffix = "/".join(parts[2:]).lower()
    if not suffix:
        return 0, len(url)
    compact_cve = re.sub(r"[^a-z0-9]", "", cve_id.lower())
    compact_path = re.sub(r"[^a-z0-9]", "", suffix)
    if compact_cve and compact_cve in compact_path:
        return 1, len(url)
    extension = Path(parts[-1]).suffix.lower()
    if extension in CODE_SUFFIXES or "/security/advisories/" in parsed.path.lower():
        return 2, len(url)
    if re.search(r"(?:^|/)(?:poc|exploit|reproducer)(?:/|$)", suffix):
        return 3, len(url)
    if extension in MEDIA_SUFFIXES:
        return 6, len(url)
    return 4, len(url)


def dedupe_source_links(urls: Iterable[str], cve_id: str) -> List[str]:
    selected: Dict[str, tuple[int, str]] = {}
    order: Dict[str, int] = {}
    for index, url in enumerate(urls):
        key = source_key(url)
        order.setdefault(key, index)
        current = selected.get(key)
        if current is None or poc_link_rank(url, cve_id) < poc_link_rank(current[1], cve_id):
            selected[key] = (index, url)
    return [selected[key][1] for key in sorted(selected, key=order.get)]


def advisory_rank(row: list, cve_id: str) -> tuple[int, int, int]:
    url = str(row[0])
    tags = set(row[1] if len(row) > 1 and isinstance(row[1], list) else [])
    if "GitHub Advisory" in tags or "/security/advisories/" in url.lower():
        tag_rank = 0
    elif "Exploit" in tags:
        tag_rank = 1
    elif "Vendor Advisory" in tags:
        tag_rank = 2
    elif "Third Party Advisory" in tags or "Advisory" in tags:
        tag_rank = 3
    elif "Issue Tracking" in tags:
        tag_rank = 4
    elif "Patch" in tags:
        tag_rank = 5
    else:
        tag_rank = 6
    path_rank, length = poc_link_rank(url, cve_id)
    return tag_rank, path_rank, length


def dedupe_advisories(rows: Iterable[list], cve_id: str) -> List[list]:
    selected: Dict[str, list] = {}
    order: Dict[str, int] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, list) or not row:
            continue
        key = source_key(str(row[0]))
        order.setdefault(key, index)
        current = selected.get(key)
        if current is None or advisory_rank(row, cve_id) < advisory_rank(current, cve_id):
            selected[key] = row
    return [selected[key] for key in sorted(selected, key=order.get)]


def reference_is_verified_poc(
    cve_id: str,
    url: str,
    metadata: Dict[str, object],
    verified: Collection[tuple[str, str]],
) -> bool:
    key = link_key(url)
    if (cve_id, key) in verified:
        return True
    for row in (metadata.get(cve_id) or {}).get("advisories", []):
        if not isinstance(row, list) or not row:
            continue
        tags = row[1] if len(row) > 1 and isinstance(row[1], list) else []
        if "Exploit" in tags and link_key(str(row[0])) == key:
            return True
    return False


def collect_links(block: str, *, blacklist: Optional[Collection[str]] = None) -> List[str]:
    links: List[str] = []
    blacklist = blacklist or set()
    for raw in block.splitlines():
        entry = raw.strip()
        if not entry or "No PoCs" in entry:
            continue
        if entry.startswith("- "):
            entry = entry[2:].strip()
        if not entry:
            continue
        if is_blacklisted(entry, blacklist):
            continue
        if entry not in links:
            links.append(entry)
    return links


def build_cve_list(blacklist: Collection[str]) -> tuple[List[Dict[str, object]], int]:
    cve_entries = []
    dates = load_dates()
    metadata = load_metadata()
    verified_references = load_verified_references()
    total = 0

    for md_path in sorted(CVES.glob("[12][0-9][0-9][0-9]/CVE-*.md")):
        cve_id = md_path.stem
        if (metadata.get(cve_id) or {}).get("rejected"):
            continue
        total += 1
        content = md_path.read_text(encoding="utf-8")
        sections = parse_sections(content)
        description = normalise_block(sections.get("### Description", ""))
        references = collect_links(sections.get("#### Reference", ""), blacklist=blacklist)
        github_links = collect_links(sections.get("#### Github", ""), blacklist=blacklist)
        # These stay in their own lists: a template, an ExploitDB entry and a
        # Metasploit module are none of them somebody's repository, and should
        # not be ranked, starred or credited as one.
        curated = {
            field: dedupe_source_links(
                collect_links(sections.get(header, ""), blacklist=blacklist),
                cve_id,
            )
            for header, field in CURATED
        }
        curated_keys = {
            source_key(url)
            for links in curated.values()
            for url in links
        }
        poc_candidates: List[str] = []
        for link in references:
            key = source_key(link)
            if (
                key not in curated_keys
                and reference_is_verified_poc(cve_id, link, metadata, verified_references)
            ):
                poc_candidates.append(link)
        for link in github_links:
            if source_key(link) not in curated_keys:
                poc_candidates.append(link)
        poc_entries = dedupe_source_links(poc_candidates, cve_id)

        if not poc_entries and not any(curated.values()):
            continue

        entry = {
            "cve": cve_id,
            "desc": description,
            "poc": poc_entries,
        }
        title, vendors, products = parse_preamble(content)
        if title:
            entry["title"] = title
        if vendors:
            entry["vendor"] = vendors
        if products:
            entry["product"] = products
        published, modified = (dates.get(cve_id) or ["", ""])[:2]
        if published:
            entry["published"] = published
        if modified and modified != published:
            entry["modified"] = modified
        entry.update({field: links for field, links in curated.items() if links})
        cve_entries.append(entry)

    return cve_entries, total


def build_repo_meta(cve_entries: List[Dict[str, object]]) -> Dict[str, object]:
    """Star count and last-push date for the repositories the index actually links."""
    try:
        stored = json.loads(REPO_META.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    linked = {
        repo_from_url(url)
        for entry in cve_entries
        for url in entry["poc"]
        if repo_from_url(url)
    }
    return {name: value for name, value in stored.items() if name in linked}


def load_dates() -> Dict[str, list]:
    """When the CVE Program first published each record and last changed it."""
    try:
        return json.loads(DATES_INPUT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def build_kev(cve_entries: List[Dict[str, object]]) -> Dict[str, object]:
    """CISA's known-exploited entries, limited to CVEs the index carries."""
    try:
        stored = json.loads(KEV_INPUT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    have = {str(entry["cve"]) for entry in cve_entries}
    return {cve: value for cve, value in stored.items() if cve in have}


def build_nuclei(cve_entries: List[Dict[str, object]]) -> Dict[str, object]:
    """Severity, CVSS and CWE per CVE, limited to the ones indexed."""
    try:
        stored = json.loads(NUCLEI_INPUT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    have = {str(entry["cve"]) for entry in cve_entries}
    keep = ("severity", "cvss", "cvss_vector", "cwe")
    return {
        cve: {field: value[field] for field in keep if field in value}
        for cve, value in stored.items()
        if cve in have
    }


def build_metadata(cve_entries: List[Dict[str, object]]) -> Dict[str, object]:
    """CVSS generations and vetted advisories for CVEs published on the site."""
    have = {str(entry["cve"]) for entry in cve_entries}
    published: Dict[str, object] = {}
    for cve, value in load_metadata().items():
        if cve not in have or not isinstance(value, dict):
            continue
        entry: Dict[str, object] = {}
        if value.get("cvss"):
            entry["cvss"] = value["cvss"]
        advisories = dedupe_advisories(value.get("advisories", []), cve)
        if advisories:
            entry["advisories"] = advisories
        if entry:
            published[cve] = entry
    return published


def build_epss(cve_entries: List[Dict[str, object]]) -> Dict[str, object]:
    """FIRST's exploitation probability, limited to the CVEs indexed.

    EPSS answers the question the PoC count cannot: of everything with exploit
    code published, which is actually being used. The feed covers essentially
    the whole index, so it is fetched here rather than tracked in the
    repository, where a daily rescore of 366,000 rows would be pure churn.

    A failure raises rather than returning {}. Swallowing it published an empty
    epss.json, which is not "EPSS is missing" to a reader: every score silently
    disappears from 82,000 pages and the site looks like it never had them. A
    build that cannot get the feed should not replace the one that did.
    """
    try:
        with urllib.request.urlopen(EPSS_FEED, timeout=180) as response:
            raw = gzip.decompress(response.read()).decode("utf-8", "replace")
    except Exception as problem:
        raise RuntimeError(f"EPSS feed unavailable: {problem}") from problem
    have = {str(entry["cve"]) for entry in cve_entries}
    text = io.StringIO(raw)
    text.readline()  # the feed opens with a model version comment, not a header
    scores: Dict[str, object] = {}
    for row in csv.DictReader(text):
        cve = (row.get("cve") or "").strip().upper()
        if cve not in have:
            continue
        try:
            scores[cve] = [round(float(row["epss"]), 5), round(float(row["percentile"]), 4)]
        except (KeyError, TypeError, ValueError):
            continue
    # The feed normally covers the whole index. A truncated or reshaped one
    # parses cleanly and yields a handful of rows, which would ship as a real
    # build; anything below nine in ten CVEs is a broken feed, not news.
    if have and len(scores) < 0.9 * len(have):
        raise RuntimeError(
            f"EPSS feed covered {len(scores):,} of {len(have):,} indexed CVEs; "
            "refusing to publish a partial rescore"
        )
    return scores


def build_trending(blacklist: Collection[str]) -> List[Dict[str, object]]:
    """The trending job's own output, minus anything the blacklist covers."""
    try:
        rows = json.loads(TRENDING_INPUT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return [
        row for row in rows
        if row.get("url") and not is_blacklisted(str(row["url"]), blacklist)
    ]


def write_json(path: Path, data, *, indent: Optional[int] = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=indent,
                  separators=None if indent else (",", ":"))


def main() -> int:
    argparse.ArgumentParser(description="Build the CVE PoC site data files").parse_args()

    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    blacklist = load_blacklist()

    cve_payload, total_cves = build_cve_list(blacklist)
    write_json(CVE_OUTPUT, cve_payload)

    repo_meta = build_repo_meta(cve_payload)
    write_json(REPO_META_OUTPUT, repo_meta)

    kev = build_kev(cve_payload)
    write_json(KEV_OUTPUT, kev)

    nuclei = build_nuclei(cve_payload)
    write_json(NUCLEI_OUTPUT, nuclei)

    metadata = build_metadata(cve_payload)
    write_json(METADATA_OUTPUT, metadata)
    write_json(CVSS_OUTPUT, {cve: value["cvss"] for cve, value in metadata.items() if value.get("cvss")})
    write_json(ADVISORIES_OUTPUT, {cve: value["advisories"] for cve, value in metadata.items() if value.get("advisories")})

    epss = build_epss(cve_payload)
    write_json(EPSS_OUTPUT, epss)

    trending_items = build_trending(blacklist)
    indexed = {entry["cve"] for entry in cve_payload}
    for item in trending_items:
        # Only link to detail pages that this build will actually publish.
        item["page"] = f"/{item['cve']}" if item.get("cve") in indexed else None
    write_json(
        TRENDING_OUTPUT,
        {
            "generated": datetime.now(timezone.utc).isoformat(),
            "total_cves": total_cves,
            "with_pocs": len(cve_payload),
            "items": trending_items,
        },
        indent=2,
    )

    print(
        f"Wrote {CVE_OUTPUT.name} ({len(cve_payload)} of {total_cves} CVEs), "
        f"{REPO_META_OUTPUT.name} ({len(repo_meta)} repositories), "
        f"{KEV_OUTPUT.name} ({len(kev)} known-exploited), "
        f"{NUCLEI_OUTPUT.name} ({len(nuclei)} rated), "
        f"{METADATA_OUTPUT.name} ({len(metadata)} enriched), "
        f"{EPSS_OUTPUT.name} ({len(epss)} scored) and {TRENDING_OUTPUT.name}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
