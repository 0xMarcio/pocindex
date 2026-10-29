#!/usr/bin/env python3
"""Render one static page per CVE, at the site root.

The index held 82,000 CVEs behind a single URL. Every one of them is a query
somebody types ("CVE-2026-72898 poc"), and the pages that answered those queries
belonged to other people. These are flat files at /CVE-2026-72898, no prefix and
no extension: GitHub Pages resolves an extensionless request to the .html beside
it, verified against the live site rather than assumed.

Nothing here is committed. The payloads this reads are already gitignored and
built in CI, so the pages go straight into the Pages artifact and git never sees
them. Rendering all of them costs about fifteen seconds.
"""

from __future__ import annotations

import html
import hashlib
import json
import re
import os
import sys
from collections import defaultdict
from datetime import date, datetime, timezone
from decimal import ROUND_HALF_UP, Decimal
from functools import lru_cache
from string import Template
from urllib import error, request
from urllib.parse import unquote, urlsplit

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from brand import BRAND, DESCRIPTION, FONTS, REPO_LINK, SITE, SLUG, SOURCES_LINE, SPONSOR_LINK, SUBTITLE, TITLE, host

DOCS = os.path.join(ROOT, "docs")
RELATED = 6
GITHUB = "https://github.com/"
SEVERITIES = {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
LASTMOD = "page_lastmod.json"
PAGE_STATE = "page_state.json"
TREND_ROWS = 20

SOURCES = (
    ("nuclei", "Nuclei templates", "projectdiscovery/nuclei-templates"),
    ("msf", "Metasploit modules", "rapid7/metasploit-framework"),
    ("edb", "ExploitDB entries", "exploit-db.com"),
    ("vulhub", "Vulhub environments", "vulhub/vulhub"),
    ("collections", "Exploit collections", ""),
)

# As logic.js labels curated paths: by leaf for these (CURATED there), and
# below these collection roots for the rest (COLLECTION_SOURCES there).
NAMED_BY_LEAF = {"zan8in/afrog", "chaitin/xray", "helloexp/0day", "tzwlhack/vulnerability"}
COLLECTION_ROOTS = {"google/security-research": "pocs/", "github/securitylab": "SecurityExploits/"}

# As logic.js reads them. A page snapshot is https on web.archive.org, a 14-digit
# UTC capture time and the http(s) page captured; a save request is not one.
WAYBACK = "https://web.archive.org/web/"
CAPTURE = re.compile(r'https://web\.archive\.org/web/([0-9]{14})/(https?://[^\x00-\x20\x7f"<>\\]+)')
AUTHORITY = re.compile(r"https?://([^/?#@\x00-\x20\x7f\\]*)(?=[/?#]|\Z)")
# A saved source file, as logic.js reads it: the raw bytes of one file at a
# pinned commit of the page's own GitHub repository, or the JSON of the page's
# own HackerOne report.
RAW_FILE = re.compile(r"https://raw\.githubusercontent\.com/([^/?#]+)/([^/?#]+)/([0-9a-f]{40})/([^?#]+)")
REPORT_PAGE = re.compile(r"https?://[^/?#]*/reports/([0-9]+)/?(?:[?#]|\Z)")
REPORT_JSON = re.compile(r"https://(?:www\.)?hackerone\.com/reports/([0-9]+)\.json")
DOT_SEGMENT = re.compile(r"(?:\.|%2e){1,2}", re.I)


@lru_cache(maxsize=2)
def asset_url(name: str) -> str:
    with open(os.path.join(DOCS, name), "rb") as handle:
        version = hashlib.sha256(handle.read()).hexdigest()[:16]
    return f"/{name}?v={version}"


def load(name: str) -> dict | list:
    with open(os.path.join(DOCS, name), encoding="utf-8") as handle:
        return json.load(handle)


def load_optional(name: str) -> dict:
    """An enrichment the pages render without. A missing file is empty; one that
    is present but not an object stops the build like any other bad input."""
    if not os.path.exists(os.path.join(DOCS, name)):
        return {}
    payload = load(name)
    if not isinstance(payload, dict):
        raise ValueError(f"Invalid {name}: expected a JSON object")
    return payload


def esc(value) -> str:
    return html.escape(str("" if value is None else value), quote=True)


def json_ld(payload: dict) -> str:
    """Serialise for a <script> block, which JSON escaping alone does not cover.

    json.dumps leaves < > and & raw, so a description carrying "</script>" ends
    the element and everything after it becomes live markup. 78 descriptions in
    the corpus already contain that sequence; only the 155-character trim keeps
    them out of the payload today. Escaping to \\u00XX keeps the JSON identical
    to a parser and inert to the HTML tokeniser.
    """
    text = json.dumps(payload, separators=(",", ":"))
    for char in ("<", ">", "&"):
        text = text.replace(char, f"\\u{ord(char):04x}")
    return text


def short(text: str, limit: int) -> str:
    text = " ".join((text or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rsplit(" ", 1)[0].rstrip(".,;: ") + "…"


def canonical_cvss(rows: list) -> list | None:
    """The first assessment, which is NVD's own where NVD scored the record.

    The search results take rows[0] and these pages took the highest score, so
    18,434 CVEs showed one severity in the list and another on the page. The
    primary assessment is the authority, and matching it makes the two agree.
    """
    for row in rows or []:
        if isinstance(row[1], (int, float)):
            return row
    return None


def unique_cvss(rows: list) -> list:
    """One row per distinct assessment.

    NVD, a CNA and the GitHub Advisory Database frequently publish the same
    vector, and the source column that told them apart was never rendered, so
    13,340 pages printed the same line two or three times over.
    """
    seen: set = set()
    kept = []
    for row in rows or []:
        if not isinstance(row[1], (int, float)):
            continue
        key = (str(row[0]), row[1], str(row[3]))
        if key in seen:
            continue
        seen.add(key)
        kept.append(row)
    return kept


ASSESSORS = {
    "nvd@nist.gov": "NVD",
    "cve@mitre.org": "MITRE",
    "github advisory database": "GitHub",
    "psirt@us.ibm.com": "IBM",
}


def assessor(row: list) -> str:
    """Who scored it, from row[4].

    row[5] is the assessment type, Primary or Secondary, and labelling with it
    left 129 pages showing two rows both marked "Secondary", the repetition
    the label was added to explain. row[4] names the party, which is the thing
    that actually differs. Scoring CNAs identify themselves by contact address
    or by UUID, so an address becomes its domain and a UUID stays generic.
    """
    raw = str(row[4]).strip() if len(row) > 4 and row[4] else ""
    if not raw:
        return str(row[5]) if len(row) > 5 and row[5] else ""
    known = ASSESSORS.get(raw.lower())
    if known:
        return known
    if "@" in raw:
        domain = raw.rsplit("@", 1)[1].lower()
        parts = [p for p in domain.split(".") if p not in ("com", "org", "net", "gov", "io")]
        return parts[0].upper() if parts else domain
    if re.fullmatch(r"[0-9a-f-]{32,36}", raw.lower()):
        return "CNA"
    return raw


def ordinal(value: int) -> str:
    """1st, 2nd, 3rd, 4th. A hard-coded "th" printed 51th on 21,100 pages."""
    if 11 <= value % 100 <= 13:
        return f"{value}th"
    return f"{value}{ {1: 'st', 2: 'nd', 3: 'rd'}.get(value % 10, 'th') }"


def owner_of(url: str) -> str | None:
    repo = repo_of(url)
    return repo.split("/")[0] if repo else None


def repo_of(url: str) -> str | None:
    """owner/repo, the key repo_meta is stored under."""
    from build_site import repo_from_url
    return repo_from_url(url) or None


def artifact_label(url: str) -> str:
    """A curated link's path inside its repository, as logic.js labels it.
    Empty for a repository root or a link that is not into a repository."""
    repo = repo_of(url)
    if not repo:
        return ""
    parts = [part for part in urlsplit(url).path.split("/") if part][2:]
    if parts[:1] in (["tree"], ["blob"]):
        parts = parts[2:]
    if repo in NAMED_BY_LEAF:
        parts = parts[-1:]
    path = unquote("/".join(parts))
    root = COLLECTION_ROOTS.get(repo, "")
    return path[len(root):] if root and path.startswith(root) and len(path) > len(root) else path


def wayback_capture(url: object) -> dict | None:
    """The capture a snapshot URL names, as waybackCapture in logic.js reads it.
    Its time has to be a real one from 1996 on, when the Wayback Machine began."""
    match = CAPTURE.fullmatch(url) if isinstance(url, str) else None
    if not match:
        return None
    stamp, original = match.groups()
    try:
        moment = datetime(int(stamp[:4]), int(stamp[4:6]), int(stamp[6:8]),
                          int(stamp[8:10]), int(stamp[10:12]), int(stamp[12:]))
    except ValueError:
        return None
    return {"url": url, "stamp": stamp, "original": original} if moment.year >= 1996 else None


def link_host(url: str) -> str:
    """Lower-cased host of an http(s) link, without www. or a port. Empty for
    anything else, a link carrying credentials included."""
    match = AUTHORITY.match(url)
    return re.sub(r"^www\.", "", re.sub(r":[0-9]*\Z", "", match[1].lower())) if match else ""


def confirmed_snapshot(url: str, archives: dict) -> dict | None:
    """The capture archives.json confirms for this exact link: a valid snapshot,
    stamped as recorded, of a page on the link's own host."""
    record = archives.get(url)
    capture = wayback_capture(record.get("url")) if isinstance(record, dict) else None
    if not capture or capture["stamp"] != record.get("timestamp"):
        return None
    host = link_host(url)
    return capture if host and link_host(capture["original"]) == host else None


def capture_date(stamp: str) -> str:
    return f"{stamp[:4]}-{stamp[4:6]}-{stamp[6:8]} {stamp[8:10]}:{stamp[10:12]} UTC"


def archived_name(label: str, capture: dict | None) -> str:
    """The accessible name of a link that opens a snapshot in place of its original."""
    if not capture:
        return ""
    name = f"{label}, archived page snapshot captured {capture_date(capture['stamp'])}"
    return f' aria-label="{esc(name)}"'


def archive_link(url: str, label: str, archives: dict) -> str:
    """The Wayback Machine beside a PoC link, drawn as archiveLink in logic.js
    draws it: the confirmed snapshot, or a lookup that claims nothing. A link
    that is itself a snapshot is stamped, and any other archive link gets nothing."""
    capture = wayback_capture(url)
    if capture:
        return ('<span class="wayback is-archived" title="Wayback Machine page snapshot captured '
                f'{capture_date(capture["stamp"])}, linked in place of the original" aria-hidden="true">ARCHIVED</span>')
    host = link_host(url)
    if not host or re.search(r"(?:^|\.)archive\.org\Z", host):
        return ""
    snapshot = confirmed_snapshot(url, archives)
    if snapshot:
        date = capture_date(snapshot["stamp"])
        name = f"snapshot of {label} on the Wayback Machine, captured {date}"
        return (f'<a class="wayback is-snapshot" href="{esc(snapshot["url"])}" target="_blank" rel="nofollow noopener" '
                f'title="Wayback Machine page snapshot, captured {date}" aria-label="{esc(name)}">snapshot</a>')
    name = f"find archive of {label} on the Wayback Machine"
    return (f'<a class="wayback is-lookup" href="{esc(WAYBACK + "*/" + url)}" target="_blank" rel="nofollow noopener" '
            f'title="Search the Wayback Machine for captures; none confirmed" aria-label="{esc(name)}">find archive</a>')


def link_path(url: str) -> str:
    """What follows a link's host: its path, query and fragment."""
    return re.sub(r"\Ahttps?://[^/?#]*", "", url)


def link_target(url: str) -> str:
    """The page a link stands for. A snapshot published in place of a lost
    original stands for that original."""
    capture = wayback_capture(url)
    return capture["original"] if capture else url


def link_identity(url: str) -> str:
    """The page a link stands for, whatever scheme, www. or port it carries."""
    target = link_target(url)
    host = link_host(target)
    return host + link_path(target) if host else target


def decoded(path: str) -> str:
    """decodeURIComponent: a path with a malformed escape is shown as written."""
    if re.search(r"%(?![0-9A-Fa-f]{2})", path):
        return path
    try:
        return unquote(path, errors="strict")
    except UnicodeDecodeError:
        return path


def source_file(parent: str, original: str) -> dict | None:
    """The file a saved original is, when it belongs to the page at parent."""
    repo = repo_of(parent)
    raw = RAW_FILE.fullmatch(original) if repo else None
    if raw:
        owner, name, commit, path = raw.groups()
        # A dot segment would resolve into another repository's files.
        if (f"{owner}/{name}".lower() != repo
                or any(not part or DOT_SEGMENT.fullmatch(part) for part in path.split("/"))):
            return None
        return {"key": f"{commit}/{path}", "name": decoded(path), "commit": commit}
    report = REPORT_PAGE.match(parent) if link_host(parent) == "hackerone.com" else None
    saved = REPORT_JSON.fullmatch(original) if report else None
    return {"key": saved[1], "name": f"{saved[1]}.json", "commit": ""} if saved and saved[1] == report[1] else None


def saved_files(url: str, archives: dict) -> list[dict]:
    """The saved files archives.json confirms for this exact link, as savedFiles
    in logic.js reads them: valid captures, stamped as recorded, of files that
    belong to it. One capture per file, the latest, in a stable order."""
    record = archives.get(url)
    files = record.get("files") if isinstance(record, dict) else None
    found: dict = {}
    for file in files if isinstance(files, list) else ():
        capture = wayback_capture(file.get("url")) if isinstance(file, dict) else None
        original = file.get("original") if capture else None
        if (not isinstance(original, str) or not original or capture["stamp"] != file.get("timestamp")
                or link_host(original) != link_host(capture["original"])
                or link_path(original) != link_path(capture["original"])):
            continue
        source = source_file(url, original)
        kept = found.get(source["key"]) if source else None
        if source and (not kept or kept["capture"]["stamp"] < capture["stamp"]):
            found[source["key"]] = {**source, "original": original, "capture": capture}
    return sorted(found.values(), key=lambda saved: saved["original"])


def shown_files(url: str, archives: dict, listed: frozenset | set = frozenset()) -> list[dict]:
    """The saved files a link discloses. A snapshot in place of a lost original
    discloses that original's files; a file listed in a row of its own is not
    repeated."""
    return [saved for saved in saved_files(link_target(url), archives)
            if link_identity(saved["original"]) not in listed]


def source_files(url: str, label: str, archives: dict, listed: frozenset | set = frozenset()) -> str:
    """A link's saved files, disclosed beside its Wayback control as sourceFiles
    in logic.js discloses them. Each opens the capture of one file's bytes, so
    none stands for the whole source and none gets an archive control of its own."""
    files = shown_files(url, archives, listed)
    if not files:
        return ""
    count = f"{len(files)} file{'' if len(files) == 1 else 's'}"
    title = ("Wayback Machine captures of individual files at pinned commits, not a copy of the whole repository"
             if files[0]["commit"] else "Wayback Machine capture of the report JSON")
    links = []
    for saved in files:
        date = capture_date(saved["capture"]["stamp"])
        what = (f"{saved['name']} at commit {saved['commit'][:7]}" if saved["commit"]
                else f"{saved['name']}, the report JSON")
        links.append(f'<a href="{esc(saved["capture"]["url"])}" target="_blank" rel="nofollow noopener" '
                     f'title="{esc(f"Wayback Machine capture of {what}, {date}")}" '
                     f'aria-label="{esc(f"{what} of {label}, Wayback Machine capture {date}")}">{esc(saved["name"])}</a>')
    # The count sizes the room the open list takes, so nothing beside it moves.
    return (f'<details class="sources" style="--files:{len(files)}" data-sources="{esc(url)}">'
            f'<summary title="{title}" aria-label="{esc(f"{count} saved from {label}")}">{count}</summary>'
            f'<div class="sources-list">{"".join(links)}</div></details>')


def page_lastmod(entry: dict, data: dict) -> str:
    """Bootstrap date before a page has a published content fingerprint: the record's own."""
    stamps = (entry.get("modified") or "", entry.get("published") or "")
    return max((s for s in stamps if len(s) == 10), default=data["today"])


def previous_page_state() -> dict:
    """Use the last successful deployment, including across fresh CI checkouts.

    A missing manifest bootstraps an existing or new site. Other failures stop
    the build rather than silently discarding the dates we already published.
    """
    stamp = int(datetime.now(timezone.utc).timestamp())
    url = f"{SITE}/{PAGE_STATE}?build={stamp}"
    try:
        with request.urlopen(url, timeout=30) as response:
            payload = json.load(response)
    except error.HTTPError as problem:
        if problem.code == 404:
            return {}
        raise
    if payload.get("version") != 1 or not isinstance(payload.get("pages"), dict):
        raise ValueError("Invalid published page-state manifest")
    return payload["pages"]


def digest(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def tracked_state(key: str, payload: object, today: str, fallback: str, previous: dict,
                  legacy=None) -> list[str]:
    fingerprint = digest(payload)
    old = previous.get(key)
    if old is not None:
        if not isinstance(old, list) or len(old) != 2:
            raise ValueError(f"Invalid published content date for {key}")
        date.fromisoformat(old[1])
        unchanged = old[0] == fingerprint or (legacy is not None and old[0] == digest(legacy()))
        lastmod = old[1] if unchanged else today
    else:
        lastmod = today if previous else fallback
    return [fingerprint, lastmod]


def content_state(entry: dict, data: dict, previous: dict) -> list[str]:
    """Track significant content: the record, every link, CVSS, advisories,
    Nuclei, KEV and the Wayback snapshots and saved files the page links.

    Daily EPSS fluctuations, star counts, repository pushes and site-wide totals
    are deliberately excluded; they are not a new exploit, assessment, or
    vulnerability record.
    """
    cid = entry["cve"]
    meta = data["meta"].get(cid) or {}
    payload = {"entry": entry, "cvss": meta.get("cvss"), "advisories": meta.get("advisories"),
               "nuclei": data["nuclei"].get(cid), "kev": data["kev"].get(cid)}
    # Only what the page renders, and only on pages that link a snapshot or a
    # saved file, so every other page keeps the fingerprint and date it was
    # published with.
    archives = data.get("archives") or {}
    links = [url for field in ("poc", *(key for key, _, _ in SOURCES)) for url in entry.get(field) or []]
    snapshots = {url: [capture["url"], capture["stamp"]] for url in links
                 if (capture := confirmed_snapshot(url, archives))}
    if snapshots:
        payload["archives"] = snapshots
    listed = frozenset(map(link_identity, links))
    files = {url: [[saved["original"], saved["capture"]["url"], saved["capture"]["stamp"]] for saved in shown]
             for url in links if (shown := shown_files(url, archives, listed))}
    if files:
        payload["files"] = files

    def legacy() -> dict:
        # Manifests published while pushes were fingerprinted still match, so they keep their dates.
        repos = data.get("repo_meta") or {}
        pushed = {repo: stored[1] for url in entry.get("poc") or []
                  if (repo := repo_of(url)) and (stored := repos.get(repo)) and len(stored) > 1}
        return {**payload, "pushed": pushed}

    return tracked_state(cid, payload, data["today"], page_lastmod(entry, data), previous, legacy)


def build_related(cves: list) -> dict:
    """CVEs that share a proof-of-concept author.

    A sitemap gets pages discovered; links get them crawled sooner and pass
    context. That only holds when the link means something. The year-adjacent
    fallback that used to fill this section had no relation behind it at all:
    CVE-2024-1235 is not related to CVE-2024-1234, it was merely numbered next,
    and 61,936 pages carried six such links apiece. A shared author is a real
    relation, so it is the only one kept; pages without one show no section.
    """
    by_owner = defaultdict(list)
    for entry in cves:
        for url in entry.get("poc") or []:
            owner = owner_of(url)
            if owner:
                by_owner[owner].append(entry["cve"])
    # An author with hundreds of PoCs relates nothing in particular.
    by_owner = {o: v for o, v in by_owner.items() if 1 < len(v) <= 40}

    related = {}
    for entry in cves:
        cid = entry["cve"]
        seen = {cid}
        picks = []
        for url in entry.get("poc") or []:
            owner = owner_of(url)
            for other in by_owner.get(owner, ()):
                if other not in seen:
                    seen.add(other)
                    picks.append(other)
                if len(picks) >= RELATED:
                    break
            if len(picks) >= RELATED:
                break
        if picks:
            related[cid] = picks[:RELATED]
    return related


def link_rows(urls: list, repo_meta: dict, *, trusted: bool = False, collection: bool = False,
              archives: dict | None = None, listed: frozenset = frozenset()) -> str:
    """One row per source link.

    The repository list is crowd-sourced: anyone can publish a repository named
    after a CVE and land in it, so those stay nofollow. Nuclei, ExploitDB,
    Metasploit, Vulhub and the CVE and NVD records are curated destinations the
    index deliberately vouches for, and Google's guidance is to leave a link
    unqualified when the association is intended.

    Stars and push dates describe the repository, including for file links.
    Artifact release and update dates are kept separate on the homepage.

    Given an archive index, each PoC row also offers the Wayback Machine, and
    discloses its saved files other than those in listed, which have rows of
    their own. A snapshot published in place of a lost original is named,
    ranked and measured as that original, and its link opens the snapshot.
    """
    rel = "noopener" if trusted else "nofollow noopener"
    rows = []

    def target(url: str) -> tuple[str, dict | None]:
        capture = wayback_capture(url) if archives is not None else None
        return (capture["original"] if capture else url), capture

    def rank(url: str) -> tuple:
        source = target(url)[0]
        meta = repo_meta.get(repo_of(source) or "")
        return -(meta[0] if meta else -1), source.lower()

    for url in sorted(urls, key=rank):
        source, capture = target(url)
        label = source[len(GITHUB):] if source.startswith(GITHUB) else source
        path = artifact_label(source) if trusted else ""
        repository = repo_of(source)
        meta = repo_meta.get(repository or "")
        detail = (f"Repo stars {meta[0]}★ · pushed {esc(meta[1]) or 'N/A'}" if meta
                  else "Repo metadata unavailable" if repository else "")
        if path and collection:
            repository = "/".join(urlsplit(source).path.strip("/").split("/")[:2])
            label, detail = path, f"{esc(repository)} · {detail}"
        label = short(label, 90)
        archive = archive_link(url, label, archives) if archives is not None else ""
        note = " · ".join(part for part in (detail, archive) if part)
        note = f"<span>{note}</span>" if note else ""
        files = source_files(url, label, archives, listed) if archives is not None else ""
        rows.append(
            f'<li><a href="{esc(url)}" rel="{rel}" target="_blank"{archived_name(label, capture)}>'
            f"{esc(label)}</a>{note}{files}</li>"
        )
    return "".join(rows)


def advisory_rows(advisories: dict) -> str:
    """Render CVE references with their source tags."""
    rows = []
    for url in sorted(advisories, key=str.lower):
        tags = list(dict.fromkeys(map(str, advisories[url])))
        reference = bool(tags) and all(tag == "Exploit" for tag in tags)
        tag = ("VENDOR" if "Vendor Advisory" in tags else "PATCH" if "Patch" in tags
               else "REFERENCE" if reference else "ADVISORY")
        rel = "nofollow noopener" if reference else "noopener"
        label = short(url[len(GITHUB):] if url.startswith(GITHUB) else url, 90)
        rows.append(f'<li><a href="{esc(url)}" rel="{rel}" target="_blank">{esc(label)}</a>'
                    f'<span title="{esc(", ".join(tags) or "Advisory")}">{tag}</span></li>')
    return "".join(rows)


def header(count: int | None = None) -> str:
    """The bar every generated page opens with, so none of them can drift.

    It is the homepage's own search bar, same height, type and placeholder,
    under the wordmark. The pages are static, so enter submits to /?q= and the
    homepage picks the query up from the URL.
    """
    tally = f'<a class="cve-count" href="/">{count:,} CVEs with PoCs</a>' if count else ""
    return f"""<header class="container cve-top"><a class="cve-home" href="/">{BRAND}</a>{tally}</header>
<div class="container search-bar"><form class="search" role="search" action="/" method="get" autocomplete="off">
<svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden="true">
<circle cx="7.6" cy="7.6" r="5.1" stroke="#8b949e" stroke-width="1.7"/>
<path d="M11.5 11.5 L15.6 15.6" stroke="#8b949e" stroke-width="1.7" stroke-linecap="round"/>
</svg>
<input type="text" name="q" spellcheck="false" placeholder="Search CVE, vendor, product or keyword &middot; exclude with -windows" aria-label="Search CVE, vendor, product or keyword"/>
<span class="search-status">enter searches the index</span>
<button type="submit" class="sr-only">Search</button>
</form></div>"""


def project_links() -> str:
    """Show the sponsor link only when the workflow confirms a public profile."""
    if os.environ.get("POCINDEX_SPONSORS_ENABLED") != "true":
        return REPO_LINK
    return f"<span>{REPO_LINK}&nbsp;&middot; {SPONSOR_LINK}</span>"


def footer(tail: str = '<a href="/">Back to the index</a>') -> str:
    return (f'<footer class="site-footer"><div class="container">'
            f"<span>{SOURCES_LINE}</span><span>{tail}</span>{project_links()}</div></footer>")


def page(entry: dict, data: dict) -> str:
    cid = entry["cve"]
    desc = " ".join((entry.get("desc") or "").split())
    pocs = entry.get("poc") or []
    rows = (data["meta"].get(cid) or {}).get("cvss") or []
    cvss = canonical_cvss(rows)
    ep = data["epss"].get(cid)
    flagged = data["kev"].get(cid)
    tpl = data["nuclei"].get(cid)

    # Every source the page goes on to list. Counting the repository column
    # alone told 19,940 pages they held "0 public PoC exploits" directly above
    # the ExploitDB or Metasploit entries they were listing, and put that same
    # figure in the title and the meta description.
    total = len(pocs) + sum(len(entry.get(key) or []) for key, _, _ in SOURCES)
    count = f"{total:,} public PoC exploit" + ("" if total == 1 else "s")
    # The record's own title names the product and the flaw, which is what a
    # query says and what the description often leaves for the second line.
    headline = " ".join((entry.get("title") or "").split())
    title = f"{cid}: {count}. {short(headline, 70)} | {BRAND}" if headline else f"{cid}: {count} | {BRAND}"
    meta_desc = short(f"{cid}. {headline + '. ' if headline else ''}{count}. {desc}", 155)
    url = f"{SITE}/{cid}"
    affected = list(dict.fromkeys([*(entry.get("vendor") or [])[:3], *(entry.get("product") or [])[:6]]))

    chips = []
    if entry.get("metadata_pending"):
        chips.append('<span class="chip">CVE metadata pending</span>')
    if flagged:
        ransom = " RANSOMWARE" if flagged[1] else ""
        chips.append(f'<span class="chip chip-kev">KEV{ransom}</span>')
    if cvss:
        chips.append(
            f'<span class="chip chip-sev is-{esc(str(cvss[2]).lower())}">'
            f"{esc(cvss[2])} {esc(cvss[1])}</span>"
        )
    elif tpl and str(tpl.get("severity") or "").upper() in SEVERITIES:
        # The same fallback entrySeverity applies in the browser. Without it a
        # CVE rated only by a Nuclei template carried a severity chip in the
        # search results and none at all on its own page.
        score = tpl.get("cvss")
        rating = f" {esc(score)}" if isinstance(score, (int, float)) else ""
        chips.append(
            f'<span class="chip chip-sev is-{esc(str(tpl["severity"]).lower())}">'
            f'{esc(str(tpl["severity"]).upper())}{rating}</span>'
        )
    if ep:
        hot = " is-hot" if ep[0] >= 0.1 else ""
        chips.append(f'<span class="chip chip-epss{hot}">EPSS {ep[0] * 100:.1f}%</span>')

    facts = []
    if affected:
        facts.append(f"<dt>Affected</dt><dd>{esc(' · '.join(affected))}</dd>")
    for row in unique_cvss(rows):
        # Who scored it, so two surviving rows read as two opinions rather than
        # as the page repeating itself.
        who = esc(assessor(row))
        label = f"CVSS v{esc(row[0])}" + (f" <span>{who}</span>" if who else "")
        facts.append(
            f"<dt>{label}</dt><dd>{esc(row[1])} {esc(row[2])}"
            f'<code>{esc(row[3])}</code></dd>'
        )
    if ep:
        facts.append(
            f"<dt>EPSS</dt><dd>{ep[0] * 100:.2f}% chance of exploitation in the next "
            f"30 days, {ordinal(round(ep[1] * 100))} percentile</dd>"
        )
    if flagged:
        used = ", used in ransomware campaigns" if flagged[1] else ""
        facts.append(f"<dt>CISA KEV</dt><dd>added {esc(flagged[0])}{used}</dd>")
    if tpl:
        cwe = f" · {esc(tpl.get('cwe'))}" if tpl.get("cwe") else ""
        facts.append(f"<dt>Nuclei</dt><dd>{esc(tpl.get('severity'))}{cwe}</dd>")
    if entry.get("published"):
        facts.append(f"<dt>Published</dt><dd>{esc(entry['published'])}</dd>")
    elif entry.get("poc_observed"):
        facts.append(f"<dt>PoC observed</dt><dd>{esc(entry['poc_observed'])}</dd>")
    if entry.get("modified"):
        facts.append(f"<dt>Updated</dt><dd>{esc(entry['modified'])}</dd>")

    # Without an archive index every PoC still offers a Wayback lookup.
    archives = data.get("archives") or {}
    # Links with a row of their own here; no row's saved files repeat them.
    rowed =frozenset(link_identity(link) for link in
                      [*pocs, *(link for key, _, _ in SOURCES for link in entry.get(key) or [])])
    blocks = []
    if pocs:
        blocks.append(
            f"<h2>Proof-of-concept exploits ({len(pocs):,})</h2>"
            f'<ul class="cve-links">{link_rows(pocs, data["repo_meta"], archives=archives, listed=rowed)}</ul>'
        )
    for key, heading, _ in SOURCES:
        urls = entry.get(key) or []
        if urls:
            listed_rows = link_rows(urls, data["repo_meta"], trusted=True, collection=key == "collections",
                                    archives=archives, listed=rowed)
            blocks.append(f'<h2>{heading} ({len(urls)})</h2><ul class="cve-links">{listed_rows}</ul>')

    siblings = "".join(
        f'<li><a href="/{other}">{other}</a></li>' for other in data["related"].get(cid, ())
    )
    listed = set(pocs)
    for key, _, _ in SOURCES:
        listed.update(entry.get(key) or [])
    advisories: dict[str, list] = {}
    for row in (data["meta"].get(cid) or {}).get("advisories") or []:
        if row and row[0] not in listed:
            advisories.setdefault(row[0], []).extend(row[1] if len(row) > 1 and isinstance(row[1], list) else [])
    advisory_block = (f'<h2>CVE references</h2><ul class="cve-links">{advisory_rows(advisories)}</ul>'
                      if advisories else "")

    # WebPage, not TechArticle. TechArticle is valid schema.org but is not one
    # of the types Google draws an Article rich result from, and claiming it
    # bought nothing. The dates were the real problem: datePublished carried the
    # date the CVE record was published, which is not when this page was written
    # or last changed. The page is a listing about a vulnerability, so it says
    # that, and dateModified is the page's own lastmod.
    ld = json_ld(
        {
            "@context": "https://schema.org",
            "@type": "WebPage",
            "name": f"{cid} proof-of-concept exploits",
            "url": url,
            "description": meta_desc,
            "dateModified": data["lastmod"][cid],
            "isPartOf": {"@type": "WebSite", "name": BRAND, "url": f"{SITE}/"},
            "mainEntity": {
                "@type": "Thing",
                "name": cid,
                **({"alternateName": headline} if headline else {}),
                "identifier": cid,
                "description": short(desc, 600) or cid,
                "sameAs": [
                    f"https://www.cve.org/CVERecord?id={cid}",
                    f"https://nvd.nist.gov/vuln/detail/{cid}",
                ],
            },
        }
    )

    year, block = block_of(cid)
    trail = json_ld(
        {
            "@context": "https://schema.org",
            "@type": "BreadcrumbList",
            "itemListElement": [
                {"@type": "ListItem", "position": 1, "name": BRAND, "item": f"{SITE}/"},
                {"@type": "ListItem", "position": 2, "name": f"CVE-{year}", "item": f"{SITE}/{year}"},
                {"@type": "ListItem", "position": 3, "name": f"CVE-{year}-{block}", "item": f"{SITE}/CVE-{year}-{block}"},
                {"@type": "ListItem", "position": 4, "name": cid, "item": url},
            ],
        }
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>{esc(title)}</title>
<meta name="description" content="{esc(meta_desc)}"/>
<meta name="robots" content="index, follow, max-image-preview:large"/>
<link rel="canonical" href="{url}"/>
<meta property="og:type" content="article"/>
<meta property="og:site_name" content="{BRAND}"/>
<meta property="og:title" content="{esc(title)}"/>
<meta property="og:description" content="{esc(meta_desc)}"/>
<meta property="og:url" content="{url}"/>
<meta property="og:image" content="{SITE}/social-card.png"/>
<meta property="og:image:width" content="1280"/>
<meta property="og:image:height" content="640"/>
<meta name="twitter:card" content="summary_large_image"/>
<meta name="twitter:title" content="{esc(title)}"/>
<meta name="twitter:description" content="{esc(meta_desc)}"/>
<meta name="twitter:image" content="{SITE}/social-card.png"/>
<link rel="icon" href="/favicon.ico"/>
{FONTS}
<link rel="stylesheet" href="{asset_url('style.css')}"/>
<script type="application/ld+json">{ld}</script>
<script type="application/ld+json">{trail}</script>
</head>
<body>
{header(len(data["cves"]))}
<main class="container cve-page">
{crumbs(cid)}
<h1>{cid}</h1>
{f'<p class="cve-title">{esc(headline)}</p>' if headline else ''}
<div class="chips">{''.join(chips)}</div>
<p class="cve-desc">{esc(desc)}</p>
<dl class="cve-facts">{''.join(facts)}</dl>
{''.join(blocks)}
{advisory_block}
<h2>References</h2>
<ul class="cve-links">
<li><a href="https://www.cve.org/CVERecord?id={cid}" rel="noopener" target="_blank">CVE Record</a></li>
<li><a href="https://nvd.nist.gov/vuln/detail/{cid}" rel="noopener" target="_blank">NVD entry</a></li>
</ul>
{f'<h2>Related</h2><ul class="cve-related">{siblings}</ul>' if siblings else ''}
</main>
{footer(f'<a href="/">{len(data["cves"]):,} CVEs with PoCs</a>')}
</body>
</html>
"""


def block_of(cid: str) -> tuple[str, str]:
    """The year and the thousand-block a CVE id falls in: CVE-2024-3400 is 2024, 3xxx."""
    _, year, number = cid.split("-", 2)
    return year, f"{int(number) // 1000}xxx"


def crumbs(cid: str) -> str:
    year, block = block_of(cid)
    return (f'<nav class="crumbs" aria-label="Browse"><a href="/{year}">{year}</a>'
            f'<span>/</span><a href="/CVE-{year}-{block}">CVE-{year}-{block}</a></nav>')


def hub_shell(title: str, description: str, path: str, body: str, count: int) -> str:
    url = f"{SITE}/{path}"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>{esc(title)} | {BRAND}</title>
<meta name="description" content="{esc(description)}"/>
<meta name="robots" content="index, follow"/>
<link rel="canonical" href="{url}"/>
<meta property="og:type" content="website"/>
<meta property="og:site_name" content="{BRAND}"/>
<meta property="og:title" content="{esc(title)}"/>
<meta property="og:description" content="{esc(description)}"/>
<meta property="og:url" content="{url}"/>
<meta property="og:image" content="{SITE}/social-card.png"/>
<meta name="twitter:card" content="summary_large_image"/>
<link rel="icon" href="/favicon.ico"/>
{FONTS}
<link rel="stylesheet" href="{asset_url('style.css')}"/>
</head>
<body>
{header(count)}
<main class="container cve-page hub">
{body}
</main>
{footer(f'<a href="/">{count:,} CVEs with PoCs</a>')}
</body>
</html>
"""


def hub_pages(cves: list, data: dict) -> dict:
    """One page per year and one per thousand-block of ids, linking every CVE page.

    A sitemap gets a page discovered; a link from a page already indexed gets
    it crawled and ranked. 62,000 of the CVE pages had no internal link at all,
    only a sitemap entry, so the tree is now home, year, block, CVE, with at
    most a thousand links on any one page.
    """
    blocks: dict = defaultdict(list)
    for entry in cves:
        blocks[block_of(entry["cve"])].append(entry)
    years: dict = defaultdict(list)
    for (year, block), entries in blocks.items():
        years[year].append((block, entries))
    total = len(cves)
    pages = {}
    lastmod = {}
    states = {}
    previous = data.get("previous", {})

    for (year, block), entries in blocks.items():
        entries.sort(key=lambda e: int(e["cve"].split("-")[2]))
        low = int(block[:-3]) * 1000
        name = f"CVE-{year}-{block}"
        rows = []
        for entry in entries:
            cid = entry["cve"]
            links = len(entry.get("poc") or []) + sum(len(entry.get(k) or []) for k, _, _ in SOURCES)
            flagged = '<span class="hub-kev">KEV</span>' if data["kev"].get(cid) else ""
            rows.append(
                f'<li><a href="/{cid}">{cid}</a><span class="hub-count">{links:,} PoC{"" if links == 1 else "s"}</span>'
                f'<span class="hub-desc">{flagged}{esc(short(entry.get("title") or entry.get("desc") or "", 140))}</span></li>'
            )
        title = f"CVE-{year}-{low:04d} to CVE-{year}-{low + 999:04d}: {len(entries):,} CVEs with public PoC exploits"
        description = (f"{len(entries):,} CVEs from CVE-{year}-{low:04d} to CVE-{year}-{low + 999:04d} "
                       "with public proof-of-concept exploits, with PoC counts and known-exploited status.")
        body = (f'<nav class="crumbs" aria-label="Browse"><a href="/{year}">{year}</a><span>/</span>{name}</nav>'
                f"<h1>CVE-{year}-{low:04d} to CVE-{year}-{low + 999:04d}</h1>"
                f'<p class="cve-desc">{len(entries):,} CVEs with public proof-of-concept exploits.</p>'
                f'<ul class="hub-list">{"".join(rows)}</ul>')
        pages[f"{name}.html"] = hub_shell(title, description, name, body, total)
        fallback = max(data["lastmod"].get(e["cve"], "") for e in entries) or data["today"]
        states[name] = tracked_state(name, [title, description, body], data["today"], fallback, previous)
        lastmod[name] = states[name][1]

    ordered = sorted(years)
    for year in ordered:
        year_blocks = sorted(years[year], key=lambda item: int(item[0][:-3]))
        count = sum(len(entries) for _, entries in year_blocks)
        rows = "".join(
            f'<li><a href="/CVE-{year}-{block}">CVE-{year}-{int(block[:-3]) * 1000:04d} to {int(block[:-3]) * 1000 + 999:04d}</a>'
            f'<span class="hub-count">{len(entries):,} CVEs</span></li>'
            for block, entries in year_blocks
        )
        at = ordered.index(year)
        neighbours = []
        if at > 0:
            neighbours.append(f'<a href="/{ordered[at - 1]}">{ordered[at - 1]}</a>')
        if at + 1 < len(ordered):
            neighbours.append(f'<a href="/{ordered[at + 1]}">{ordered[at + 1]}</a>')
        title = f"CVE-{year}: {count:,} CVEs with public PoC exploits"
        description = (f"Every {year} CVE with a public proof-of-concept exploit, {count:,} in all, "
                       "grouped by id with PoC counts and known-exploited status.")
        body = (f'<nav class="crumbs" aria-label="Browse"><a href="/">all years</a><span>/</span>{year}</nav>'
                f"<h1>CVE-{year}</h1>"
                f'<p class="cve-desc">{count:,} CVEs with public proof-of-concept exploits, in {len(year_blocks)} blocks of a thousand ids.</p>'
                f'<ul class="hub-list hub-blocks">{rows}</ul>'
                + (f'<p class="hub-neighbours">{" · ".join(neighbours)}</p>' if neighbours else ""))
        pages[f"{year}.html"] = hub_shell(title, description, year, body, total)
        fallback = max(lastmod[f"CVE-{year}-{block}"] for block, _ in year_blocks)
        states[year] = tracked_state(year, [title, description, body], data["today"], fallback, previous)
        lastmod[year] = states[year][1]

    return {"pages": pages, "lastmod": lastmod, "states": states}


def utc_day(value: object) -> str:
    """UTC date of an ISO date or timestamp, read as logic.js reads it: a time
    without a zone is UTC. Empty when there is no readable date."""
    if not isinstance(value, str) or not re.match(r"\d{4}-\d{2}-\d{2}", value):
        return ""
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return ""
    return (moment.astimezone(timezone.utc) if moment.tzinfo else moment).date().isoformat()


def star_label(stars: int) -> str:
    """formatStars in logic.js. toFixed rounds the exact binary value half up,
    so 1,250 stars is 1.3k there where Python's format would print 1.2k."""
    if stars < 1000:
        return str(stars)
    return f"{Decimal(stars / 1000).quantize(Decimal('0.1'), ROUND_HALF_UP)}k"


def trend_age(value: object, now: datetime) -> str:
    """Relative age and exact UTC tooltip, matching logic.js's trendAge."""
    if not utc_day(value):
        return '<span class="trend-age">N/A</span>'
    moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    moment = moment.replace(tzinfo=timezone.utc) if moment.tzinfo is None else moment.astimezone(timezone.utc)
    day_only = len(value) == 10
    seconds = max(0, (now - moment).total_seconds())
    label = ""
    if day_only:
        count, unit = max(0, (now.astimezone(timezone.utc).date() - moment.date()).days), "day"
        if not count:
            label = "today"
    elif seconds < 60:
        label = "just now"
    elif seconds < 3600:
        count, unit = int(seconds // 60), "minute"
    elif seconds < 86400:
        count, unit = int(seconds // 3600), "hour"
    else:
        count, unit = int(seconds // 86400), "day"
    if not label:
        label = f"{count:,} {unit}{'' if count == 1 else 's'} ago"
    iso = value if day_only else moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    title = f"{value} UTC (time unavailable)" if day_only else iso.replace("T", " ").replace("Z", " UTC")
    return f'<time class="trend-age" datetime="{iso}" title="{title}">{label}</time>'


def trend_rows(items: object, landed: bool, now: datetime | None = None, archives: dict | None = None) -> str:
    """A front-page list as logic.js renders it, in feed order. Just landed is
    dated by first release, Trending by latest artifact commit. Each row offers
    its Wayback snapshot or a lookup, and its saved files."""
    now = now or datetime.now(timezone.utc)
    archives = archives or {}
    shown = (items if isinstance(items, list) else [])[:TREND_ROWS]
    listed = frozenset(link_identity(str(item.get("url") or "")) for item in shown)
    rows = []
    for item in shown:
        url = str(item.get("url") or "")
        repository = repo_of(url)
        stars = item.get("stars") if repository else None
        star_cell = "N/A" if stars is None else f'{star_label(stars)} <span class="star">★</span>'
        star_title = f"Repository stars: {repository}" if repository else "No GitHub repository"
        if repository and stars is None:
            star_title += " (unavailable)"
        popular = " is-popular" if stars is not None and stars >= 500 else ""
        # Off GitHub the last path segment is a bare id, so it keeps its host.
        source = str(item.get("source") or "").removeprefix("www.")
        name = (f"{source}/{item.get('name') or ''}" if item.get("artifact") and source and source != "github.com"
                else item.get("name"))
        flagged = '<span class="trend-kev" title="CISA known exploited">KEV</span>' if item.get("kev") else ""
        detail = (f'<a class="trend-detail" href="{esc(item["page"])}">{esc(item.get("cve"))} details</a>'
                  if item.get("page") else "")
        label = str(name or url)
        rows.append(
            f'<div class="trend-row"><span class="trend-stars{popular}" title="{esc(star_title)}">{star_cell}</span>'
            f'{trend_age(item.get("released" if landed else "pushed"), now)}'
            f'<div class="trend-name-cell">{flagged}<a class="trend-name" href="{esc(item.get("url"))}" '
            f'target="_blank" rel="nofollow noopener"{archived_name(label, wayback_capture(url))}>{esc(name)}</a>'
            f'<div class="trend-sub">{detail}{archive_link(url, label, archives)}'
            f'{source_files(url, label, archives, listed)}</div></div>'
            f'<span class="trend-desc">{esc(item.get("desc") or "Description unavailable")}</span></div>'
        )
    return "".join(rows) or '<div class="empty">No recent PoCs.</div>'


def homepage(cves: list, kev: dict, trending: dict, now: datetime | None = None,
             archives: dict | None = None) -> str:
    """Publish the same content before JavaScript or a crawler render runs."""
    indexed = {entry["cve"] for entry in cves}
    if trending["with_pocs"] != len(indexed) or trending["total_cves"] < len(indexed):
        raise ValueError("Homepage counts disagree with the searchable corpus")
    generated = datetime.fromisoformat(trending["generated"].replace("Z", "+00:00"))

    website = {
        "@context": "https://schema.org",
        "@type": "WebSite",
        "@id": f"{SITE}/#website",
        "name": BRAND,
        "alternateName": ["pocindex", host()],
        "url": f"{SITE}/",
        "description": DESCRIPTION,
        "sameAs": f"https://github.com/{SLUG}",
    }
    years = sorted({cid.split("-")[1] for cid in indexed}, reverse=True)
    with open(os.path.join(ROOT, "templates", "index.html"), encoding="utf-8") as handle:
        template = Template(handle.read())
    return template.substitute(
        brand=esc(BRAND), title=esc(TITLE), subtitle=esc(SUBTITLE),
        description=esc(DESCRIPTION), site=esc(SITE), fonts=FONTS,
        stylesheet_url=asset_url("style.css"), script_url=asset_url("logic.js"),
        sources_line=SOURCES_LINE, project_links=project_links(), website_schema=json_ld(website),
        total_cves=f"{trending['total_cves']:,}", with_pocs=f"{len(indexed):,}", kev=f"{len(kev):,}",
        landed_rows=trend_rows(trending.get("landed"), True, now, archives),
        generated=esc(generated.strftime("%Y-%m-%d %H:%M UTC")),
        year_links=" ".join(f'<a href="/{esc(year)}">{esc(year)}</a>' for year in years),
    )


def not_found() -> str:
    """The 404, rendered from the same constants as every other page.

    It used to be hand-written, and drifted: it referenced four CSS classes that
    no longer existed, so it rendered unstyled, and it carried a meta refresh
    that threw a reader out of a search two seconds after they arrived.
    """
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Page not found | {BRAND}</title>
<meta name="robots" content="noindex, follow"/>
<link rel="icon" href="/favicon.ico"/>
{FONTS}
<link rel="stylesheet" href="{asset_url('style.css')}"/>
</head>
<body>
{header()}
<main class="container cve-page">
<h1>404</h1>
<p class="cve-desc">No page at this address. If you were after a CVE, search for it above, or
<a href="/">browse the whole index</a>.</p>
</main>
{footer()}
</body>
</html>
"""


def main() -> int:
    asset_url.cache_clear()
    cves = load("CVE_list.json")
    data = {
        "cves": cves,
        "meta": load("cve_metadata.json"),
        "epss": load("epss.json"),
        "kev": load("kev.json"),
        "nuclei": load("nuclei.json"),
        "repo_meta": load("repo_meta.json"),
        "archives": load_optional("archives.json"),
        "today": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
    }
    data["related"] = build_related(cves)
    previous = previous_page_state()
    data["previous"] = previous
    states = {entry["cve"]: content_state(entry, data, previous) for entry in cves}
    lastmod = {cid: state[1] for cid, state in states.items()}
    data["lastmod"] = lastmod

    written = 0
    for entry in cves:
        cid = entry["cve"]
        with open(os.path.join(DOCS, f"{cid}.html"), "w", encoding="utf-8") as handle:
            handle.write(page(entry, data))
        written += 1

    hubs = hub_pages(cves, data)
    for name, markup in hubs["pages"].items():
        with open(os.path.join(DOCS, name), "w", encoding="utf-8") as handle:
            handle.write(markup)
    lastmod.update(hubs["lastmod"])
    states.update(hubs["states"])

    # The sitemap has to quote the same date the page does, so it is computed
    # once here and handed to build_seo.py rather than derived twice. Hub pages
    # ride in the same file under their own names.
    with open(os.path.join(DOCS, LASTMOD), "w", encoding="utf-8") as handle:
        json.dump(lastmod, handle, separators=(",", ":"))
    with open(os.path.join(DOCS, PAGE_STATE), "w", encoding="utf-8") as handle:
        json.dump({"version": 1, "pages": states}, handle, separators=(",", ":"))

    with open(os.path.join(DOCS, "404.html"), "w", encoding="utf-8") as handle:
        handle.write(not_found())

    with open(os.path.join(DOCS, "index.html"), "w", encoding="utf-8") as handle:
        handle.write(homepage(cves, data["kev"], load("trending_poc.json"), archives=data["archives"]))

    related = sum(1 for cid in lastmod if data["related"].get(cid))
    print(f"Wrote {written:,} CVE pages and {len(hubs['pages']):,} hub pages into {DOCS} "
          f"({related:,} with a shared-author Related block)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
