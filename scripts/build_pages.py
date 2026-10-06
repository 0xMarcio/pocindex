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
import json
import re
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from brand import BRAND, FONTS, SITE, SOURCES_LINE

DOCS = os.path.join(ROOT, "docs")
RELATED = 6
GITHUB = "https://github.com/"
SEVERITIES = {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
LASTMOD = "page_lastmod.json"

SOURCES = (
    ("nuclei", "Nuclei templates", "projectdiscovery/nuclei-templates"),
    ("msf", "Metasploit modules", "rapid7/metasploit-framework"),
    ("edb", "ExploitDB entries", "exploit-db.com"),
    ("vulhub", "Vulhub environments", "vulhub/vulhub"),
    ("collections", "Exploit collections", ""),
)


def load(name: str) -> dict | list:
    with open(os.path.join(DOCS, name), encoding="utf-8") as handle:
        return json.load(handle)


def esc(value) -> str:
    return html.escape(str(value or ""), quote=True)


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
    return text[: limit - 1].rsplit(" ", 1)[0] + "…"


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
}


def assessor(row: list) -> str:
    """Who scored it, from row[4].

    row[5] is the assessment type, Primary or Secondary, and labelling with it
    left 129 pages showing two rows both marked "Secondary" — the repetition
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
    if not url.startswith(GITHUB):
        return None
    parts = url[len(GITHUB):].split("/")
    return parts[0].lower() if parts and parts[0] else None


def repo_of(url: str) -> str | None:
    """owner/repo, the key repo_meta is stored under."""
    if not url.startswith(GITHUB):
        return None
    parts = [p for p in url[len(GITHUB):].split("/") if p]
    if len(parts) < 2:
        return None
    return f"{parts[0].lower()}/{re.sub(r'[.]git$', '', parts[1], flags=re.I).lower()}"


def page_lastmod(entry: dict, data: dict) -> str:
    """When this page last changed, not when the CVE record did.

    A sitemap lastmod is meant to describe the page. Ours described the CVE
    record, so a CVE that gained forty new proof-of-concept repositories this
    week still advertised a lastmod from 2021 and crawlers had no reason to
    come back. The linked repositories carry their own last-push date in
    repo_meta, so the later of the two is what actually moved.
    """
    stamps = [entry.get("modified") or "", entry.get("published") or ""]
    for url in entry.get("poc") or []:
        meta = data["repo_meta"].get(repo_of(url) or "")
        if meta and len(meta) > 1 and isinstance(meta[1], str):
            stamps.append(meta[1][:10])
    return max((s for s in stamps if len(s) == 10), default=data["today"])


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


def link_rows(urls: list, repo_meta: dict, *, trusted: bool = False) -> str:
    """One row per source link.

    The repository list is crowd-sourced: anyone can publish a repository named
    after a CVE and land in it, so those stay nofollow. Nuclei, ExploitDB,
    Metasploit, Vulhub and the CVE and NVD records are curated destinations the
    index deliberately vouches for, and Google's guidance is to leave a link
    unqualified when the association is intended.
    """
    rel = "noopener" if trusted else "nofollow noopener"
    rows = []
    for url in urls:
        label = url[len(GITHUB):] if url.startswith(GITHUB) else url
        meta = repo_meta.get(repo_of(url) or "")
        note = f"<span>{meta[0]}★ · {esc(meta[1])}</span>" if meta else ""
        rows.append(
            f'<li><a href="{esc(url)}" rel="{rel}" target="_blank">'
            f"{esc(short(label, 90))}</a>{note}</li>"
        )
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


def footer(tail: str = '<a href="/">Back to the index</a>') -> str:
    return (f'<footer class="site-footer"><div class="container">'
            f"<span>{SOURCES_LINE}</span><span>{tail}</span></div></footer>")


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
    if entry.get("modified"):
        facts.append(f"<dt>Updated</dt><dd>{esc(entry['modified'])}</dd>")

    blocks = []
    if pocs:
        blocks.append(
            f"<h2>Proof-of-concept exploits ({len(pocs):,})</h2>"
            f'<ul class="cve-links">{link_rows(pocs, data["repo_meta"])}</ul>'
        )
    for key, heading, _ in SOURCES:
        urls = entry.get(key) or []
        if urls:
            blocks.append(
                f"<h2>{heading} ({len(urls)})</h2>"
                f'<ul class="cve-links">{link_rows(urls, data["repo_meta"], trusted=True)}</ul>'
            )

    siblings = "".join(
        f'<li><a href="/{other}">{other}</a></li>' for other in data["related"].get(cid, ())
    )

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
            "dateModified": page_lastmod(entry, data),
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
<link rel="stylesheet" href="/style.css"/>
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
<link rel="stylesheet" href="/style.css"/>
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
        title = f"CVE-{year}-{low} to CVE-{year}-{low + 999}: {len(entries):,} with public PoC exploits"
        description = (f"{len(entries):,} CVEs from CVE-{year}-{low} to CVE-{year}-{low + 999} "
                       "with public proof-of-concept exploits, with PoC counts and known-exploited status.")
        body = (f'<nav class="crumbs" aria-label="Browse"><a href="/{year}">{year}</a><span>/</span>{name}</nav>'
                f"<h1>CVE-{year}-{low} to CVE-{year}-{low + 999}</h1>"
                f'<p class="cve-desc">{len(entries):,} CVEs with public proof-of-concept exploits.</p>'
                f'<ul class="hub-list">{"".join(rows)}</ul>')
        pages[f"{name}.html"] = hub_shell(title, description, name, body, total)
        lastmod[name] = max(data["lastmod"].get(e["cve"], "") for e in entries) or data["today"]

    ordered = sorted(years)
    for year in ordered:
        year_blocks = sorted(years[year], key=lambda item: int(item[0][:-3]))
        count = sum(len(entries) for _, entries in year_blocks)
        rows = "".join(
            f'<li><a href="/CVE-{year}-{block}">CVE-{year}-{int(block[:-3]) * 1000} to {int(block[:-3]) * 1000 + 999}</a>'
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
        lastmod[year] = max(lastmod[f"CVE-{year}-{block}"] for block, _ in year_blocks)

    return {"pages": pages, "lastmod": lastmod}


def check_static_drift() -> None:
    """Fail the build if the hand-maintained homepage drifts from the constants.

    index.html is written by hand and cannot be generated without losing what
    is in it, so the next best thing is refusing to publish a homepage whose
    fonts or source credit no longer match what every generated page states.
    """
    with open(os.path.join(DOCS, "index.html"), encoding="utf-8") as handle:
        home = handle.read()
    problems = []
    if "fonts.googleapis.com/css2?family=Space+Grotesk" not in home:
        problems.append("index.html no longer loads the shared fonts")
    if SOURCES_LINE not in home:
        problems.append("index.html footer disagrees with brand.SOURCES_LINE")
    if problems:
        raise SystemExit("static drift: " + "; ".join(problems))


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
<link rel="stylesheet" href="/style.css"/>
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
    cves = load("CVE_list.json")
    data = {
        "cves": cves,
        "meta": load("cve_metadata.json"),
        "epss": load("epss.json"),
        "kev": load("kev.json"),
        "nuclei": load("nuclei.json"),
        "repo_meta": load("repo_meta.json"),
        "today": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
    }
    data["related"] = build_related(cves)

    written = 0
    lastmod = {}
    for entry in cves:
        cid = entry["cve"]
        with open(os.path.join(DOCS, f"{cid}.html"), "w", encoding="utf-8") as handle:
            handle.write(page(entry, data))
        lastmod[cid] = page_lastmod(entry, data)
        written += 1

    data["lastmod"] = lastmod
    hubs = hub_pages(cves, data)
    for name, markup in hubs["pages"].items():
        with open(os.path.join(DOCS, name), "w", encoding="utf-8") as handle:
            handle.write(markup)
    lastmod.update(hubs["lastmod"])

    # The sitemap has to quote the same date the page does, so it is computed
    # once here and handed to build_seo.py rather than derived twice. Hub pages
    # ride in the same file under their own names.
    with open(os.path.join(DOCS, LASTMOD), "w", encoding="utf-8") as handle:
        json.dump(lastmod, handle, separators=(",", ":"))

    with open(os.path.join(DOCS, "404.html"), "w", encoding="utf-8") as handle:
        handle.write(not_found())

    check_static_drift()

    related = sum(1 for cid in lastmod if data["related"].get(cid))
    print(f"Wrote {written:,} CVE pages and {len(hubs['pages']):,} hub pages into {DOCS} "
          f"({related:,} with a shared-author Related block)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
