#!/usr/bin/env python3
"""Write docs/robots.txt and docs/sitemap.xml.

Both files were 404 before this, so nothing told a crawler where the site ends
or how often it changes. Everything here is derived from scripts/brand.py, so a
domain move is one edit rather than a hunt through the tree.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from brand import BRAND, DESCRIPTION, SITE

DOCS = os.path.join(ROOT, "docs")
ROBOTS = os.path.join(DOCS, "robots.txt")
SITEMAP = os.path.join(DOCS, "sitemap.xml")

# These small feeds enhance the prerendered homepage and remain crawlable.
RENDER_CRITICAL = ("trending_poc.json", "kev.json", "stats.json")

# These only feed the search box, which a crawler never types into. Together they
# are over 13 MB on the wire, which is crawl budget spent on nothing. Blocking
# them here does not touch curl: robots.txt binds crawlers, not clients.
BULK_PAYLOADS = (
    "CVE_list.json",
    "cve_metadata.json",
    "cvss.json",
    "advisories.json",
    "epss.json",
    "repo_meta.json",
    "nuclei.json",
)


def robots() -> str:
    lines = ["User-agent: *", "Allow: /"]
    lines += [f"Disallow: /{name}" for name in BULK_PAYLOADS]
    lines += ["", f"Sitemap: {SITE}/sitemap.xml", ""]
    return "\n".join(lines)


def opensearch() -> str:
    """The descriptor a browser reads to offer the site as a search engine."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<OpenSearchDescription xmlns="http://a9.com/-/spec/opensearch/1.1/">\n'
        f"  <ShortName>{BRAND}</ShortName>\n"
        f"  <Description>{DESCRIPTION}</Description>\n"
        "  <InputEncoding>UTF-8</InputEncoding>\n"
        f'  <Image width="16" height="16" type="image/x-icon">{SITE}/favicon.ico</Image>\n'
        f'  <Url type="text/html" method="get" template="{SITE}/?q={{searchTerms}}"/>\n'
        "</OpenSearchDescription>\n"
    )


def urlset(urls: list[tuple[str, str]]) -> str:
    body = "".join(
        f"  <url>\n    <loc>{loc}</loc>\n    <lastmod>{lastmod}</lastmod>\n  </url>\n"
        for loc, lastmod in urls
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{body}</urlset>\n"
    )


def sitemap_index(names: list[tuple[str, str]]) -> str:
    body = "".join(
        f"  <sitemap>\n    <loc>{SITE}/{name}</loc>\n"
        f"    <lastmod>{lastmod}</lastmod>\n  </sitemap>\n"
        for name, lastmod in names
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{body}</sitemapindex>\n"
    )


def main() -> int:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    os.makedirs(DOCS, exist_ok=True)

    with open(ROBOTS, "w", encoding="utf-8") as handle:
        handle.write(robots())
    with open(os.path.join(DOCS, "opensearch.xml"), "w", encoding="utf-8") as handle:
        handle.write(opensearch())

    # One sitemap per CVE year. The 50,000 URL cap makes some split necessary and
    # the year is the split the data already has, which also means a crawler only
    # refetches the shard that moved.
    try:
        with open(os.path.join(DOCS, "CVE_list.json"), encoding="utf-8") as handle:
            cves = json.load(handle)
    except FileNotFoundError:
        cves = []

    # build_pages.py works out when each page actually changed, taking the new
    # PoC repositories into account and not only the CVE record date, and drops
    # the answer here. Falling back to the record date keeps a standalone run
    # working, just less accurately.
    try:
        with open(os.path.join(DOCS, "page_lastmod.json"), encoding="utf-8") as handle:
            page_dates = json.load(handle)
    except (OSError, json.JSONDecodeError):
        page_dates = {}

    years: dict[str, list[tuple[str, str]]] = {}
    for entry in cves:
        cid = entry["cve"]
        year = cid.split("-")[1]
        lastmod = page_dates.get(cid) or entry.get("modified") or entry.get("published") or today
        years.setdefault(year, []).append((f"{SITE}/{cid}", lastmod))

    # A shard's own lastmod is the newest page in it. Stamping every shard with
    # today told a crawler all 29 had changed on every build, which is the kind
    # of lastmod Google stops trusting and then ignores.
    names: list[tuple[str, str]] = []
    for year in sorted(years):
        name = f"sitemap-{year}.xml"
        with open(os.path.join(DOCS, name), "w", encoding="utf-8") as handle:
            handle.write(urlset(years[year]))
        names.append((name, max(date for _, date in years[year])))

    # The year and block hubs build_pages.py writes, keyed in page_lastmod.json
    # under their own names beside the CVE ids.
    hubs = sorted(
        (f"{SITE}/{name}", date) for name, date in page_dates.items()
        if not name.startswith("CVE-") or name.endswith("xxx")
    )
    if hubs:
        with open(os.path.join(DOCS, "sitemap-hubs.xml"), "w", encoding="utf-8") as handle:
            handle.write(urlset(hubs))
        names.insert(0, ("sitemap-hubs.xml", max(date for _, date in hubs)))

    with open(os.path.join(DOCS, "sitemap-home.xml"), "w", encoding="utf-8") as handle:
        handle.write(urlset([(f"{SITE}/", today)]))
    names.insert(0, ("sitemap-home.xml", today))

    with open(SITEMAP, "w", encoding="utf-8") as handle:
        handle.write(sitemap_index(names))

    total = sum(len(v) for v in years.values()) + 1 + len(hubs)
    sourced = sum(1 for entry in cves if page_dates.get(entry["cve"]))
    print(f"Wrote {ROBOTS}, {SITEMAP} and {len(names)} shards ({total:,} URLs) for {SITE}; "
          f"{sourced:,} lastmod values reflect page content")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
