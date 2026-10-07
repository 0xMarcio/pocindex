"""Every user-facing name and URL, in one place.

The site header, the browser title, the social card, the README banner and the
GitHub About box all have to say the same thing. When they disagree Google picks
its own site name, and mentions stop compounding into one brand. Change a string
here and every generated surface follows.
"""

BRAND = "PoC Index"
TITLE = f"{BRAND}: Search CVE Proof-of-Concept Exploits"
# Short line under the wordmark, on the site and on both cards.
SUBTITLE = "Public proof-of-concept exploits, indexed by CVE."
# Meta description, the JSON-LD description and the GitHub About box, which are
# three places a reader meets the same sentence and so should be one string.
# Keep this evergreen: search engines cache snippets independently of the
# corpus updates. Exact counts belong in the generated page, not this promise.
DESCRIPTION = (
    "Search public CVE proof-of-concept exploits from GitHub, Nuclei, ExploitDB, "
    "Metasploit and Vulhub, with CVSS, EPSS and CISA KEV context."
)

SEARCH_GUIDE = (
    "Find exploits by CVE, vendor, product or keyword. Compare CVSS severity, "
    "EPSS exploitation scores and CISA known-exploited status."
)

SITE = "https://pocindex.io"
SLUG = "0xMarcio/pocindex"


def host() -> str:
    """SITE without the scheme, for the places that display a bare domain."""
    return SITE.split("://", 1)[-1].rstrip("/")

# The head fragment every page shares. The per-CVE pages rendered without it and
# fell back to system fonts, which is why they read as a different site.
FONTS = (
    '<link rel="preconnect" href="https://fonts.googleapis.com"/>\n'
    '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>\n'
    '<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600'
    '&amp;family=IBM+Plex+Mono:wght@400;500&amp;display=swap" rel="stylesheet"/>'
)

# One footer credit line. The homepage and the generated pages listed different
# sources, so a reader met two different claims about where the data comes from.
SOURCES_LINE = (
    'sources: <a href="https://nvd.nist.gov/">nvd</a>&nbsp;&middot; '
    '<a href="https://www.cve.org/">cve program</a>&nbsp;&middot; '
    '<a href="https://github.com/search?q=cve+poc&amp;type=repositories">github</a>&nbsp;&middot; '
    '<a href="https://github.com/advisories">github advisories</a>&nbsp;&middot; '
    '<a href="https://github.com/cisagov/vulnrichment">cisa vulnrichment</a>&nbsp;&middot; '
    '<a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">cisa kev</a>&nbsp;&middot; '
    '<a href="https://www.first.org/epss/">first epss</a>'
)
REPO_LINK = f'<a href="https://github.com/{SLUG}">github.com/{SLUG}</a>'
# Rendered beside REPO_LINK only once the Sponsors profile is public.
SPONSOR_LINK = '<a href="https://github.com/sponsors/0xMarcio">sponsor</a>'
