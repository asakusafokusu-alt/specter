"""Web, news and public-record search across keyless sources."""

from __future__ import annotations

import base64
import html
import json
import math
import re
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Iterable
from urllib.parse import parse_qs, quote, quote_plus, urlsplit

from .. import images
from ..config import Config
from ..http import HttpClient
from ..google import GoogleScraper, google_url as _google_url, parse_results as _parse_google
from ..models import BLOCKED, ERROR, FOUND, INFO, Finding, ImageRef

DEFAULT_SOURCES = ("web", "news", "wikipedia", "wikidata", "hn")
ALL_SOURCES = (
    "web",
    "news",
    "wikipedia",
    "wikidata",
    "hn",
    "stack",
    "sec",
    "archive",
    "courtlistener",
    "crawl",
)

ENGINES = {
    "Google": "https://www.google.com/search?q={q}",
    "Bing": "https://www.bing.com/search?q={q}",
    "DuckDuckGo": "https://duckduckgo.com/?q={q}",
    "Brave": "https://search.brave.com/search?q={q}",
    "Yandex": "https://yandex.com/search/?text={q}",
    "Startpage": "https://www.startpage.com/sp/search?query={q}",
    "Mojeek": "https://www.mojeek.com/search?q={q}",
}

LOOKUPS: dict[str, list[tuple[str, str]]] = {
    "username": [
        ("Zeal", "https://zealsight.vercel.app/"),
        ("WhatsMyName", "https://whatsmyname.app/?q={t}"),
        ("Instant Username", "https://instantusername.com/?q={t}"),
        ("Namechk", "https://namechk.com/{t}"),
        ("Epieos", "https://epieos.com/?q={t}&t=username"),
    ],
    "email": [
        ("Epieos", "https://epieos.com/?q={t}&t=email"),
        ("IntelX", "https://intelx.io/?s={t}"),
        ("Hunter verifier", "https://hunter.io/email-verifier/{t}"),
        ("Have I Been Pwned", "https://haveibeenpwned.com/"),
    ],
    "phone": [
        ("NumLookup", "https://www.numlookup.com/?number={t}"),
        ("Truecaller", "https://www.truecaller.com/search/{t}"),
    ],
    "name": [
        ("TruePeopleSearch", "https://www.truepeoplesearch.com/results?name={t}"),
        ("Usersearch", "https://usersearch.org/"),
        ("Epieos", "https://epieos.com/?q={t}&t=name"),
    ],
    "domain": [
        ("urlscan", "https://urlscan.io/domain/{t}"),
        ("crt.sh", "https://crt.sh/?q={t}"),
        ("Wayback Machine", "https://web.archive.org/web/*/{t}"),
    ],
    "ip": [
        ("Shodan", "https://www.shodan.io/host/{t}"),
        ("Censys", "https://search.censys.io/hosts/{t}"),
    ],
}


DORKS = {
    "name": [
        '"{t}"',
        '"{t}" resume OR CV',
        '"{t}" linkedin',
        '"{t}" email',
        '"{t}" phone',
        '"{t}" filetype:pdf',
        '"{t}" -site:facebook.com',
        '"{t}" site:gov',
    ],
    "email": [
        '"{t}"',
        '"{t}" site:pastebin.com',
        '"{t}" -site:haveibeenpwned.com',
        '"{t}" filetype:pdf',
        '"{t}" github',
        '"{t}" leaked',
    ],
    "username": [
        '"{t}"',
        '"{t}" site:github.com',
        '"{t}" -site:github.com',
        '"{t}" email OR contact',
        '"{t}" forum',
        '"{t}" filetype:pdf',
    ],
    "phone": [
        '"{t}"',
        '"{t}" site:pastebin.com',
        '"{t}" filetype:pdf',
        '"{t}" whatsapp',
    ],
    "domain": [
        'site:{t}',
        '"{t}"',
        'site:{t} -www',
        '"{t}" email',
        '"{t}" whois',
        '"{t}" filetype:pdf',
    ],
    "ip": ['"{t}"', '"{t}" shodan', '"{t}" abuse'],
}


def _clean(text: str | None) -> str:
    if not text:
        return ""
    plain = re.sub(r"<[^>]+>", " ", text)
    return " ".join(html.unescape(plain).split())


_OPERATORS = {"site", "filetype", "intitle", "inurl", "in", "or", "and", "the"}


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", text.lower())


def _terms(query: str) -> list[str]:
    terms: list[str] = []
    for raw in re.findall(r"[A-Za-z0-9][A-Za-z0-9@._+-]*", query):
        if raw.lower() in _OPERATORS:
            continue
        term = _norm(raw)
        if len(term) >= 2 and term not in terms:
            terms.append(term)
    return terms


def _relevant(query: str, *texts: str | None) -> bool:
    """Reject pages that do not actually mention the search terms.

    Bing (and some other providers) return unrelated pages when a query has no
    matches. Presenting those as evidence would be misleading, so results must
    share most of the query's significant tokens.
    """
    terms = _terms(query)
    if not terms:
        return True
    blob = _norm(" ".join(text or "" for text in texts))
    if not blob:
        return False
    matched = sum(1 for term in terms if term in blob)
    if '"' in query:
        return matched == len(terms)
    return matched >= max(1, math.ceil(len(terms) * 0.6))


def dork_queries(target: str, kind: str) -> list[str]:
    template = DORKS.get(kind, DORKS["name"])
    return [item.format(t=target) for item in template]


def dork_links(target: str, kind: str = "name") -> list[tuple[str, str]]:
    """Search-engine links plus the manual lookup services for this kind."""
    query = quote_plus(f'"{target}"' if kind != "domain" else target)
    links = [(engine, url.format(q=query)) for engine, url in ENGINES.items()]
    raw = quote(target, safe="")
    for name, template in LOOKUPS.get(kind, []):
        links.append((name, template.format(t=raw, q=query)))
    return links


def _rss_image(item: ET.Element) -> str:
    """First usable image reference in a feed item (News:Image, enclosure, media)."""
    for child in item.iter():
        tag = str(child.tag).split("}")[-1].lower()
        if tag not in ("image", "thumbnail", "content", "enclosure"):
            continue
        candidate = (child.get("url") or child.get("href") or child.text or "").strip()
        if candidate.startswith(("http://", "https://")):
            return candidate
        for nested in child.iter():
            if nested is child:
                continue
            url = (nested.get("url") or "").strip()
            if url.startswith(("http://", "https://")):
                return url
    return ""


def _rss_items(text: str) -> list[dict[str, str]]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    items: list[dict[str, str]] = []
    for item in root.iter("item"):
        title = _clean(item.findtext("title"))
        link = (item.findtext("link") or "").strip()
        description = _clean(item.findtext("description"))
        published = (item.findtext("pubDate") or "").strip()
        source = item.find("source")
        publisher = _clean(source.text) if source is not None else ""
        if title or link:
            items.append(
                {
                    "title": title,
                    "url": link,
                    "description": description,
                    "published": published,
                    "publisher": publisher,
                    "image": _rss_image(item),
                }
            )
    return items


_BING_BLOCK = re.compile(r'<li class="b_algo', re.S)
_BING_TITLE = re.compile(r'<h2[^>]*>\s*<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>', re.S)
_BING_SNIPPET = re.compile(r"<p[^>]*>(.*?)</p>", re.S)


def _bing_url(href: str) -> str | None:
    """Decode Bing's /ck/a redirect wrapper to the real destination."""
    target = html.unescape(href).strip()
    if "bing.com/ck/a" in target:
        match = re.search(r"[?&]u=a1([^&]+)", target)
        if match:
            raw = match.group(1)
            if raw.startswith("http"):
                return raw
            padded = raw + "=" * (-len(raw) % 4)
            try:
                decoded = base64.urlsafe_b64decode(padded).decode("utf-8", "replace")
            except (ValueError, UnicodeDecodeError):
                return None
            return decoded if decoded.startswith(("http://", "https://")) else None
        match = re.search(r"[?&]u=([^&]+)", target)
        if match:
            decoded = html.unescape(match.group(1))
            return decoded if decoded.startswith(("http://", "https://")) else None
        return None
    return target if target.startswith(("http://", "https://")) else None


def _parse_bing(text: str, query: str, limit: int) -> list[Finding]:
    """Parse Bing's HTML result list (its RSS endpoint now returns unrelated pages)."""
    findings: list[Finding] = []
    for block in _BING_BLOCK.split(text)[1:]:
        title_match = _BING_TITLE.search(block)
        if not title_match:
            continue
        url = _bing_url(title_match.group(1))
        if not url:
            continue
        title = _clean(title_match.group(2))
        snippet_match = _BING_SNIPPET.search(block)
        snippet = _clean(snippet_match.group(1)) if snippet_match else ""
        if not _relevant(query, title, snippet, url):
            continue
        findings.append(
            Finding(
                source="Bing",
                category="Web",
                status=FOUND,
                title=title,
                url=url,
                detail=snippet[:400] or None,
            )
        )
        if len(findings) >= limit:
            break
    return findings


def _web_bing(query: str, limit: int, http: HttpClient) -> list[Finding]:
    response = http.get(
        "https://www.bing.com/search",
        params={"q": query},
        timeout=20,
    )
    if not response.ok:
        status = BLOCKED if response.blocked else ERROR
        return [
            Finding(
                source="Bing",
                category="Web",
                status=status,
                detail=f"Web search failed: {response.short_error()}",
            )
        ]
    findings = _parse_bing(response.text, query, limit)
    if not findings:
        findings.append(
            Finding(
                source="Bing",
                category="Web",
                status=INFO,
                detail="No relevant Bing results (unrelated pages are discarded).",
            )
        )
    return findings


def _web_google_html(
    query: str, limit: int, http: HttpClient, config: Config | None = None
) -> list[Finding]:
    """Keyless Google via the pacing/cooldown client in specter/google.py."""
    outcome = GoogleScraper(http, limit=limit).search(query)
    if outcome.findings:
        return outcome.findings
    return [
        Finding(
            source="Google",
            category="Web",
            status=outcome.status,
            detail=outcome.detail,
        )
    ]


# Concurrency, merging and result enrichment
# ---------------------------------------------------------------------------
_TRACKING = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "gclid",
    "fbclid",
    "ref",
    "ref_src",
    "mc_cid",
    "mc_eid",
    "igshid",
}


def _url_key(url: str) -> str:
    """Normalize a result URL so the same page from two engines collapses."""
    candidate = url if "://" in url else "https://" + url
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return url
    host = (parts.hostname or "").lower().removeprefix("www.")
    path = parts.path.rstrip("/") or "/"
    try:
        params = sorted(
            (key, value)
            for key, values in parse_qs(parts.query).items()
            for value in values
            if key.lower() not in _TRACKING
        )
    except ValueError:
        params = []
    query = "&".join(f"{key}={value}" for key, value in params)
    return f"{host}{path}" + (f"?{query}" if query else "")


def _parallel(calls: list[tuple[str, Callable[[], list[Finding]]]]) -> list[list[Finding]]:
    """Run provider calls concurrently; one failing provider never kills a search."""
    if not calls:
        return []
    if len(calls) == 1:
        name, func = calls[0]
        try:
            return [func()]
        except Exception as exc:  # noqa: BLE001 - provider isolation
            return [
                [
                    Finding(
                        source=name,
                        category="Web",
                        status=ERROR,
                        detail=f"{type(exc).__name__}: {exc}",
                    )
                ]
            ]
    with ThreadPoolExecutor(max_workers=min(8, len(calls))) as pool:
        futures = [pool.submit(func) for _, func in calls]
    results: list[list[Finding]] = []
    for (name, _), future in zip(calls, futures):
        try:
            results.append(future.result())
        except Exception as exc:  # noqa: BLE001 - provider isolation
            results.append(
                [
                    Finding(
                        source=name,
                        category="Web",
                        status=ERROR,
                        detail=f"{type(exc).__name__}: {exc}",
                    )
                ]
            )
    return results


def _merge_web(batches: list[list[Finding]], limit: int) -> list[Finding]:
    """Merge engine batches, dedupe by normalized URL and score agreement."""
    merged: dict[str, Finding] = {}
    engines: dict[str, list[str]] = {}
    notes: list[Finding] = []
    for batch in batches:
        for finding in batch:
            if not finding.url:
                notes.append(finding)
                continue
            key = _url_key(finding.url)
            engines.setdefault(key, []).append(finding.source)
            existing = merged.get(key)
            if existing is None:
                merged[key] = finding
                continue
            if len(finding.detail or "") > len(existing.detail or ""):
                existing.detail = finding.detail
            if finding.title and not existing.title:
                existing.title = finding.title
            for image in finding.images:
                if all(image.url != other.url for other in existing.images):
                    existing.images.append(image)
            for label, value in finding.data.items():
                existing.data.setdefault(label, value)

    results: list[Finding] = []
    for key, finding in merged.items():
        seen = engines.get(key, [])
        if len(seen) > 1:
            finding.data["also reported by"] = sorted(set(seen))
            finding.confidence = "high"
        else:
            finding.confidence = "medium"
        results.append(finding)

    if not results:
        return notes or [
            Finding(
                source="Web",
                category="Web",
                status=INFO,
                detail="No web results returned.",
            )
        ]
    # Keep provider warnings; drop the "nothing found" notes that no longer apply.
    return results[: limit + 1] + [note for note in notes if note.status in (ERROR, BLOCKED)]


def _attach_result_images(findings: list[Finding], http: HttpClient, limit: int = 3) -> None:
    """Read OpenGraph title, description and image for the top results (bounded)."""
    targets = [item for item in findings if item.status == FOUND and item.url][:limit]
    targets = [item for item in targets if images.is_allowed(item.url)]
    if not targets:
        return

    def worker(finding: Finding) -> None:
        response = http.get(finding.url, timeout=10)
        if not response.ok or not response.text:
            return
        meta = images.extract_meta(response.text, finding.url)
        image = meta.get("image")
        if image and all(image != ref.url for ref in finding.images):
            finding.images.append(
                ImageRef(url=image, alt=finding.title or "", kind="thumbnail", page_url=finding.url)
            )
        if meta.get("description") and not finding.data.get("description"):
            finding.data["description"] = meta["description"]
        if meta.get("favicon"):
            finding.data.setdefault("favicon", meta["favicon"])
        if meta.get("title") and not finding.title:
            finding.title = meta["title"]

    with ThreadPoolExecutor(max_workers=min(4, len(targets))) as pool:
        list(pool.map(worker, targets))


_DDG_BLOCK = re.compile(
    r'<div class="result results_links.*?(?=<div class="result results_links|</body>)', re.S
)
_DDG_TITLE = re.compile(r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', re.S)
_DDG_SNIPPET = re.compile(r'class="result__snippet[^"]*"[^>]*>(.*?)</(?:a|div|span)>', re.S)


def _ddg_target(href: str) -> str | None:
    target = html.unescape(href).strip()
    if target.startswith("//"):
        target = "https:" + target
    if "uddg=" in target:
        try:
            values = parse_qs(urlsplit(target).query).get("uddg") or []
        except ValueError:
            values = []
        if values:
            target = values[0]
    if target.startswith(("http://", "https://")):
        return target
    return None


def _parse_duckduckgo(text: str, query: str, limit: int) -> list[Finding]:
    findings: list[Finding] = []
    for block in _DDG_BLOCK.findall(text):
        title_match = _DDG_TITLE.search(block)
        if not title_match:
            continue
        url = _ddg_target(title_match.group(1))
        if not url:
            continue
        title = _clean(title_match.group(2))
        snippet_match = _DDG_SNIPPET.search(block)
        snippet = _clean(snippet_match.group(1)) if snippet_match else ""
        if not _relevant(query, title, snippet, url):
            continue
        findings.append(
            Finding(
                source="DuckDuckGo",
                category="Web",
                status=FOUND,
                title=title,
                url=url,
                detail=snippet[:400] or None,
            )
        )
        if len(findings) >= limit:
            break
    return findings


def _web_duckduckgo(query: str, limit: int, http: HttpClient) -> list[Finding]:
    """Keyless HTML endpoint: a second engine balances Bing's results."""
    response = http.get(
        "https://html.duckduckgo.com/html/",
        params={"q": query, "kl": "us-en"},
        headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Referer": "https://duckduckgo.com/",
        },
        timeout=20,
    )
    if not response.ok:
        status = BLOCKED if response.blocked else ERROR
        return [
            Finding(
                source="DuckDuckGo",
                category="Web",
                status=status,
                detail=f"Web search failed: {response.short_error()}",
            )
        ]
    findings = _parse_duckduckgo(response.text, query, limit)
    if not findings:
        findings.append(
            Finding(
                source="DuckDuckGo",
                category="Web",
                status=INFO,
                detail="No relevant DuckDuckGo results.",
            )
        )
    return findings


def _web_searxng(query: str, limit: int, http: HttpClient, base: str) -> list[Finding]:
    endpoint = base.rstrip("/") + "/search"
    response = http.get(
        endpoint,
        params={"q": query, "format": "json", "language": "en"},
        timeout=20,
    )
    if not response.ok:
        return []
    payload = response.json() or {}
    findings = []
    for result in (payload.get("results") or []):
        url = result.get("url")
        if not url:
            continue
        if not _relevant(query, result.get("title"), result.get("content"), url):
            continue
        findings.append(
            Finding(
                source=f"SearXNG · {result.get('engine', 'web')}",
                category="Web",
                status=FOUND,
                title=_clean(result.get("title")),
                url=url,
                detail=_clean(result.get("content"))[:240],
                confidence="high",
            )
        )
        if len(findings) >= limit:
            break
    return findings


def _web_google(query: str, limit: int, http: HttpClient, config: Config) -> list[Finding]:
    key = config.get("google_api_key")
    cx = config.get("google_cse_id")
    if not key or not cx:
        return []
    response = http.get(
        "https://www.googleapis.com/customsearch/v1",
        params={"key": key, "cx": cx, "q": query, "num": min(10, limit)},
    )
    payload = response.json() or {}
    if not response.ok:
        return []
    findings = []
    for item in payload.get("items") or []:
        if not _relevant(query, item.get("title"), item.get("snippet"), item.get("link")):
            continue
        findings.append(
            Finding(
                source="Google",
                category="Web",
                status=FOUND,
                title=_clean(item.get("title")),
                url=item.get("link"),
                detail=_clean(item.get("snippet"))[:240],
            )
        )
        if len(findings) >= limit:
            break
    return findings


def _web_brave(query: str, limit: int, http: HttpClient, config: Config) -> list[Finding]:
    key = config.get("brave_api_key")
    if not key:
        return []
    response = http.get(
        "https://api.search.brave.com/res/v1/web/search",
        params={"q": query, "count": limit},
        headers={"X-Subscription-Token": str(key), "Accept": "application/json"},
    )
    payload = response.json() or {}
    if not response.ok:
        return []
    results = (payload.get("web") or {}).get("results") or []
    findings = []
    for item in results:
        if not _relevant(query, item.get("title"), item.get("description"), item.get("url")):
            continue
        findings.append(
            Finding(
                source="Brave",
                category="Web",
                status=FOUND,
                title=_clean(item.get("title")),
                url=item.get("url"),
                detail=_clean(item.get("description"))[:240],
            )
        )
        if len(findings) >= limit:
            break
    return findings


def search_web(
    query: str,
    http: HttpClient,
    config: Config,
    *,
    limit: int = 10,
    include_images: bool = True,
) -> list[Finding]:
    """Query every available web engine concurrently and merge the results.

    The keyless engines (Bing, Google HTML and DuckDuckGo) always run, so
    coverage never depends on a paid key. Google is also tried with static HTML;
    when it serves its JavaScript wall the engine reports that instead of
    pretending there were no results. A configured SearXNG instance, Google CSE or
    Brave key is added on top and merged with the same deduplication.
    """
    calls: list[tuple[str, Callable[[], list[Finding]]]] = []
    searxng = config.get("searxng_url")
    if searxng:
        calls.append(("SearXNG", lambda: _web_searxng(query, limit, http, str(searxng))))
    calls.append(("Bing", lambda: _web_bing(query, limit, http)))
    google_cse = bool(config.get("google_api_key") and config.get("google_cse_id"))
    if google_cse:
        # The official API replaces HTML scraping; running both would double our
        # request rate against Google for the same results.
        calls.append(("Google", lambda: _web_google(query, limit, http, config)))
    else:
        calls.append(("Google", lambda: _web_google_html(query, limit, http)))
    calls.append(("DuckDuckGo", lambda: _web_duckduckgo(query, limit, http)))
    if config.get("brave_api_key"):
        calls.append(("Brave", lambda: _web_brave(query, limit, http, config)))

    findings = _merge_web(_parallel(calls), limit)
    if include_images:
        _attach_result_images(findings, http, limit=3)
    return findings


def _rss_news(
    query: str,
    limit: int,
    http: HttpClient,
    *,
    engine: str,
    endpoint: str,
    params: dict[str, Any],
) -> list[Finding]:
    response = http.get(endpoint, params=params, timeout=20)
    if not response.ok:
        return [
            Finding(
                source=engine,
                category="News",
                status=BLOCKED if response.blocked else ERROR,
                detail=f"News search failed: {response.short_error()}",
            )
        ]
    findings: list[Finding] = []
    for item in _rss_items(response.text):
        if not item["url"]:
            continue
        if not _relevant(query, item["title"], item["description"], item["url"]):
            continue
        detail = " · ".join(
            part
            for part in (item["publisher"], item["published"], item["description"])
            if part
        )
        findings.append(
            Finding(
                source=engine,
                category="News",
                status=FOUND,
                title=item["title"],
                url=item["url"],
                detail=detail or None,
                data=(
                    {"image": item["image"]}
                    if item.get("image")
                    else {}
                ),
                images=(
                    [
                        ImageRef(
                            url=item["image"],
                            alt=item["title"],
                            kind="thumbnail",
                            page_url=item["url"],
                        )
                    ]
                    if item.get("image")
                    else []
                ),
            )
        )
        if len(findings) >= limit:
            break
    return findings


def _news(
    query: str, limit: int, http: HttpClient, *, include_images: bool = True
) -> list[Finding]:
    batches = _parallel(
        [
            (
                "Google News",
                lambda: _rss_news(
                    query,
                    limit,
                    http,
                    engine="Google News",
                    endpoint="https://news.google.com/rss/search",
                    params={"q": query, "hl": "en-US", "gl": "US", "ceid": "US:en"},
                ),
            ),
            (
                "Bing News",
                lambda: _rss_news(
                    query,
                    limit,
                    http,
                    engine="Bing News",
                    endpoint="https://www.bing.com/news/search",
                    params={"q": query, "format": "rss", "count": limit},
                ),
            ),
        ]
    )
    findings: list[Finding] = []
    notes: list[Finding] = []
    seen: set[str] = set()
    for batch in batches:
        for finding in batch:
            if not finding.url:
                notes.append(finding)
                continue
            key = _url_key(finding.url)
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)
        if len(findings) >= limit:
            break
    if not findings:
        errors = [note for note in notes if note.status in (ERROR, BLOCKED)]
        if errors:
            return errors
        return [
            Finding(
                source="News",
                category="News",
                status=INFO,
                detail="No relevant news results for this query.",
            )
        ]
    if include_images:
        _attach_result_images(findings, http, limit=2)
    return findings[:limit]


def _wiki_enrich(
    findings: list[Finding], http: HttpClient, *, include_images: bool = True
) -> None:
    """One batched request for intro extracts and lead images of the top pages."""
    titles = [finding.title for finding in findings if finding.title][:5]
    if not titles:
        return
    response = http.get(
        "https://en.wikipedia.org/w/api.php",
        params={
            "action": "query",
            "prop": "extracts|pageimages|info",
            "exintro": 1,
            "explaintext": 1,
            "exlimit": "max",
            "pithumbsize": 600,
            "inprop": "url",
            "redirects": 1,
            "titles": "|".join(titles),
            "format": "json",
            "formatversion": "2",
        },
        timeout=20,
    )
    payload = response.json() or {}
    pages = (payload.get("query") or {}).get("pages") or []
    if isinstance(pages, dict):
        pages = list(pages.values())
    by_title: dict[str, dict[str, Any]] = {}
    for page in pages:
        if isinstance(page, dict) and page.get("title"):
            by_title[_norm(str(page["title"]))] = page
    for finding in findings:
        page = by_title.get(_norm(finding.title or ""))
        if not page:
            continue
        extract = " ".join(str(page.get("extract") or "").split())
        if extract:
            finding.data["extract"] = extract[:1800] + ("…" if len(extract) > 1800 else "")
            if not finding.detail:
                finding.detail = extract[:300]
        if page.get("pageid"):
            finding.data["page id"] = page.get("pageid")
        thumbnail = page.get("thumbnail") or {}
        source = thumbnail.get("source") if isinstance(thumbnail, dict) else None
        if include_images and source:
            finding.images.append(
                ImageRef(
                    url=str(source),
                    alt=finding.title or "",
                    kind="thumbnail",
                    page_url=finding.url,
                    width=thumbnail.get("width"),
                    height=thumbnail.get("height"),
                )
            )


def _wikipedia(
    query: str, limit: int, http: HttpClient, *, include_images: bool = True
) -> list[Finding]:
    response = http.get(
        "https://en.wikipedia.org/w/api.php",
        params={
            "action": "query",
            "list": "search",
            "srsearch": query,
            "srlimit": limit,
            "srprop": "snippet",
            "format": "json",
        },
    )
    payload = response.json() or {}
    results = (payload.get("query") or {}).get("search") or []
    findings = []
    for result in results:
        title = result.get("title", "")
        findings.append(
            Finding(
                source="Wikipedia",
                category="Wikipedia",
                status=FOUND,
                title=title,
                url=f"https://en.wikipedia.org/wiki/{quote(title.replace(' ', '_'), safe='')}",
                detail=_clean(result.get("snippet"))[:260],
                data={"word count": result.get("wordcount"), "timestamp": result.get("timestamp")},
            )
        )
    if findings:
        _wiki_enrich(findings[:3], http, include_images=include_images)
    if not findings and not response.ok:
        findings.append(
            Finding(
                source="Wikipedia",
                category="Wikipedia",
                status=BLOCKED if response.blocked else ERROR,
                detail=response.short_error(),
            )
        )
    return findings


WIKIDATA_PROPERTIES = {
    "P18": "image",
    "P569": "date of birth",
    "P570": "date of death",
    "P19": "place of birth",
    "P20": "place of death",
    "P27": "citizenship",
    "P31": "instance of",
    "P106": "occupation",
    "P625": "coordinates",
    "P856": "official website",
}


def _wikidata_time(value: str) -> str:
    text = str(value).lstrip("+")
    date = text.split("T")[0]
    return date.lstrip("-") + (" BCE" if text.startswith("-") else "")


def _wikidata_labels(ids: list[str], http: HttpClient) -> dict[str, str]:
    if not ids:
        return {}
    response = http.get(
        "https://www.wikidata.org/w/api.php",
        params={
            "action": "wbgetentities",
            "ids": "|".join(ids),
            "props": "labels",
            "languages": "en",
            "format": "json",
        },
        timeout=20,
    )
    entities = (response.json() or {}).get("entities") or {}
    labels: dict[str, str] = {}
    for qid, entity in entities.items():
        if isinstance(entity, dict):
            labels[qid] = ((entity.get("labels") or {}).get("en") or {}).get("value") or qid
    return labels


def _wikidata_enrich(
    findings: list[Finding], http: HttpClient, *, include_images: bool = True
) -> None:
    """Batched entity fetch: labels, key facts and the lead image."""
    ids = [str(finding.data.get("id")) for finding in findings if finding.data.get("id")][:3]
    if not ids:
        return
    response = http.get(
        "https://www.wikidata.org/w/api.php",
        params={
            "action": "wbgetentities",
            "ids": "|".join(ids),
            "props": "claims|labels|descriptions|sitelinks",
            "languages": "en",
            "sitefilter": "enwiki",
            "format": "json",
        },
        timeout=20,
    )
    entities = (response.json() or {}).get("entities") or {}
    pending: set[str] = set()
    built: dict[str, dict[str, list[str]]] = {}
    for qid in ids:
        entity = entities.get(qid) or {}
        claims = entity.get("claims") or {}
        facts: dict[str, list[str]] = {}
        for prop, label in WIKIDATA_PROPERTIES.items():
            values: list[str] = []
            for statement in (claims.get(prop) or [])[:3]:
                value = ((statement.get("mainsnak") or {}).get("datavalue") or {}).get("value")
                if value is None:
                    continue
                if isinstance(value, dict):
                    if "time" in value:
                        values.append(_wikidata_time(value["time"]))
                    elif "id" in value:
                        values.append(str(value["id"]))
                        pending.add(str(value["id"]))
                    elif "text" in value:
                        values.append(str(value["text"]))
                    elif "amount" in value:
                        values.append(str(value["amount"]))
                    elif "latitude" in value and "longitude" in value:
                        values.append(f"{value['latitude']}, {value['longitude']}")
                else:
                    values.append(str(value))
            values = [item for item in values if item]
            if values:
                facts[label] = values
        built[qid] = facts

    labels = _wikidata_labels(sorted(pending)[:40], http)
    for finding in findings:
        qid = str(finding.data.get("id"))
        entity = entities.get(qid) or {}
        facts = built.get(qid) or {}
        for label, values in facts.items():
            if label == "image":
                filename = values[0]
                finding.data["image file"] = filename
                if include_images:
                    url = (
                        "https://commons.wikimedia.org/wiki/Special:FilePath/"
                        + quote(filename.replace(" ", "_"))
                        + "?width=640"
                    )
                    finding.images.append(
                        ImageRef(
                            url=url,
                            alt=finding.title or "",
                            kind="thumbnail",
                            page_url=finding.url,
                        )
                    )
                continue
            resolved = [labels.get(value, value) for value in values]
            resolved = [item for item in resolved if item]
            if resolved:
                finding.data[label] = resolved[0] if len(resolved) == 1 else resolved
        description = ((entity.get("descriptions") or {}).get("en") or {}).get("value")
        if description and not finding.detail:
            finding.detail = description
        sitelink = ((entity.get("sitelinks") or {}).get("enwiki") or {}).get("title")
        if sitelink:
            finding.data["wikipedia"] = (
                "https://en.wikipedia.org/wiki/" + quote(str(sitelink).replace(" ", "_"))
            )


def _wikidata(
    query: str, limit: int, http: HttpClient, *, include_images: bool = True
) -> list[Finding]:
    response = http.get(
        "https://www.wikidata.org/w/api.php",
        params={
            "action": "wbsearchentities",
            "search": query,
            "language": "en",
            "uselang": "en",
            "limit": limit,
            "format": "json",
            "type": "item",
        },
    )
    payload = response.json() or {}
    findings = []
    for result in payload.get("search", [])[:limit]:
        findings.append(
            Finding(
                source="Wikidata",
                category="Wikidata",
                status=FOUND,
                title=result.get("label") or result.get("id"),
                url=result.get("concepturi"),
                detail=result.get("description") or result.get("id"),
                data={"id": result.get("id")},
            )
        )
    if findings:
        _wikidata_enrich(findings[:3], http, include_images=include_images)
    return findings


def _hackernews(query: str, limit: int, http: HttpClient) -> list[Finding]:
    response = http.get(
        "https://hn.algolia.com/api/v1/search",
        params={"query": query, "hitsPerPage": limit},
    )
    payload = response.json() or {}
    findings = []
    for hit in payload.get("hits", [])[:limit]:
        object_id = hit.get("objectID")
        url = hit.get("url") or hit.get("story_url") or (
            f"https://news.ycombinator.com/item?id={object_id}" if object_id else None
        )
        title = hit.get("title") or hit.get("story_title") or f"Hacker News item {object_id}"
        findings.append(
            Finding(
                source="Hacker News",
                category="Forums",
                status=FOUND,
                title=title,
                url=url,
                detail=(
                    f"by {hit.get('author', 'unknown')} · "
                    f"{hit.get('points') or 0} points · {hit.get('created_at', '')}"
                ),
                data={
                    "comments": hit.get("num_comments"),
                    "story id": object_id,
                },
            )
        )
    return findings


def _stackexchange(query: str, limit: int, http: HttpClient) -> list[Finding]:
    response = http.get(
        "https://api.stackexchange.com/2.3/search/excerpts",
        params={
            "order": "desc",
            "sort": "relevance",
            "q": query,
            "site": "stackoverflow",
            "pagesize": limit,
        },
    )
    payload = response.json() or {}
    findings = []
    for item in payload.get("items", [])[:limit]:
        question_id = item.get("question_id")
        url = (
            f"https://stackoverflow.com/q/{question_id}"
            if question_id
            else "https://stackoverflow.com"
        )
        findings.append(
            Finding(
                source="Stack Overflow",
                category="Forums",
                status=FOUND,
                title=_clean(item.get("title")),
                url=url,
                detail=_clean(item.get("excerpt"))[:220],
            )
        )
    return findings


def _sec_edgar(query: str, limit: int, http: HttpClient) -> list[Finding]:
    # SEC full-text search matches individual terms; quote names for precision.
    search_query = query if query.startswith('"') else f'"{query}"'
    response = http.get(
        "https://efts.sec.gov/LATEST/search-index",
        params={"q": search_query},
        timeout=25,
    )
    payload = response.json() or {}
    hits = ((payload.get("hits") or {}).get("hits") or [])[:limit]
    findings = []
    for hit in hits:
        source = hit.get("_source") or {}
        names = source.get("display_names") or []
        entity = ", ".join(names) if isinstance(names, list) else str(names)
        form = source.get("form")
        filed = source.get("file_date")
        cik = (source.get("ciks") or [None])[0]
        accession = (source.get("adsh") or "").replace("-", "")
        url = "https://www.sec.gov/edgar/search/#/q=" + quote(query)
        if cik and accession:
            url = f"https://www.sec.gov/Archives/edgar/data/{cik}/{accession}/{source.get('adsh')}-index.htm"
        findings.append(
            Finding(
                source="SEC EDGAR",
                category="Filings",
                status=FOUND,
                title=entity or "SEC filing",
                url=url,
                detail=f"{form or 'filing'} · filed {filed or 'unknown date'}",
                data={
                    "form": form,
                    "filed": filed,
                    "company": entity,
                    "file number": source.get("file_num"),
                },
            )
        )
    if not findings and not response.ok:
        findings.append(
            Finding(
                source="SEC EDGAR",
                category="Filings",
                status=ERROR,
                detail=response.short_error(),
            )
        )
    return findings


def _archive(query: str, limit: int, http: HttpClient) -> list[Finding]:
    response = http.get(
        "https://archive.org/advancedsearch.php",
        params=[
            ("q", query),
            ("fl[]", "identifier"),
            ("fl[]", "title"),
            ("fl[]", "year"),
            ("rows", limit),
            ("output", "json"),
        ],
        timeout=25,
    )
    payload = response.json() or {}
    docs = ((payload.get("response") or {}).get("docs") or [])[:limit]
    findings = []
    for doc in docs:
        identifier = doc.get("identifier")
        findings.append(
            Finding(
                source="Internet Archive",
                category="Archive",
                status=FOUND,
                title=_clean(doc.get("title")) or str(identifier),
                url=f"https://archive.org/details/{quote(str(identifier))}" if identifier else None,
                detail=f"Archived item · {doc.get('year', 'undated')}",
            )
        )
    return findings


def _courtlistener(query: str, limit: int, http: HttpClient, config: Config) -> list[Finding]:
    token = config.get("courtlistener_token")
    if not token:
        return []
    response = http.get(
        "https://www.courtlistener.com/api/rest/v4/search/",
        params={"q": query, "type": "r"},
        headers={"Authorization": f"Token {token}"},
    )
    payload = response.json() or {}
    findings = []
    for result in payload.get("results", [])[:limit]:
        case = result.get("caseName") or result.get("case_name") or "Court record"
        findings.append(
            Finding(
                source="CourtListener",
                category="Filings",
                status=FOUND,
                title=case,
                url=result.get("absolute_url") or "https://www.courtlistener.com/",
                detail=f"{result.get('court', '')} · filed {result.get('dateFiled', 'unknown')}",
                data={"docket": result.get("docketNumber"), "citation": result.get("citation")},
            )
        )
    return findings


def search_all(
    query: str,
    http: HttpClient,
    config: Config,
    *,
    sources: Iterable[str] | None = None,
    limit: int = 10,
    kind: str = "name",
    include_images: bool = True,
) -> list[Finding]:
    """Run every requested source and return grouped findings."""
    selected = [source.lower() for source in (sources or DEFAULT_SOURCES)]
    if "all" in selected:
        selected = list(ALL_SOURCES)

    findings: list[Finding] = []
    for source in selected:
        # The crawl runs last, seeded with whatever the other sources returned.
        if source == "crawl":
            continue
        try:
            if source == "web":
                findings.extend(
                    search_web(query, http, config, limit=limit, include_images=include_images)
                )
            elif source == "news":
                findings.extend(_news(query, limit, http, include_images=include_images))
            elif source == "wikipedia":
                findings.extend(_wikipedia(query, limit, http, include_images=include_images))
            elif source == "wikidata":
                findings.extend(_wikidata(query, limit, http, include_images=include_images))
            elif source == "hn":
                findings.extend(_hackernews(query, limit, http))
            elif source == "stack":
                findings.extend(_stackexchange(query, limit, http))
            elif source == "sec":
                findings.extend(_sec_edgar(query, limit, http))
            elif source == "archive":
                findings.extend(_archive(query, limit, http))
            elif source == "courtlistener":
                findings.extend(_courtlistener(query, limit, http, config))
            else:
                findings.append(
                    Finding(
                        source="Search",
                        category="Web",
                        status=INFO,
                        detail=f"Unknown source '{source}' (valid: {', '.join(ALL_SOURCES)}).",
                    )
                )
        except Exception as exc:  # noqa: BLE001 - one provider must not kill the search
            findings.append(
                Finding(
                    source=f"Search ({source})",
                    category="Web",
                    status=ERROR,
                    detail=f"{type(exc).__name__}: {exc}",
                )
            )

    if "crawl" in selected:
        try:
            from .scrape import DEFAULT_PAGES, crawl_findings

            seeds = [
                (finding.url, finding.title or "")
                for finding in findings
                if finding.category == "Web" and finding.url
            ][:limit]
            if not seeds:
                seeds = [
                    (finding.url, finding.title or "")
                    for finding in search_web(
                        query, http, config, limit=limit, include_images=include_images
                    )
                    if finding.url
                ][:limit]
            findings.extend(
                crawl_findings(
                    query,
                    seeds,
                    http,
                    config,
                    budget=min(max(1, limit), DEFAULT_PAGES),
                )
            )
        except Exception as exc:  # noqa: BLE001 - a crawl failure must not hide results
            findings.append(
                Finding(
                    source="Crawl",
                    category="Web",
                    status=ERROR,
                    detail=f"{type(exc).__name__}: {exc}",
                )
            )
    return findings
