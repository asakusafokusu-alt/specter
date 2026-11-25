"""A focused, best-first web crawler for person investigations.

Instead of fetching every link on a page, this keeps a priority queue scored
against the target's identifiers (name, handles, addresses, domains, employer,
location). Links that cannot plausibly mention the target are pruned before any
request is made, near-duplicate pages are skipped by content digest, and the
crawl stops when the budget is spent or the next candidate scores too low.

It also extracts what an investigator actually needs from each page: visible
addresses and phone numbers, linked profiles, JSON-LD entities (schema.org
Person/Organization), names and organisations, images and a text excerpt.

Politeness: robots.txt is honoured per host, only text/html is parsed, pages are
size-capped, and requests are spaced per host.
"""

from __future__ import annotations

import hashlib
import heapq
import json
import re
import time
from dataclasses import dataclass, field
from html import unescape
from html.parser import HTMLParser
from typing import Any, Callable, Iterable
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser

import phonenumbers

from .http import HttpClient
from .models import Finding, ImageRef

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(?:\+|00)?\d[\d\s().-]{7,}\d")
TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid", "ref", "ref_src", "mc_cid", "mc_eid", "igshid", "s", "si",
}
SKIP_SUFFIXES = (
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico", ".pdf", ".zip",
    ".gz", ".mp4", ".mp3", ".css", ".js", ".woff", ".woff2", ".ttf",
)
PLATFORM_HOSTS = {
    "github.com": "GitHub",
    "gitlab.com": "GitLab",
    "linkedin.com": "LinkedIn",
    "twitter.com": "X",
    "x.com": "X",
    "instagram.com": "Instagram",
    "facebook.com": "Facebook",
    "keybase.io": "Keybase",
    "bsky.app": "Bluesky",
    "mastodon.social": "Mastodon",
    "stackoverflow.com": "Stack Overflow",
    "medium.com": "Medium",
    "about.me": "About.me",
    "gravatar.com": "Gravatar",
    "youtube.com": "YouTube",
    "t.me": "Telegram",
    "wa.me": "WhatsApp",
    "reddit.com": "Reddit",
    "pinterest.com": "Pinterest",
    "tiktok.com": "TikTok",
    "dev.to": "Dev.to",
    "npmjs.com": "npm",
    "pypi.org": "PyPI",
    "crunchbase.com": "Crunchbase",
}
BOOST_WORDS = (("contact", 2.5), ("about", 1.8), ("team", 1.5), ("profile", 1.5), ("cv", 2.0), ("resume", 2.0), ("bio", 1.5), ("people", 1.2))


# ---------------------------------------------------------------------------
# Target model
# ---------------------------------------------------------------------------
@dataclass
class Target:
    """Weighted terms the crawler scores candidates against."""

    terms: dict[str, float] = field(default_factory=dict)
    emails: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)

    @classmethod
    def from_query(cls, query: str, extra: Iterable[str] | None = None) -> "Target":
        target = cls()
        for item in [query, *(extra or [])]:
            for token in re.split(r"[^A-Za-z0-9@._+-]+", str(item)):
                token = token.strip().lower()
                if len(token) < 3 or token in {"the", "and", "for", "site", "www", "com", "net", "org"}:
                    continue
                weight = 2.5 if "@" in token else 1.6
                target.terms[token] = max(target.terms.get(token, 0), weight)
                if "@" in token:
                    target.emails.add(token)
                elif "." in token and not token.startswith(".") and token.count(".") >= 1:
                    target.domains.add(token)
        return target

    @classmethod
    def from_person(cls, person: Any) -> "Target":
        """Build the term set from a PersonInput (name, handles, employer...)."""
        target = cls()
        values: list[tuple[str, float]] = []
        if person.full_name:
            for token in person.full_name.split():
                if len(token) >= 3:
                    values.append((token, 2.0))
        for alias in person.aliases:
            values.append((alias, 1.8))
        for username in person.usernames:
            values.append((username, 2.6))
        for email in person.emails:
            values.append((email, 2.6))
            target.emails.add(email.lower())
            local = email.split("@")[0]
            if len(local) >= 4:
                values.append((local, 2.0))
        for domain in person.domains:
            values.append((domain, 2.0))
            target.domains.add(domain.lower())
        if person.employer:
            values.append((person.employer, 1.6))
        if person.location:
            for token in re.split(r"[,\s]+", person.location):
                if len(token) >= 3:
                    values.append((token, 1.2))
        for text, weight in values:
            for token in re.split(r"[^A-Za-z0-9@._+-]+", text.lower()):
                if len(token) < 3:
                    continue
                target.terms[token] = max(target.terms.get(token, 0), weight)
        return target

    def match_terms(self, *texts: str) -> list[str]:
        haystack = " ".join(text or "" for text in texts).lower()
        if not haystack.strip():
            return []
        return sorted(term for term in self.terms if term in haystack)

    def score_text(self, *texts: str) -> float:
        haystack = " ".join(text or "" for text in texts).lower()
        if not haystack.strip():
            return 0.0
        score = 0.0
        for term, weight in self.terms.items():
            if term in haystack:
                score += weight
        return score


def url_key(url: str) -> str:
    """Stable identity for a URL: no scheme, www, fragment, tracking or slash."""
    try:
        parts = urlsplit(url if "://" in url else "https://" + url)
    except ValueError:
        return url
    host = (parts.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    path = re.sub(r"/{2,}", "/", parts.path).rstrip("/") or "/"
    query = "&".join(
        f"{key}={value}"
        for key, value in sorted(
            item for item in _query_pairs(parts.query) if item[0].lower() not in TRACKING_PARAMS
        )
    )
    return f"{host}{path}" + (f"?{query}" if query else "")


def _query_pairs(query: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for chunk in query.split("&"):
        if not chunk:
            continue
        key, _, value = chunk.partition("=")
        pairs.append((key, value))
    return pairs


def origin_of(url: str) -> str:
    try:
        parts = urlsplit(url if "://" in url else "https://" + url)
    except ValueError:
        return ""
    host = (parts.hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


# ---------------------------------------------------------------------------
# Page parsing
# ---------------------------------------------------------------------------
@dataclass
class PageData:
    url: str
    title: str
    description: str
    text: str
    emails: set[str] = field(default_factory=set)
    phones: set[str] = field(default_factory=set)
    profiles: dict[str, set[str]] = field(default_factory=dict)
    names: set[str] = field(default_factory=set)
    organisations: set[str] = field(default_factory=set)
    entities: list[dict[str, Any]] = field(default_factory=list)
    images: list[str] = field(default_factory=list)
    links: list[tuple[str, str]] = field(default_factory=list)
    matched: list[str] = field(default_factory=list)
    relevance: float = 0.0

    @property
    def excerpt(self) -> str:
        return " ".join(self.text.split())[:420]


class _Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.meta: dict[str, str] = {}
        self.links: list[tuple[str, str]] = []
        self.text_parts: list[str] = []
        self.main_parts: list[str] = []
        self.jsonld: list[str] = []
        self.mailto: list[str] = []
        self.tel: list[str] = []
        self._in_title = False
        self._skip = 0
        self._in_jsonld = False
        self._href: str | None = None
        self._anchor: list[str] = []
        self._main = 0
        self._zone = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key: value or "" for key, value in attrs}
        if tag in ("script", "style", "noscript"):
            kind = values.get("type", "").lower()
            if tag == "script" and "ld+json" in kind:
                self._in_jsonld = True
                return
            self._skip += 1
        elif tag == "title":
            self._in_title = True
        elif tag in ("main", "article"):
            self._main += 1
        elif tag in ("nav", "aside", "footer"):
            self._zone += 1
        elif tag == "a":
            href = values.get("href", "").strip()
            if href.lower().startswith("mailto:"):
                self.mailto.append(href[7:].split("?")[0])
            elif href.lower().startswith("tel:"):
                self.tel.append(href[4:].strip())
            elif href:
                self._href = href
                self._anchor = []
        elif tag == "meta":
            name = (values.get("property") or values.get("name") or "").lower()
            content = values.get("content", "")
            if name and content:
                self.meta.setdefault(name, content)
        elif tag == "img" and values.get("src"):
            if not self.meta.get("og:image"):
                self.meta["og:image"] = values["src"]

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style", "noscript"):
            if self._in_jsonld:
                self._in_jsonld = False
            elif self._skip:
                self._skip -= 1
        elif tag == "title":
            self._in_title = False
        elif tag in ("main", "article"):
            self._main = max(0, self._main - 1)
        elif tag in ("nav", "aside", "footer"):
            self._zone = max(0, self._zone - 1)
        elif tag == "a" and self._href is not None:
            self.links.append((self._href, " ".join("".join(self._anchor).split())))
            self._href = None
            self._anchor = []

    def handle_data(self, data: str) -> None:
        if self._in_jsonld:
            self.jsonld.append(data)
            return
        if self._skip:
            return
        if self._in_title:
            self.title += data
        if self._href is not None:
            self._anchor.append(data)
        self.text_parts.append(data)
        if self._main and not self._zone:
            self.main_parts.append(data)


def _entities_from_jsonld(blocks: list[str]) -> list[dict[str, Any]]:
    wanted = {"person", "organization", "localbusiness", "professionalservice"}
    found: list[dict[str, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            kind = str(node.get("@type") or "").lower()
            kinds = kind if isinstance(kind, list) else [kind]
            if any(item in wanted for item in kinds):
                found.append(node)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    for block in blocks:
        try:
            walk(json.loads(block))
        except (ValueError, TypeError):
            continue
    return found


def _phones(text: str, region: str | None) -> set[str]:
    numbers: set[str] = set()
    for match in PHONE_RE.finditer(text):
        raw = " ".join(match.group(0).split())
        if not region and not raw.startswith("+"):
            continue
        try:
            parsed = phonenumbers.parse(raw, region or "ZZ")
        except phonenumbers.NumberParseException:
            continue
        if phonenumbers.is_valid_number(parsed):
            numbers.add(phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164))
    return numbers


def _profiles(links: Iterable[tuple[str, str]], base_url: str) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for href, _ in links:
        absolute = urljoin(base_url, href)
        host = origin_of(absolute)
        for candidate, platform in PLATFORM_HOSTS.items():
            if host == candidate or host.endswith("." + candidate):
                found.setdefault(platform, set()).add(absolute)
                break
    return found


def extract_page(html_text: str, url: str, *, region: str | None = None) -> PageData:
    parser = _Parser()
    try:
        parser.feed(html_text or "")
    except Exception:  # noqa: BLE001 - malformed markup must not stop a crawl
        pass
    full_text = " ".join(" ".join(parser.text_parts).split())
    main_text = " ".join(" ".join(parser.main_parts).split())
    # Prefer the article body: navigation repeats the site name on every page
    # and would make each one look relevant to the target.
    text = main_text if len(main_text) >= 180 else full_text
    emails = {match.lower() for match in EMAIL_RE.findall(full_text)}
    for value in parser.mailto:
        emails.update(match.lower() for match in EMAIL_RE.findall(value))
    emails = {email for email in emails if not email.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp"))}
    entities = _entities_from_jsonld(parser.jsonld)
    names: set[str] = set()
    organisations: set[str] = set()
    phones = _phones(full_text, region)
    for entity in entities:
        email_value = entity.get("email")
        if isinstance(email_value, str):
            cleaned = email_value.strip().removeprefix("mailto:").lower()
            if EMAIL_RE.fullmatch(cleaned):
                emails.add(cleaned)
        phone_value = entity.get("telephone")
        if isinstance(phone_value, str):
            phones |= _phones(phone_value, region)
        kind = str(entity.get("@type") or "").lower()
        name = str(entity.get("name") or "").strip()
        if not name:
            continue
        if "person" in kind:
            names.add(name)
            employer = entity.get("worksFor") or entity.get("affiliation")
            if isinstance(employer, dict) and employer.get("name"):
                organisations.add(str(employer["name"]))
            elif isinstance(employer, str):
                organisations.add(employer)
        else:
            organisations.add(name)
    # schema.org sameAs lists the profiles the page itself vouches for.
    profile_links = list(parser.links)
    for entity in entities:
        same_as = entity.get("sameAs")
        for value in same_as if isinstance(same_as, list) else [same_as]:
            if isinstance(value, str) and value.startswith(("http://", "https://")):
                profile_links.append((value, ""))
    images: list[str] = []
    for key in ("og:image", "twitter:image", "og:image:url"):
        value = parser.meta.get(key)
        if value:
            absolute = urljoin(url, value)
            if absolute.startswith(("http://", "https://")) and absolute not in images:
                images.append(absolute)
    return PageData(
        url=url,
        title=" ".join(unescape(parser.title).split()) or parser.meta.get("og:title", ""),
        description=parser.meta.get("og:description") or parser.meta.get("description", ""),
        text=text,
        emails=emails,
        phones=phones,
        profiles=_profiles(profile_links, url),
        names=names,
        organisations=organisations,
        entities=entities,
        images=images,
        links=[(urljoin(url, href), anchor) for href, anchor in parser.links if href],
    )


# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------
@dataclass
class FetchResult:
    ok: bool
    url: str
    status: int | None = None
    text: str = ""
    content_type: str = ""
    error: str | None = None


@dataclass
class CrawlResult:
    pages: list[PageData] = field(default_factory=list)
    fetched: int = 0
    skipped: int = 0
    pruned: int = 0
    duplicates: int = 0
    budget: int = 0
    seeds: list[str] = field(default_factory=list)
    stopped: str = ""


def _http_fetcher(http: HttpClient, timeout: int, max_bytes: int) -> Callable[[str], FetchResult]:
    def fetch(url: str) -> FetchResult:
        response = http.get(url, timeout=timeout)
        text = response.text or ""
        if len(text) > max_bytes:
            text = text[:max_bytes]
        content_type = (response.header("content-type") or "").split(";")[0].strip().lower()
        return FetchResult(
            ok=bool(response.ok),
            url=response.url or url,
            status=response.status,
            text=text,
            content_type=content_type,
            error=response.short_error() if not response.ok else None,
        )

    return fetch


class SmartCrawler:
    """Best-first crawl scored against a target, bounded by pages and depth."""

    def __init__(
        self,
        http: HttpClient,
        *,
        budget: int = 8,
        max_depth: int = 2,
        min_link_score: float = 2.0,
        min_page_score: float = 1.5,
        timeout: int = 12,
        max_bytes: int = 1_500_000,
        same_site_bonus: float = 1.5,
        delay_per_host: float = 0.35,
        respect_robots: bool = True,
        region: str | None = None,
        fetcher: Callable[[str], FetchResult] | None = None,
    ) -> None:
        self.budget = max(1, budget)
        self.max_depth = max(0, max_depth)
        self.min_link_score = min_link_score
        self.min_page_score = min_page_score
        self.same_site_bonus = same_site_bonus
        self.delay_per_host = delay_per_host
        self.respect_robots = respect_robots
        self.region = region
        self.fetcher = fetcher or _http_fetcher(http, timeout, max_bytes)
        self._user_agent = getattr(http, "user_agent", "SPECTER")
        self._robots: dict[str, RobotFileParser | None] = {}
        self._last_request: dict[str, float] = {}

    # -- robots / politeness ---------------------------------------------
    def _robots_allows(self, url: str) -> bool:
        host = origin_of(url)
        if host not in self._robots:
            parser = RobotFileParser()
            try:
                response = self.fetcher(f"https://{host}/robots.txt")
                if response.ok and "html" not in response.content_type:
                    parser.parse(response.text.splitlines())
                    self._robots[host] = parser
                else:
                    self._robots[host] = None
            except Exception:  # noqa: BLE001 - unknown robots = allowed
                self._robots[host] = None
        parser = self._robots[host]
        if parser is None:
            return True
        try:
            return parser.can_fetch(self._user_agent, url)
        except Exception:  # noqa: BLE001
            return True

    def _polite_wait(self, url: str) -> None:
        host = origin_of(url)
        last = self._last_request.get(host)
        now = time.monotonic()
        if last is not None and now - last < self.delay_per_host:
            time.sleep(self.delay_per_host - (now - last))
        self._last_request[host] = time.monotonic()

    # -- scoring ----------------------------------------------------------
    def score_link(self, target: Target, url: str, anchor: str, depth: int, seed_hosts: set[str]) -> float:
        score = target.score_text(anchor, url)
        lowered = f"{anchor} {url}".lower()
        for word, bonus in BOOST_WORDS:
            if word in lowered:
                score += bonus
        if depth == 0:
            score += 1.0
        else:
            score -= 0.8 * depth
        if origin_of(url) in seed_hosts:
            score += self.same_site_bonus
        return score

    # -- run --------------------------------------------------------------
    def run(self, seeds: Iterable[tuple[str, str]], target: Target) -> CrawlResult:
        result = CrawlResult(budget=self.budget)
        heap: list[tuple[float, int, int, str, str]] = []
        sequence = 0
        seed_hosts = {origin_of(url) for url, _ in seeds}
        for url, anchor in seeds:
            if not _crawlable(url):
                continue
            result.seeds.append(url)
            heapq.heappush(heap, (-1e9, sequence, 0, url, anchor))
            sequence += 1

        visited: set[str] = set()
        digests: set[str] = set()

        while heap and result.fetched < self.budget:
            priority, _, depth, url, anchor = heapq.heappop(heap)
            score = -priority
            if score < self.min_link_score and depth > 0:
                # Everything left is weaker than this, so stop instead of crawling noise.
                result.pruned += 1 + len(heap)
                result.stopped = "relevance threshold reached"
                break
            key = url_key(url)
            if key in visited:
                continue
            visited.add(key)
            if self.respect_robots and not self._robots_allows(url):
                result.skipped += 1
                continue
            self._polite_wait(url)
            fetched = self.fetcher(url)
            if not fetched.ok or not fetched.text:
                result.skipped += 1
                continue
            content_type = fetched.content_type
            if content_type and "html" not in content_type and "xml" not in content_type:
                result.skipped += 1
                continue
            page = extract_page(fetched.text, fetched.url or url, region=self.region)
            result.fetched += 1

            digest = hashlib.sha1(" ".join(page.text.split()).lower().encode("utf-8", "replace")).hexdigest()
            if digest in digests:
                result.duplicates += 1
                continue
            digests.add(digest)

            page.matched = target.match_terms(page.title, page.description, page.excerpt)
            page.relevance = target.score_text(page.title, page.description, page.excerpt)
            if depth > 0 and page.relevance < self.min_page_score:
                result.pruned += 1
                continue
            result.pages.append(page)

            if depth >= self.max_depth:
                continue
            for link_url, link_anchor in page.links[:120]:
                if not _crawlable(link_url):
                    continue
                if url_key(link_url) in visited:
                    continue
                link_score = self.score_link(target, link_url, link_anchor, depth + 1, seed_hosts)
                if link_score < self.min_link_score:
                    result.pruned += 1
                    continue
                heapq.heappush(heap, (-link_score, sequence, depth + 1, link_url, link_anchor))
                sequence += 1

        if result.fetched >= self.budget and result.stopped == "":
            result.stopped = "page budget reached"
        elif not result.stopped and not heap:
            result.stopped = "frontier exhausted"
        return result


def sitemap_seeds(
    fetcher: Callable[[str], FetchResult],
    seed_url: str,
    target: Target,
    *,
    limit: int = 12,
    max_files: int = 3,
    max_urls: int = 400,
) -> list[tuple[str, str]]:
    """Rank a site's own sitemap against the target — no search engine needed.

    robots.txt is checked for Sitemap: lines, then sitemap files (and one level
    of sitemap indexes) are read and every URL is scored with the same target
    terms the crawler uses. Only the best few are returned as seeds.
    """
    host = origin_of(seed_url)
    if not host:
        return []
    base = f"https://{host}"
    queue: list[str] = []
    robots = fetcher(base + "/robots.txt")
    if robots.ok:
        for line in robots.text.splitlines():
            if line.lower().startswith("sitemap:"):
                queue.append(line.split(":", 1)[1].strip())
    if not queue:
        queue = [base + "/sitemap.xml"]

    seen: set[str] = set()
    urls: list[str] = []
    while queue and len(seen) < max_files and len(urls) < max_urls:
        sitemap = queue.pop(0)
        if sitemap in seen:
            continue
        seen.add(sitemap)
        response = fetcher(sitemap)
        if not response.ok or not response.text:
            continue
        locations = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", response.text, re.I)
        for location in locations[: max_urls]:
            lowered = location.lower()
            if lowered.endswith((".xml", ".xml.gz")) or "sitemap" in lowered.rsplit("/", 1)[-1]:
                if len(queue) < max_files * 3:
                    queue.append(location)
            elif _crawlable(location):
                urls.append(location)

    scored = [
        (max(target.score_text(url), 0.1), url)
        for url in dict.fromkeys(urls)
    ]
    scored.sort(reverse=True)
    return [(url, "") for _, url in scored[:limit]]


SEARCH_HOSTS = (
    "google.com",
    "google.fr",
    "google.co.uk",
    "google.de",
    "bing.com",
    "duckduckgo.com",
    "yandex.com",
    "search.brave.com",
    "startpage.com",
    "mojeek.com",
    "ecosia.org",
    "qwant.com",
)


def _crawlable(url: str) -> bool:
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return False
    host = (parts.hostname or "").lower()
    # Never crawl a search engine's own result pages: that is how a crawl turns
    # into the burst Google blocks.
    if any(host == candidate or host.endswith("." + candidate) for candidate in SEARCH_HOSTS):
        return False
    if parts.path.lower().endswith(SKIP_SUFFIXES):
        return False
    return True


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
def page_finding(page: PageData, target: Target) -> Finding:
    data: dict[str, Any] = {"relevance score": round(page.relevance, 1)}
    if page.matched:
        data["matched terms"] = page.matched
    if page.emails:
        data["email addresses"] = sorted(page.emails)
    if page.phones:
        data["phone numbers"] = sorted(page.phones)
    if page.profiles:
        data["linked profiles"] = {platform: sorted(urls) for platform, urls in page.profiles.items()}
    if page.names:
        data["names"] = sorted(page.names)
    if page.organisations:
        data["organisations"] = sorted(page.organisations)
    if page.entities:
        data["structured data"] = [
            {
                key: value
                for key, value in entity.items()
                if key in ("@type", "name", "jobTitle", "worksFor", "address", "email", "telephone", "url")
            }
            for entity in page.entities[:5]
        ]
    if page.description:
        data["description"] = page.description
    images = [
        ImageRef(url=image, alt=page.title or page.url, kind="thumbnail", page_url=page.url)
        for image in page.images[:2]
    ]
    return Finding(
        source=f"Scraped · {origin_of(page.url) or 'page'}",
        category="Web",
        status="found",
        title=page.title or page.url,
        url=page.url,
        detail=page.excerpt,
        data=data,
        images=images,
        confidence="high" if page.relevance >= 3 else "medium",
    )
