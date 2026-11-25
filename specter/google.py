"""Keyless Google scraping that tries hard not to get itself blocked.

Google dislikes bursts far more than it dislikes single requests. This client
therefore:

* warms up one browser-like session (consent cookies and locale) before the
  first query;
* spaces requests with a random jitter and serialises them across threads, so a
  multi-source investigation cannot fire several Google queries at once;
* keeps a per-process query budget;
* detects a JavaScript wall, an automated-query block or a 429/403, and then
  puts Google into a cooldown so the rest of the run does not hammer it;
* falls back through Google's static endpoints (classic `gbv=1`, `udm=14`,
  mobile `/m`) with a different User-Agent each time.

Every outcome is explicit: callers get either results, an honest "blocked" with
the reason, or a "cooling down" note — never an empty list that looks like
"no results".
"""

from __future__ import annotations

import html
import os
import random
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit

from .models import BLOCKED, ERROR, FOUND, INFO, Finding

ANCHOR_RE = re.compile(r'<a[^>]+href="([^"]+)"[^>]*>(?:(?!</a>).)*?<h3[^>]*>(.*?)</h3>', re.S)
SNIPPET_RE = re.compile(
    r'<(?:div|span)[^>]+class="[^"]*(?:VwiC3b|IsZvec|\bst\b)[^"]*"[^>]*>(.*?)</(?:div|span)>',
    re.S,
)
TAG_RE = re.compile(r"<[^>]+>")
TERM_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9@._+-]{1,}")

WALL_MARKERS = (
    "enablejs",
    "automated queries",
    "unusual traffic",
    "before you continue",
    "sorry/index",
    "g-recaptcha",
    "our systems have detected",
)

USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
)

CONSENT_COOKIE = "CONSENT=YES+cb; SOCS=CAESHAgBEhJnd3NfMjAyMzA4MTAtMF9SQzIaAmVuIAEaBgiA_LyaBg"

# Shared by every scraper instance in the process: a block seen once must stop
# the next call too, wherever it comes from.
_LOCK = threading.Lock()
_STATE: dict[str, Any] = {
    "blocked_until": 0.0,
    "queries": 0,
    "last_request": 0.0,
    "warmed": False,
}


def reset_state() -> None:
    """Clear the cooldown/budget/warm-up state (used by tests)."""
    with _LOCK:
        _STATE.update({"blocked_until": 0.0, "queries": 0, "last_request": 0.0, "warmed": False})


def cooldown_remaining(clock: Callable[[], float] = time.monotonic) -> float:
    with _LOCK:
        return max(0.0, float(_STATE["blocked_until"]) - clock())


def queries_used() -> int:
    with _LOCK:
        return int(_STATE["queries"])


def clean_text(value: str) -> str:
    return " ".join(html.unescape(TAG_RE.sub(" ", value or "")).split())


def query_terms(query: str) -> list[str]:
    terms: list[str] = []
    for raw in TERM_RE.findall(query or ""):
        term = raw.lower().strip(".-")
        if len(term) < 2 or term in {"or", "and", "site", "filetype", "inurl", "intitle"}:
            continue
        if term not in terms:
            terms.append(term)
    return terms


def is_relevant(query: str, *texts: str | None) -> bool:
    """Discard results that share none (or almost none) of the query's terms."""
    terms = query_terms(query)
    if not terms:
        return True
    haystack = " ".join(text or "" for text in texts).lower()
    matched = sum(1 for term in terms if term in haystack)
    return matched >= max(1, (len(terms) + 1) // 2)


def google_url(href: str) -> str | None:
    """Resolve `/url?q=` wrappers and drop Google-owned destinations."""
    target = html.unescape(href or "").strip()
    if target.startswith("/url?"):
        params = parse_qs(urlsplit(target).query)
        for key in ("q", "url"):
            for value in params.get(key, []):
                if value.startswith(("http://", "https://")):
                    return value
        return None
    if not target.startswith(("http://", "https://")):
        return None
    host = (urlsplit(target).hostname or "").lower()
    if host.endswith(("google.com", "gstatic.com", "googleusercontent.com")):
        return None
    return target


def parse_results(text: str, query: str, limit: int = 10) -> list[Finding]:
    """Parse a static Google result page."""
    findings: list[Finding] = []
    seen: set[str] = set()
    for match in ANCHOR_RE.finditer(text or ""):
        url = google_url(match.group(1))
        if not url:
            continue
        key = _url_key(url)
        if key in seen:
            continue
        title = clean_text(match.group(2))
        snippet_match = SNIPPET_RE.search(text, match.end())
        snippet = clean_text(snippet_match.group(1))[:400] if snippet_match else ""
        if not is_relevant(query, title, snippet, url):
            continue
        seen.add(key)
        findings.append(
            Finding(
                source="Google",
                category="Web",
                status=FOUND,
                title=title or url,
                url=url,
                detail=snippet or None,
            )
        )
        if len(findings) >= limit:
            break
    return findings


def _url_key(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    host = (parts.hostname or "").lower().removeprefix("www.")
    return f"{host}{parts.path.rstrip('/') or '/'}"


def is_wall(text: str) -> bool:
    lowered = (text or "").lower()
    return any(marker in lowered for marker in WALL_MARKERS)


@dataclass
class GoogleOutcome:
    findings: list[Finding] = field(default_factory=list)
    status: str = INFO
    detail: str | None = None
    endpoint: str | None = None


class GoogleScraper:
    """Paced, budgeted, cooldown-aware keyless Google client."""

    ENDPOINTS = (
        ("classic", "https://www.google.com/search", {"gbv": "1", "pws": "0", "filter": "0"}),
        ("web", "https://www.google.com/search", {"udm": "14"}),
        ("mobile", "https://www.google.com/m", {}),
    )

    def __init__(
        self,
        http: Any,
        *,
        limit: int = 10,
        min_interval: float | None = None,
        cooldown: float | None = None,
        max_queries: int | None = None,
        warmup: bool = True,
        sleeper: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        rng: random.Random | None = None,
        get: Callable[..., Any] | None = None,
    ) -> None:
        self.limit = max(1, limit)
        self.min_interval = float(
            min_interval if min_interval is not None else os.environ.get("SPECTER_GOOGLE_INTERVAL", "1.6")
        )
        self.cooldown = float(
            cooldown if cooldown is not None else os.environ.get("SPECTER_GOOGLE_COOLDOWN", "600")
        )
        self.max_queries = int(
            max_queries if max_queries is not None else os.environ.get("SPECTER_GOOGLE_QUERIES", "12")
        )
        self.warmup = warmup
        self._sleep = sleeper
        self._clock = clock
        self._rng = rng or random.Random()
        self._get = get or self._http_get(http)

    @staticmethod
    def _http_get(http: Any) -> Callable[..., Any]:
        def call(url: str, params: dict[str, str] | None, headers: dict[str, str]) -> Any:
            return http.get(url, params=params, headers=headers, timeout=20)

        return call

    # -- politeness -------------------------------------------------------
    def _headers(self) -> dict[str, str]:
        with _LOCK:
            index = int(_STATE["queries"]) % len(USER_AGENTS)
        return {
            "User-Agent": USER_AGENTS[index],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Cookie": CONSENT_COOKIE,
        }

    def _pace(self) -> None:
        with _LOCK:
            now = self._clock()
            wait = self.min_interval - (now - float(_STATE["last_request"]))
            if wait > 0:
                delay = wait + self._rng.uniform(0.0, 0.7)
            else:
                delay = self._rng.uniform(0.0, 0.25)
            _STATE["last_request"] = now + max(0.0, delay)
        if delay > 0:
            self._sleep(delay)

    def _warm_up(self) -> None:
        with _LOCK:
            if _STATE["warmed"]:
                return
            _STATE["warmed"] = True
        try:
            self._get("https://www.google.com/ncr", None, self._headers())
        except Exception:  # noqa: BLE001 - a failed warm-up must not stop the query
            return

    # -- query ------------------------------------------------------------
    def search(self, query: str) -> GoogleOutcome:
        now = self._clock()
        with _LOCK:
            blocked_until = float(_STATE["blocked_until"])
            used = int(_STATE["queries"])
        if now < blocked_until:
            minutes = max(1, int(round((blocked_until - now) / 60)))
            return GoogleOutcome(
                [],
                BLOCKED,
                f"Google is cooling down for about {minutes} more minute(s) after a block. "
                "This query is skipped so the tool does not get itself blocked; set "
                "GOOGLE_API_KEY + GOOGLE_CSE_ID (or SPECTER_GOOGLE_COOLDOWN=0) to query "
                "Google another way.",
            )
        if used >= self.max_queries:
            return GoogleOutcome(
                [],
                INFO,
                f"Google query budget for this run ({self.max_queries}) is spent, so this "
                "query is skipped instead of risking a block.",
            )

        with _LOCK:
            _STATE["queries"] = used + 1
            attempt_seed = used
        if self.warmup:
            self._warm_up()

        blocked_notes: list[str] = []
        for name, url, base_params in self.ENDPOINTS:
            self._pace()
            params = {
                **base_params,
                "q": query,
                "hl": "en",
                "num": str(min(20, max(10, self.limit))),
            }
            headers = dict(self._headers())
            headers["User-Agent"] = USER_AGENTS[(attempt_seed + len(blocked_notes)) % len(USER_AGENTS)]
            try:
                response = self._get(url, params, headers)
            except Exception as exc:  # noqa: BLE001 - network errors are per-endpoint
                blocked_notes.append(f"{name}: {type(exc).__name__}: {exc}")
                continue

            status = getattr(response, "status", None)
            text = getattr(response, "text", "") or ""
            ok = bool(getattr(response, "ok", False))
            if status in (429, 403) or (not ok and getattr(response, "blocked", False)):
                blocked_notes.append(f"{name}: HTTP {status}")
                continue
            if not ok:
                continue
            if is_wall(text):
                blocked_notes.append(f"{name}: JavaScript or automated-query wall")
                continue
            findings = parse_results(text, query, self.limit)
            if findings:
                for finding in findings:
                    finding.data.setdefault("via", f"Google ({name})")
                return GoogleOutcome(findings, FOUND, endpoint=name)

        if blocked_notes:
            with _LOCK:
                _STATE["blocked_until"] = self._clock() + self.cooldown
            return GoogleOutcome(
                [],
                BLOCKED,
                "Google refused every keyless endpoint ("
                + "; ".join(blocked_notes)
                + f") and is now cooling down for {int(self.cooldown)}s. Add GOOGLE_API_KEY "
                "+ GOOGLE_CSE_ID (100 free queries/day) or a SEARXNG_URL for reliable "
                "Google results.",
            )
        return GoogleOutcome(
            [],
            INFO,
            "Google answered but returned no parseable results for this query.",
        )


def google_findings(query: str, http: Any, *, limit: int = 10) -> list[Finding]:
    """Convenience wrapper returning findings (notes included)."""
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
