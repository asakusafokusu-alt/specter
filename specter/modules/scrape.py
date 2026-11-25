"""Smart crawler integration: findings from scored, budgeted page collection."""

from __future__ import annotations

from typing import Any, Iterable

from ..config import Config
from ..crawl import CrawlResult, SmartCrawler, Target, origin_of, page_finding
from ..http import HttpClient
from ..models import ERROR, FOUND, INFO, Finding

DEFAULT_PAGES = 8
DEFAULT_DEPTH = 2
DEFAULT_MIN_SCORE = 1.6


def looks_like_url(value: str) -> bool:
    text = value.strip().lower()
    if text.startswith(("http://", "https://")):
        return True
    if " " in text or "/" in text.rstrip("/"):
        return False
    return "." in text and not text.endswith(".")


def crawl_findings(
    query: str,
    seeds: Iterable[tuple[str, str]],
    http: HttpClient,
    config: Config,
    *,
    terms: Iterable[str] | None = None,
    person: Any = None,
    budget: int = DEFAULT_PAGES,
    depth: int = DEFAULT_DEPTH,
    min_score: float = DEFAULT_MIN_SCORE,
    region: str | None = None,
    respect_robots: bool = True,
    fetcher: Any = None,
) -> list[Finding]:
    """Crawl the seeds best-first and turn what was found into findings."""
    target = Target.from_person(person) if person is not None else Target.from_query(query, terms)
    if person is None and not target.terms:
        return [
            Finding(
                source="Crawl",
                category="Web",
                status=INFO,
                detail="Nothing to score pages against: give a name, handle or address.",
            )
        ]
    crawler = SmartCrawler(
        http,
        budget=budget,
        max_depth=depth,
        min_link_score=min_score,
        region=region,
        respect_robots=respect_robots,
        fetcher=fetcher,
    )
    result = crawler.run(seeds, target)
    return result_to_findings(result, target)


def result_to_findings(result: CrawlResult, target: Target) -> list[Finding]:
    findings: list[Finding] = []
    pages = sorted(result.pages, key=lambda page: page.relevance, reverse=True)
    emails: set[str] = set()
    phones: set[str] = set()
    profiles: dict[str, set[str]] = {}
    names: set[str] = set()
    organisations: set[str] = set()
    for page in pages:
        emails |= page.emails
        phones |= page.phones
        names |= page.names
        organisations |= page.organisations
        for platform, urls in page.profiles.items():
            profiles.setdefault(platform, set()).update(urls)

    summary: dict[str, Any] = {
        "pages analysed": len(pages),
        "pages fetched": result.fetched,
        "page budget": result.budget,
        "links pruned as irrelevant": result.pruned,
        "duplicate pages skipped": result.duplicates,
        "pages skipped (blocked or not html)": result.skipped,
        "stopped because": result.stopped or "frontier empty",
    }
    if result.seeds:
        summary["seeds"] = result.seeds[:6]
    findings.append(
        Finding(
            source="Crawl",
            category="Web",
            status=INFO,
            title=(
                f"{len(pages)} page(s) analysed · {result.fetched} fetched of {result.budget}"
                if pages
                else "No page passed the relevance filter"
            ),
            detail=(
                f"{result.pruned} low-scoring link(s) were never requested, "
                f"{result.duplicates} near-duplicate page(s) skipped; stopped because "
                f"{result.stopped or 'the frontier ran out'}."
                if pages
                else "The crawl fetched pages but none looked related to the target; "
                "narrow the query or raise --min-score."
            ),
            data=summary,
        )
    )
    if not pages:
        return findings

    if emails or phones:
        contact_data: dict[str, Any] = {}
        if emails:
            contact_data["email addresses"] = sorted(emails)
        if phones:
            contact_data["phone numbers"] = sorted(phones)
        findings.append(
            Finding(
                source="Crawled pages · contacts",
                category="Contact",
                status=FOUND,
                title=f"{len(emails)} address(es) and {len(phones)} phone number(s) published",
                detail="Extracted from the crawled pages, not from search snippets.",
                data=contact_data,
            )
        )

    if profiles:
        findings.append(
            Finding(
                source="Crawled pages · profiles",
                category="Social",
                status=FOUND,
                title=f"{sum(len(urls) for urls in profiles.values())} linked profile(s) on {len(profiles)} platform(s)",
                detail="Profiles linked directly from the crawled pages.",
                data={"linked profiles": {platform: sorted(urls) for platform, urls in profiles.items()}},
            )
        )

    if names or organisations:
        identity_data: dict[str, Any] = {}
        if names:
            identity_data["names"] = sorted(names)
        if organisations:
            identity_data["organisations"] = sorted(organisations)
        findings.append(
            Finding(
                source="Crawled pages · structured identity",
                category="Identity",
                status=FOUND,
                title="Names and organisations from structured data",
                detail="schema.org Person/Organization blocks embedded in the pages.",
                data=identity_data,
            )
        )

    for page in pages:
        findings.append(page_finding(page, target))
    return findings


def page_summary_line(page: Any) -> str:
    return f"{page.title or page.url} · {origin_of(page.url)} · relevance {page.relevance:.1f}"
