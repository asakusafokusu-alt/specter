"""Identity correlation: turn per-identifier evidence into one assessment.

The person profile runs the normal modules for every supplied identifier, then
this module answers the question that matters: *do these identifiers actually
describe the same person, and on what evidence?* Each rule below is a fact that
links two things (an identifier and an attribute somebody published), with a
weight reflecting how hard that link is to fake. The weights add up to a score,
and contradictions are reported separately rather than being averaged away.

Nothing here touches the network, so every rule is unit-testable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urlsplit

from .models import FOUND, Finding

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
NAME_STOPWORDS = {"mr", "mrs", "ms", "dr", "prof", "sir", "jr", "sr", "the", "de", "da", "van", "von"}
SEARCH_CATEGORIES = {"Web", "News", "Wikipedia", "Wikidata", "Forums", "Archive", "Filings"}

BANDS = ((60, "strong"), (30, "moderate"), (12, "weak"), (0, "inconclusive"))
# A single page can be internally consistent and still be wrong (a shared
# employer page, a namesake). It therefore cannot on its own reach "strong".
MAX_PER_SOURCE = 55


@dataclass
class Evidence:
    """Everything one supplied identifier produced."""

    label: str
    kind: str
    value: str
    findings: list[Finding] = field(default_factory=list)
    derived: bool = False

    @property
    def found(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.status == FOUND]


@dataclass
class Link:
    left: str
    right: str
    basis: str
    weight: int
    url: str | None = None
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "from": self.left,
            "to": self.right,
            "basis": self.basis,
            "weight": self.weight,
        }
        if self.source:
            out["source"] = self.source
        if self.url:
            out["url"] = self.url
        return out


@dataclass
class Assessment:
    score: int
    band: str
    verdict: str
    links: list[Link]
    conflicts: list[str]
    consistent: list[str]
    gaps: list[str]
    coverage: dict[str, int]
    sources: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "band": self.band,
            "verdict": self.verdict,
            "links": [link.to_dict() for link in self.links],
            "conflicts": self.conflicts,
            "consistent": self.consistent,
            "gaps": self.gaps,
            "coverage": self.coverage,
            "sources": self.sources,
        }


# ---------------------------------------------------------------------------
# Text helpers
# ---------------------------------------------------------------------------
def norm_text(value: Any) -> str:
    text = str(value or "").lower()
    text = re.sub(r"[^a-z0-9@._+-]+", " ", text)
    return " ".join(text.split())


def tokens(value: Any) -> set[str]:
    return {
        token
        for token in re.split(r"[^a-z0-9]+", str(value or "").lower())
        if len(token) >= 2 and token not in NAME_STOPWORDS
    }


def name_similarity(left: str, right: str) -> float:
    """Token overlap, penalising extra tokens on either side."""
    a, b = tokens(left), tokens(right)
    if not a or not b:
        return 0.0
    return len(a & b) / max(len(a), len(b))


def location_match(left: str, right: str) -> bool:
    a, b = tokens(left), tokens(right)
    if not a or not b:
        return False
    if a & b:
        return True
    la, lb = norm_text(left), norm_text(right)
    return bool(la and lb and (la in lb or lb in la))


def host_of(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if "://" not in text:
        text = "https://" + text
    try:
        host = (urlsplit(text).hostname or "").lower()
    except ValueError:
        return ""
    return host[4:] if host.startswith("www.") else host


def emails_in(finding: Finding) -> set[str]:
    """Every address visible in a finding's own evidence."""
    found: set[str] = set()
    blobs: list[str] = [finding.title or "", finding.detail or "", finding.url or ""]
    for value in (finding.data or {}).values():
        if isinstance(value, str):
            blobs.append(value)
        elif isinstance(value, (list, tuple)):
            blobs.extend(str(item) for item in value if isinstance(item, (str, int)))
        elif isinstance(value, dict):
            blobs.extend(str(item) for item in value.values() if isinstance(item, str))
    for blob in blobs:
        for match in EMAIL_RE.findall(blob):
            found.add(match.lower())
    return found


def _value(data: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = data.get(key)
        if isinstance(value, (list, tuple)):
            value = next((item for item in value if item), None)
        if value not in (None, "", {}, []):
            return str(value).strip()
    return ""


def profile_of(finding: Finding) -> dict[str, Any]:
    """The person-facing attributes a finding publishes about its subject."""
    data = finding.data or {}
    name = _value(data, "name", "full name", "display name", "real name")
    if not name:
        first = _value(data, "first name")
        last = _value(data, "last name")
        name = " ".join(part for part in (first, last) if part)
    location = _value(data, "location", "current location")
    if not location:
        location = ", ".join(
            part for part in (_value(data, "city"), _value(data, "country")) if part
        )
    return {
        "name": name,
        "location": location,
        "company": _value(data, "company", "organization", "employer", "organisation"),
        "website": _value(data, "website", "blog", "homepage", "url"),
        "username": _value(data, "login", "username", "handle", "user", "preferred username", "id"),
        "emails": emails_in(finding),
    }


# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------
def _profile_links(evidence: Evidence, finding: Finding, person: Any) -> list[Link]:
    links: list[Link] = []
    profile = profile_of(finding)
    url = finding.url
    source = finding.source
    label = evidence.label

    if person.full_name and profile["name"]:
        similarity = name_similarity(person.full_name, profile["name"])
        if similarity >= 0.99:
            links.append(
                Link(
                    label,
                    f'name "{profile["name"]}"',
                    f"{source} states this name in full; it matches the supplied name exactly",
                    22,
                    url,
                    source,
                )
            )
        elif similarity >= 0.6:
            links.append(
                Link(
                    label,
                    f'name "{profile["name"]}"',
                    f"{source} publishes a name that partially matches the supplied name",
                    14,
                    url,
                    source,
                )
            )

    own_value = evidence.value.strip().lower()
    for email in sorted(profile["emails"]):
        # A validation or breach record for this very address names it by
        # definition; that is not an independent link.
        if email == own_value:
            continue
        if email in person.emails_lower:
            penalty = 0 if "@" not in (url or "") else 2
            weight = 42 if "commit" in source.lower() else 36
            links.append(
                Link(
                    label,
                    email,
                    f"{source} publishes this exact address",
                    max(10, weight - penalty),
                    url,
                    source,
                )
            )

    website = profile["website"]
    if website and person.domains:
        host = host_of(website)
        for domain in person.domains:
            if host and (host == domain or host.endswith("." + domain)):
                links.append(
                    Link(label, domain, f"{source} links to {host}", 30, url, source)
                )

    if person.employer and profile["company"]:
        if name_similarity(person.employer, profile["company"]) >= 0.5:
            links.append(
                Link(
                    label,
                    f'employer "{profile["company"]}"',
                    f"{source} lists an employer matching the supplied one",
                    12,
                    url,
                    source,
                )
            )

    if person.location and profile["location"]:
        if location_match(person.location, profile["location"]):
            links.append(
                Link(
                    label,
                    f'location "{profile["location"]}"',
                    f"{source} places the subject in the supplied location",
                    12,
                    url,
                    source,
                )
            )

    # An alias appearing as a display name is weak on its own, but real.
    for alias in person.aliases:
        if profile["name"] and name_similarity(alias, profile["name"]) >= 0.99:
            links.append(
                Link(
                    label,
                    f'alias "{alias}"',
                    f"{source} uses the supplied alias verbatim",
                    10,
                    url,
                    source,
                )
            )
    return links


def _mention_links(
    evidence: Evidence, person: Any, covered: set[tuple[int, str]]
) -> list[Link]:
    """A supplied handle showing up inside another identifier's evidence."""
    links: list[Link] = []
    handles = [
        (value, label)
        for label, values in (
            ("username", person.usernames),
            ("email", person.emails),
        )
        for value in values
    ]
    for finding in evidence.found:
        # Search hits are already visible as findings; they mention names and
        # handles incidentally and must not pump up the identity score.
        if finding.category in SEARCH_CATEGORIES:
            continue
        haystack = " ".join(
            [
                finding.url or "",
                finding.title or "",
                finding.detail or "",
                " ".join(str(value) for value in (finding.data or {}).values() if isinstance(value, str)),
            ]
        )
        # Strip addresses first: a handle is not "found" inside user@domain.
        haystack = EMAIL_RE.sub(" ", haystack).lower()
        if not haystack.strip():
            continue
        for value, kind in handles:
            needle = value.lower()
            if len(needle) < 4:
                continue
            if not re.search(rf"(?<![a-z0-9]){re.escape(needle)}(?![a-z0-9])", haystack):
                continue
            if evidence.value.lower() == needle:
                continue
            # An address's own local part matching a handle is not evidence.
            if needle in evidence.value.lower():
                continue
            if (id(finding), value) in covered:
                continue
            if kind == "username":
                basis = f'the handle "{value}" appears as a word in this {finding.source} record'
                weight = 16
            else:
                basis = f"this {finding.source} record contains the supplied address"
                weight = 20
            links.append(
                Link(evidence.label, value, basis, weight, finding.url, finding.source)
            )
    return links


ORIGIN_HINTS = (
    "GitHub",
    "GitLab",
    "Gravatar",
    "XposedOrNot",
    "Wikipedia",
    "Wikidata",
    "Bing",
    "Google",
    "DuckDuckGo",
    "Hacker News",
    "Stack Overflow",
    "Keybase",
    "Bluesky",
    "Mastodon",
    "Dev.to",
    "SEC EDGAR",
    "Internet Archive",
)


def origin_of(source: str) -> str:
    """Coarse origin for a finding source so one service cannot count twice.

    The username sweep, the GitHub deep dive and the commit-email pass all
    report as separate sources; they are still one service, and counting each
    as independent evidence would inflate the score.
    """
    base = re.split(r"\s*[\u00b7\u2192]\s*", str(source or "")).pop(0).strip()
    lowered = base.lower()
    for hint in ORIGIN_HINTS:
        if lowered.startswith(hint.lower()):
            return hint
    return base or "unattributed"


def _dedupe(links: Iterable[Link]) -> list[Link]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[Link] = []
    for link in links:
        key = (link.left, link.right, link.basis)
        if key in seen:
            continue
        seen.add(key)
        unique.append(link)
    unique.sort(key=lambda item: item.weight, reverse=True)
    return unique


def _band(score: int) -> str:
    for threshold, label in BANDS:
        if score >= threshold:
            return label
    return "inconclusive"


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" + ("" if count == 1 else "s")


def _verdict(
    person: Any,
    band: str,
    links: list[Link],
    link_sources: list[str],
    conflicts: list[str],
    found_total: int = 0,
) -> str:
    subject = person.full_name or "the supplied identifiers"
    hard = [link for link in links if link.weight >= 30]
    scope = f"{_plural(len(links), 'link')} from {_plural(len(link_sources), 'independent source')}"
    caveat = (
        f" {_plural(len(conflicts), 'contradiction')} below need review before attributing anything."
        if conflicts
        else ""
    )
    if band == "strong":
        return (
            f"Strong support that {subject} is one person: {scope}, "
            f"{_plural(len(hard), 'hard link')} (a published address, website or commit "
            f"record) plus supporting details." + caveat
        )
    if band == "moderate":
        return (
            f"Probable match for {subject}: {scope}, but only "
            f"{_plural(len(hard), 'hard link')}. Treat the profile as a working hypothesis "
            f"and confirm one more independent hard link before acting." + caveat
        )
    if band == "weak":
        return (
            f"Weak support for {subject}: {scope} and no published address or website "
            f"to anchor it. This is a lead, not an identification." + caveat
        )
    supplied = sum(
        1
        for value in (
            person.full_name,
            person.emails,
            person.usernames,
            person.phones,
            person.domains,
            person.ips,
        )
        if value
    )
    if supplied <= 1:
        return (
            f"Only one identifier was supplied, so there is nothing to correlate: "
            f"{found_total} public record(s) came back for {subject}, but a single "
            f"identifier cannot confirm an identity. Add an email, username or phone "
            f"to test whether the records describe the same person." + caveat
        )
    return (
        f"The supplied identifiers could not be tied together for {subject}. "
        "Either the person has little public footprint under these values, or the "
        "values belong to different people — add a hard identifier (email, username "
        "or domain) to test it." + caveat
    )


def assess(person: Any, evidence: list[Evidence]) -> Assessment:
    """Correlate every piece of evidence and return a scored assessment."""
    links: list[Link] = []
    coverage: dict[str, int] = {}
    sources: list[str] = []

    covered: set[tuple[int, str]] = set()
    for item in evidence:
        coverage[item.kind] = coverage.get(item.kind, 0) + len(item.found)
        for finding in item.found:
            if finding.source not in sources:
                sources.append(finding.source)
            direct = _profile_links(item, finding, person)
            links.extend(direct)
            covered.update((id(finding), link.right) for link in direct)
        links.extend(_mention_links(item, person, covered))

    links = _dedupe(links)

    # One profile self-publishing its own name, site and address is one source.
    # Extra links from the same source are halved so a single page cannot alone
    # produce a "strong" conclusion.
    by_source: dict[str, list[Link]] = {}
    for link in links:
        by_source.setdefault(origin_of(link.source), []).append(link)
    score_value = 0.0
    for items in by_source.values():
        ordered = sorted(items, key=lambda item: item.weight, reverse=True)
        subtotal = ordered[0].weight + 0.4 * sum(link.weight for link in ordered[1:])
        score_value += min(MAX_PER_SOURCE, subtotal)
    score = min(100, round(score_value))
    band = _band(score)
    link_sources = sorted(by_source)

    conflicts = _conflicts(person, evidence)
    consistent = _consistent(person, evidence)
    gaps = _gaps(person, coverage, links)
    found_total = sum(len(item.found) for item in evidence)
    verdict = _verdict(person, band, links, link_sources, conflicts, found_total)

    return Assessment(
        score=score,
        band=band,
        verdict=verdict,
        links=links,
        conflicts=conflicts,
        consistent=consistent,
        gaps=gaps,
        coverage=coverage,
        sources=sorted(sources),
    )


def _conflicts(person: Any, evidence: list[Evidence]) -> list[str]:
    conflicts: list[str] = []
    names: list[tuple[str, str]] = []
    for item in evidence:
        for finding in item.found:
            published = profile_of(finding)["name"]
            if not published or len(tokens(published)) < 2:
                continue
            if all(name_similarity(published, existing) < 0.99 for existing, _ in names):
                names.append((published, finding.source))
    for index, (left, left_source) in enumerate(names):
        for right, right_source in names[index + 1 :]:
            if name_similarity(left, right) < 0.5:
                conflicts.append(
                    f'Two different names are published for these identifiers: "{left}" '
                    f"({left_source}) vs \"{right}\" ({right_source}). One may be an "
                    "employer, a namesake or a shared device."
                )
                break
        if len(conflicts) >= 3:
            break

    if person.location:
        for item in evidence:
            for finding in item.found:
                published = profile_of(finding)["location"]
                if published and not location_match(person.location, published):
                    conflicts.append(
                        f'The supplied location "{person.location}" does not match '
                        f'"{published}" published by {finding.source}. Confirm before '
                        "treating the location as corroborated."
                    )
                    break
            if len(conflicts) >= 3:
                break
    return conflicts[:3]


def _consistent(person: Any, evidence: list[Evidence]) -> list[str]:
    consistent: list[str] = []
    for item in evidence:
        for finding in item.found:
            profile = profile_of(finding)
            if person.full_name and profile["name"] and name_similarity(person.full_name, profile["name"]) >= 0.6:
                consistent.append(
                    f'Name "{profile["name"]}" appears on {finding.source} ({item.label}).'
                )
            if person.employer and profile["company"] and name_similarity(person.employer, profile["company"]) >= 0.5:
                consistent.append(
                    f'Employer "{profile["company"]}" appears on {finding.source} ({item.label}).'
                )
            if person.location and profile["location"] and location_match(person.location, profile["location"]):
                consistent.append(
                    f'Location "{profile["location"]}" appears on {finding.source} ({item.label}).'
                )
    unique: list[str] = []
    for entry in consistent:
        if entry not in unique:
            unique.append(entry)
    return unique[:8]


def _gaps(person: Any, coverage: dict[str, int], links: list[Link]) -> list[str]:
    gaps: list[str] = []
    supplied = {
        "name": bool(person.full_name),
        "email": bool(person.emails),
        "username": bool(person.usernames),
        "phone": bool(person.phones),
        "domain": bool(person.domains),
        "ip": bool(person.ips),
    }
    for kind, present in supplied.items():
        if present and coverage.get(kind, 0) == 0:
            gaps.append(f"No public result was returned for the supplied {kind}; it adds nothing yet.")
    if not supplied["email"]:
        gaps.append("Add an email address: a published address is the strongest keyless link.")
    if not supplied["username"]:
        gaps.append("Add a username: platform profiles expose names, sites and commit emails.")
    if not supplied["name"]:
        gaps.append("Add the person's name to test profile names, news and public records.")
    if links and max(link.weight for link in links) < 30:
        gaps.append(
            "Every link found is circumstantial (a name or place match). Do not attribute "
            "the profile on this alone."
        )
    if not links:
        gaps.append(
            "No link was found. Try a second username, the address used for sign-ups, or "
            "the domain of the person's employer."
        )
    return gaps[:8]
