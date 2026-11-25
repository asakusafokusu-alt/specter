"""Multi-identifier person profiles.

Feed it whatever identifiers you have — name, aliases, emails, phones,
usernames, domains, IPs, location, employer — and it runs the matching modules
concurrently, then correlates the results instead of just listing them:

* which identifiers are genuinely linked (and by what fact),
* which details corroborate each other,
* what contradicts,
* and what is still missing.
"""

from __future__ import annotations

import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from .config import Config
from .correlate import Assessment, Evidence, assess
from .http import HttpClient
from .models import ERROR, FOUND, INFO, Report, Finding
from .modules.domain import investigate_domain, normalize_domain
from .modules.email import investigate_email, validate_email
from .modules.github import investigate_github
from .modules.ip import investigate_ip
from .modules.phone import investigate_phone
from .modules.search import search_all
from .modules.username import USERNAME_RE, investigate_username, validate_username

SPLIT_RE = re.compile(r"[,;\n]+")

# Derived handles are only checked on the platforms that publish a name, a site
# or an address — a full 57-platform sweep for a guess is not worth the requests.
DERIVED_PLATFORMS = (
    "GitHub",
    "GitLab",
    "Dev.to",
    "Bluesky",
    "Keybase",
    "Hacker News",
    "Stack Overflow",
)


def split_values(values: Iterable[str] | str | None) -> list[str]:
    """Accept repeated flags or comma-separated strings, in input order."""
    if values is None:
        return []
    if isinstance(values, str):
        values = [values]
    items: list[str] = []
    for value in values:
        for part in SPLIT_RE.split(str(value)):
            part = part.strip()
            if part and part.lower() not in {item.lower() for item in items}:
                items.append(part)
    return items


@dataclass
class PersonInput:
    first_name: str = ""
    last_name: str = ""
    name: str = ""
    aliases: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    location: str = ""
    employer: str = ""
    birth_year: str = ""

    @property
    def full_name(self) -> str:
        explicit = " ".join(self.name.split())
        if explicit:
            return explicit
        return " ".join(part for part in (self.first_name, self.last_name) if part).strip()

    @property
    def emails_lower(self) -> set[str]:
        return {email.lower() for email in self.emails}

    def is_empty(self) -> bool:
        return not any(
            (
                self.full_name,
                self.aliases,
                self.emails,
                self.phones,
                self.usernames,
                self.domains,
                self.ips,
            )
        )

    def summary(self) -> dict[str, Any]:
        data: dict[str, Any] = {}
        if self.full_name:
            data["name"] = self.full_name
        if self.aliases:
            data["aliases"] = self.aliases
        if self.emails:
            data["emails"] = self.emails
        if self.phones:
            data["phones"] = self.phones
        if self.usernames:
            data["usernames"] = self.usernames
        if self.domains:
            data["domains"] = self.domains
        if self.ips:
            data["ips"] = self.ips
        if self.location:
            data["location"] = self.location
        if self.employer:
            data["employer"] = self.employer
        if self.birth_year:
            data["birth year"] = self.birth_year
        return data


def normalize_person(person: PersonInput) -> tuple[PersonInput, list[str]]:
    """Validate each identifier, dropping (and explaining) the unusable ones."""
    notes: list[str] = []
    cleaned = PersonInput(
        first_name=person.first_name.strip(),
        last_name=person.last_name.strip(),
        name=" ".join(person.name.split()),
        aliases=split_values(person.aliases),
        location=person.location.strip(),
        employer=person.employer.strip(),
        birth_year=person.birth_year.strip(),
    )
    for raw in split_values(person.emails):
        try:
            cleaned.emails.append(validate_email(raw))
        except ValueError as exc:
            notes.append(f"Ignored email '{raw}': {exc}")
    for raw in split_values(person.usernames):
        try:
            cleaned.usernames.append(validate_username(raw))
        except ValueError as exc:
            notes.append(f"Ignored username '{raw}': {exc}")
    for raw in split_values(person.domains):
        try:
            cleaned.domains.append(normalize_domain(raw))
        except ValueError as exc:
            notes.append(f"Ignored domain '{raw}': {exc}")
    for raw in split_values(person.ips):
        try:
            cleaned.ips.append(str(ipaddress.ip_address(raw)))
        except ValueError:
            notes.append(f"Ignored IP '{raw}': not a valid address")
    for raw in split_values(person.phones):
        cleaned.phones.append(raw)
    return cleaned, notes


def derived_usernames(person: PersonInput) -> list[str]:
    """Handles implied by the email local part, used only as extra leads."""
    existing = {username.lower() for username in person.usernames}
    derived: list[str] = []
    for email in person.emails:
        local = email.split("@")[0].split("+")[0]
        for candidate in (local, re.sub(r"[._-]", "", local)):
            if len(candidate) < 4 or not USERNAME_RE.match(candidate):
                continue
            if candidate.lower() in existing or candidate in derived:
                continue
            derived.append(candidate)
    return derived[:2]


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------
def _tasks(
    person: PersonInput,
    http: HttpClient,
    config: Config,
    *,
    sources: Iterable[str] | None,
    limit: int,
    region: str | None,
    subdomains: bool,
    include_images: bool,
) -> list[tuple[str, str, str, bool, Callable[[], list[Finding]]]]:
    tasks: list[tuple[str, str, str, bool, Callable[[], list[Finding]]]] = []

    if person.full_name:
        tasks.append(
            (
                "name",
                person.full_name,
                f'Name search · "{person.full_name}"',
                False,
                lambda: search_all(
                    f'"{person.full_name}"',
                    http,
                    config,
                    sources=sources or ("web", "news", "wikipedia", "wikidata", "sec"),
                    limit=limit,
                    kind="name",
                    include_images=include_images,
                ),
            )
        )
    for email in person.emails:
        tasks.append(
            (
                "email",
                email,
                f"Email · {email}",
                False,
                lambda email=email: investigate_email(
                    email, http, config, include_breaches=True, include_probes=False
                ),
            )
        )
    for username in person.usernames:
        tasks.append(
            (
                "username",
                username,
                f"Username · {username}",
                False,
                lambda username=username: investigate_username(username, http, config)
                + investigate_github(username, http, config, repo_limit=30),
            )
        )
    for phone in person.phones:
        tasks.append(
            (
                "phone",
                phone,
                f"Phone · {phone}",
                False,
                lambda phone=phone: investigate_phone(phone, http, config, region=region),
            )
        )
    for domain in person.domains:
        tasks.append(
            (
                "domain",
                domain,
                f"Domain · {domain}",
                False,
                lambda domain=domain: investigate_domain(
                    domain, http, config, include_subdomains=subdomains
                ),
            )
        )
    for ip in person.ips:
        tasks.append(
            (
                "ip",
                ip,
                f"IP · {ip}",
                False,
                lambda ip=ip: investigate_ip(ip, http, config),
            )
        )
    for candidate in derived_usernames(person):
        tasks.append(
            (
                "username",
                candidate,
                f"Username · {candidate} (derived from email local part)",
                True,
                lambda candidate=candidate: investigate_username(
                    candidate, http, config, only=list(DERIVED_PLATFORMS)
                ),
            )
        )
    return tasks


def _run_tasks(
    tasks: list[tuple[str, str, str, bool, Callable[[], list[Finding]]]]
) -> list[Evidence]:
    if not tasks:
        return []
    with ThreadPoolExecutor(max_workers=min(6, len(tasks))) as pool:
        futures = [(task, pool.submit(task[4])) for task in tasks]
    evidence: list[Evidence] = []
    for (kind, value, label, derived, _), future in futures:
        try:
            findings = future.result()
        except Exception as exc:  # noqa: BLE001 - one identifier must not stop the profile
            findings = [
                Finding(
                    source="Person profile",
                    category="Assessment",
                    status=ERROR,
                    detail=f"{label} failed: {type(exc).__name__}: {exc}",
                )
            ]
        evidence.append(
            Evidence(label=label, kind=kind, value=value, findings=findings, derived=derived)
        )
    return evidence


METHOD = (
    "Links are scored by how hard they are to fake: a published email or a website "
    "matching a supplied domain weighs more than a shared name or city, and one page "
    "can never produce a strong verdict on its own — independent sources must agree. "
    "Scores are indicative, not proof: public data goes stale, and a shared device, "
    "employer or namesake can produce a false link. The per-identifier entries below "
    "are the raw evidence behind every statement above."
)


def assessment_findings(assessment: Assessment, person: PersonInput) -> list[Finding]:
    """The report's conclusion section, as ordinary findings."""
    findings: list[Finding] = []
    band = assessment.band
    findings.append(
        Finding(
            source="Identity assessment",
            category="Assessment",
            status=INFO,
            title=f"{band.title()} match · {assessment.score}/100",
            detail=assessment.verdict,
            confidence="high" if band == "strong" else "medium" if band == "moderate" else "low",
            data={
                "band": band,
                "score": f"{assessment.score}/100",
                "identifiers supplied": person.summary(),
                "links": len(assessment.links),
                "sources": len(assessment.sources),
            },
        )
    )
    if assessment.links:
        findings.append(
            Finding(
                source="Identity links",
                category="Assessment",
                status=INFO,
                title=f"{len(assessment.links)} link(s) between the supplied identifiers",
                detail=(
                    "Each row is a public fact that ties two identifiers together. "
                    "Higher weight means harder to fake."
                ),
                data={
                    "links": [
                        {
                            "from": link.left,
                            "to": link.right,
                            "basis": link.basis,
                            "weight": link.weight,
                            "source": link.source,
                            "url": link.url,
                        }
                        for link in assessment.links
                    ]
                },
            )
        )
    if assessment.consistent:
        findings.append(
            Finding(
                source="Corroborated details",
                category="Assessment",
                status=INFO,
                title=f"{len(assessment.consistent)} detail(s) agree across sources",
                data={"consistent": assessment.consistent},
            )
        )
    if assessment.conflicts:
        findings.append(
            Finding(
                source="Contradictions",
                category="Assessment",
                status=INFO,
                title=f"{len(assessment.conflicts)} contradiction(s) to resolve",
                detail="Resolve these before attributing any account to the person.",
                data={"conflicts": assessment.conflicts},
            )
        )
    if assessment.gaps:
        findings.append(
            Finding(
                source="Open questions",
                category="Assessment",
                status=INFO,
                title=f"{len(assessment.gaps)} gap(s) in the picture",
                data={"gaps": assessment.gaps},
            )
        )
    findings.append(
        Finding(
            source="Method and limits",
            category="Assessment",
            status=INFO,
            detail=METHOD,
            data={
                "coverage per identifier type": assessment.coverage,
                "sources queried": assessment.sources,
            },
        )
    )
    return findings


def run_person_profile(
    person: PersonInput,
    http: HttpClient,
    config: Config,
    *,
    sources: Iterable[str] | None = None,
    limit: int = 8,
    region: str | None = None,
    subdomains: bool = False,
    include_images: bool = True,
) -> Report:
    """Run every identifier concurrently, correlate, and return one report."""
    cleaned, notes = normalize_person(person)
    if cleaned.is_empty():
        raise ValueError(
            "Supply at least one identifier: name, email, phone, username, domain or IP."
        )

    report = Report(
        target=cleaned.full_name or " / ".join(
            [*cleaned.usernames, *cleaned.emails, *cleaned.phones, *cleaned.domains, *cleaned.ips]
        ),
        target_type="person profile",
        options={
            "identifiers": cleaned.summary(),
            "sources": list(sources) if sources else "default",
            "limit": limit,
            "region": region,
        },
    )
    report.notes.extend(notes)

    tasks = _tasks(
        cleaned,
        http,
        config,
        sources=sources,
        limit=limit,
        region=region,
        subdomains=subdomains,
        include_images=include_images,
    )
    evidence = _run_tasks(tasks)
    assessment = assess(cleaned, evidence)

    report.identity = assessment.to_dict()
    report.extend(assessment_findings(assessment, cleaned))
    for item in evidence:
        report.extend(item.findings)

    if not any(item.derived for item in evidence):
        pass
    else:
        report.notes.append(
            "Handles derived from the email local part are labelled as such; they are "
            "leads, not confirmed accounts."
        )
    report.notes.append(
        "A person profile is an inference engine, not proof of identity. Every link "
        "above cites the public record that produced it."
    )
    return report
