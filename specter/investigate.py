"""Target detection and the multi-module investigation pipeline."""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable

from .config import Config
from .http import HttpClient
from .models import Report
from .modules.domain import investigate_domain, normalize_domain
from .modules.email import EMAIL_RE, investigate_email, validate_email
from .modules.github import investigate_github
from .modules.ip import investigate_ip
from .modules.phone import investigate_phone
from .modules.search import search_all, search_web
from .modules.username import investigate_username, validate_username

DISPLAY_TYPE = {
    "username": "username",
    "email": "email address",
    "phone": "phone number",
    "ip": "IP address",
    "domain": "domain",
    "name": "person name",
}

KIND_BY_TYPE = {
    "username": "username",
    "email": "email",
    "phone": "phone",
    "ip": "ip",
    "domain": "domain",
    "name": "name",
}


def _looks_like_domain(value: str) -> bool:
    if " " in value or "@" in value or value.startswith(("+", ".")):
        return False
    try:
        normalized = normalize_domain(value)
    except ValueError:
        return False
    return "." in normalized


def detect_target(value: str) -> str:
    """Guess whether a target is an email, phone, IP, domain, name or username."""
    target = value.strip()
    if not target:
        raise ValueError("Target cannot be empty.")

    if EMAIL_RE.match(target):
        return "email"

    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        pass

    if _looks_like_domain(target):
        return "domain"

    digits = sum(char.isdigit() for char in target)
    if digits >= 7 and re.fullmatch(r"[+()\d][\d\s().-]*", target):
        return "phone"

    if " " in target or "," in target:
        return "name"

    return "username"


def run_investigation(
    target: str,
    target_type: str,
    http: HttpClient,
    config: Config,
    *,
    sources: Iterable[str] | None = None,
    limit: int = 8,
    subdomains: bool = False,
    include_images: bool = True,
) -> Report:
    """Run the relevant modules for one target and aggregate the results."""
    target = target.strip()
    if target_type == "auto":
        target_type = detect_target(target)
    if target_type not in DISPLAY_TYPE:
        raise ValueError(f"Unsupported target type: {target_type}")

    report = Report(
        target=target,
        target_type=DISPLAY_TYPE[target_type],
        options={"sources": list(sources) if sources else "default", "limit": limit},
    )

    if target_type == "username":
        username = validate_username(target)
        report.target = username
        report.extend(investigate_username(username, http, config))
        report.extend(investigate_github(username, http, config))
        report.extend(
            search_all(
                f'"{username}"',
                http,
                config,
                sources=sources or ("web", "news"),
                limit=min(limit, 10),
                kind="username",
                include_images=include_images,
            )
        )
        if not config.get("github_token"):
            report.notes.append(
                "GitHub's public API allows 60 requests/hour without a token. "
                "Set GITHUB_TOKEN for deeper GitHub and email-source coverage."
            )

    elif target_type == "email":
        email = validate_email(target)
        report.target = email
        report.extend(investigate_email(email, http, config))
        report.extend(
            search_all(
                f'"{email}"',
                http,
                config,
                sources=sources or ("web", "news"),
                limit=min(limit, 10),
                kind="email",
                include_images=include_images,
            )
        )
        report.notes.append(
            "Breach data comes from the keyless XposedOrNot index; an optional "
            "HIBP_API_KEY adds Have I Been Pwned's verified records on top."
        )

    elif target_type == "phone":
        report.extend(investigate_phone(target, http, config))
        report.extend(
            search_all(
                f'"{target}"',
                http,
                config,
                sources=sources or ("web",),
                limit=min(limit, 8),
                kind="phone",
                include_images=include_images,
            )
        )
        report.notes.append(
            "Carrier and region data comes from libphonenumber metadata, not from the "
            "network. A ported number may no longer belong to the original carrier."
        )

    elif target_type == "ip":
        report.extend(investigate_ip(target, http, config))
        report.notes.append(
            "IP geolocation is approximate (city-level) and belongs to the network, "
            "not necessarily the person behind it."
        )

    elif target_type == "domain":
        domain = normalize_domain(target)
        report.target = domain
        domain_findings = investigate_domain(domain, http, config, include_subdomains=subdomains)
        report.extend(domain_findings)
        report.extend(
            search_all(
                f"site:{domain}",
                http,
                config,
                sources=sources or ("web",),
                limit=min(limit, 8),
                kind="domain",
                include_images=include_images,
            )
        )
        addresses: list[str] = []
        for finding in domain_findings:
            values = finding.data.get("A")
            if isinstance(values, list):
                addresses.extend(str(value) for value in values)
        if addresses:
            report.extend(investigate_ip(addresses[0], http, config))
        if not subdomains:
            report.notes.append(
                "Subdomain enumeration was skipped. Re-run with --subdomains to query "
                "passive certificate and hostsearch sources."
            )

    elif target_type == "name":
        if not sources:
            sources = ("web", "news", "wikipedia", "wikidata", "hn", "sec")
        report.extend(
            search_all(
                f'"{target}"',
                http,
                config,
                sources=sources,
                limit=limit,
                kind="name",
                include_images=include_images,
            )
        )
        report.notes.append(
            "Name searches return homonyms. Corroborate at least two independent "
            "attributes (location, employer, age) before attributing a record."
        )

    report.notes.append(
        "Evidence comes from public endpoints and search indexes. Blocked, missing or "
        "inconclusive sources are listed explicitly rather than treated as negative."
    )
    return report
