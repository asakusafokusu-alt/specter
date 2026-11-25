"""Domain intelligence: registration, DNS, email posture, subdomains and banner.

Registration data is read from RDAP (keyless, structured JSON) and port-43 WHOIS
in parallel, then merged; DNS record types are queried concurrently.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from html import unescape
from typing import Any
from urllib.parse import quote, urlsplit

from .. import dns_util, images, whois
from ..config import Config
from ..http import HttpClient
from ..models import BLOCKED, ERROR, FOUND, INFO, MANUAL, Finding, ImageRef

DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{2,63}(?<!-))+$"
)

RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
RDAP_FALLBACK = "https://rdap.org/domain/{domain}"
_RDAP_BASES: dict[str, str] | None = None


def normalize_domain(value: str) -> str:
    candidate = value.strip().lower()
    if "://" in candidate:
        candidate = urlsplit(candidate).hostname or ""
    candidate = candidate.split("/")[0].split(":")[0].strip(".")
    if not candidate or not DOMAIN_RE.match(candidate):
        raise ValueError("That does not look like a valid domain name.")
    if candidate.rsplit(".", 1)[-1].isdigit():
        raise ValueError("Top-level domain cannot be numeric.")
    try:
        return candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Domain contains invalid characters.") from exc


# ---------------------------------------------------------------------------
# Registration data: RDAP + WHOIS
# ---------------------------------------------------------------------------
def _vcard_value(entity: dict[str, Any], field: str) -> str | None:
    array = entity.get("vcardArray") or [None, []]
    entries = array[1] if isinstance(array, list) and len(array) > 1 else []
    for entry in entries or []:
        if not isinstance(entry, list) or not entry:
            continue
        if str(entry[0]).lower() != field:
            continue
        value = entry[3] if len(entry) > 3 else None
        if isinstance(value, list):
            value = " ".join(str(part) for part in value)
        if value:
            return str(value).strip()
    return None


def _entity_with_role(entities: list[Any], role: str) -> dict[str, Any]:
    for entity in entities:
        if isinstance(entity, dict) and role in (entity.get("roles") or []):
            return entity
    return {}


def _abuse_email(entities: list[Any]) -> str | None:
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        if "abuse" in (entity.get("roles") or []):
            email = _vcard_value(entity, "email")
            if email:
                return email
        nested = entity.get("entities") or []
        if nested:
            email = _abuse_email(nested)
            if email:
                return email
    return None


def _rdap_base(tld: str, http: HttpClient) -> str | None:
    """Resolve the registry's RDAP base URL from the IANA bootstrap registry."""
    global _RDAP_BASES
    if _RDAP_BASES is None:
        mapping: dict[str, str] = {}
        response = http.get(RDAP_BOOTSTRAP, timeout=25)
        payload = response.json() or {}
        for service in payload.get("services") or []:
            if not isinstance(service, list) or len(service) < 2:
                continue
            urls = service[1] or []
            if not urls:
                continue
            base = str(urls[0])
            for name in service[0] or []:
                mapping[str(name).lower()] = base
        _RDAP_BASES = mapping
    return _RDAP_BASES.get(tld.lower())


def _rdap_parse(payload: dict[str, Any], server: str) -> dict[str, Any]:
    events = {
        str(event.get("eventAction", "")).lower(): event.get("eventDate")
        for event in payload.get("events") or []
        if isinstance(event, dict)
    }
    entities = payload.get("entities") or []
    registrar = _entity_with_role(entities, "registrar")
    registrant = _entity_with_role(entities, "registrant")
    created = (events.get("registration") or "")[:10]
    expires = (events.get("expiration") or "")[:10]
    updated = (events.get("last changed") or events.get("last update") or "")[:10]
    nameservers = [
        str(nameserver.get("ldhName")).lower()
        for nameserver in payload.get("nameservers") or []
        if isinstance(nameserver, dict) and nameserver.get("ldhName")
    ]
    data_nameservers = nameservers
    parsed_created = whois.parse_date(created)
    data: dict[str, Any] = {
        "registrar": _vcard_value(registrar, "fn"),
        "created": created or None,
        "expires": expires or None,
        "updated": updated or None,
        "age": f"{whois.days_since(parsed_created):,} days" if parsed_created else None,
        "statuses": payload.get("status") or None,
        "name servers": data_nameservers or None,
        "registrant": _vcard_value(registrant, "fn") or _vcard_value(registrant, "org"),
        "abuse contact": _abuse_email(entities),
        "DNSSEC": (payload.get("secureDNS") or {}).get("delegationSigned"),
        "registry handle": payload.get("handle"),
        "rdap server": server,
    }
    return {key: value for key, value in data.items() if value not in (None, "", [], {})}


def _rdap_data(domain: str, http: HttpClient) -> tuple[dict[str, Any] | None, str | None]:
    """Structured registration data from RDAP — keyless and usually richer.

    The registry endpoint from the IANA bootstrap is queried first; the public
    rdap.org proxy is only a fallback because it rate-limits aggressively.
    """
    tld = domain.rsplit(".", 1)[-1]
    candidates: list[str] = []
    base = _rdap_base(tld, http)
    if base:
        candidates.append(f"{base.rstrip('/')}/domain/{quote(domain, safe='')}")
    candidates.append(RDAP_FALLBACK.format(domain=quote(domain, safe="")))

    errors: list[str] = []
    for endpoint in candidates:
        response = http.get(
            endpoint,
            headers={"Accept": "application/rdap+json, application/json"},
            timeout=20,
        )
        if not response.ok:
            errors.append(f"{response.status or response.short_error()}")
            continue
        payload = response.json()
        if not isinstance(payload, dict) or payload.get("errorCode"):
            errors.append("no record")
            continue
        data = _rdap_parse(payload, response.url)
        if data:
            return data, None
        errors.append("empty record")
    return None, ", ".join(dict.fromkeys(errors)) or "no RDAP record"


def _whois_data(text: str) -> dict[str, Any]:
    fields = whois.parse_fields(text)
    created = whois.parse_date(
        whois.first(
            fields,
            "creation date",
            "created",
            "domain registration date",
            "registered on",
            "registration time",
            "domain create date",
        )
    )
    expires = whois.parse_date(
        whois.first(
            fields,
            "registry expiry date",
            "registrar registration expiration date",
            "expiry date",
            "expiration date",
            "paid-till",
            "expires",
        )
    )
    updated = whois.parse_date(
        whois.first(fields, "updated date", "last updated", "last-modified", "changed")
    )
    nameservers = whois.all_values(text, "name server", "nserver", "name servers")
    statuses = whois.all_values(text, "domain status", "status")
    registrant = whois.first(
        fields,
        "registrant organization",
        "registrant",
        "org",
        "organisation",
        "registrant name",
    )
    data: dict[str, Any] = {
        "registrar": whois.first(fields, "registrar", "sponsoring registrar"),
        "created": created.date().isoformat() if created else None,
        "expires": expires.date().isoformat() if expires else None,
        "updated": updated.date().isoformat() if updated else None,
        "age": f"{whois.days_since(created):,} days" if created else None,
        "statuses": statuses,
        "name servers": nameservers,
        "registrant": None if whois.redacted(registrant) else registrant,
        "registrant country": None
        if whois.redacted(whois.first(fields, "registrant country", "country"))
        else whois.first(fields, "registrant country", "country"),
        "DNSSEC": whois.first(fields, "dnssec"),
        "abuse contact": whois.first(
            fields, "registrar abuse contact email", "orgabuseemail", "abuse-mailbox"
        ),
    }
    return {key: value for key, value in data.items() if value not in (None, [], "")}


def _registration(domain: str, http: HttpClient) -> tuple[list[Finding], dict[str, Any]]:
    """RDAP first (fast, structured); port-43 WHOIS only fills the gaps it leaves."""
    findings: list[Finding] = []
    try:
        rdap, rdap_error = _rdap_data(domain, http)
    except Exception as exc:  # noqa: BLE001 - registration must not kill the scan
        rdap, rdap_error = None, f"{type(exc).__name__}: {exc}"

    whois_data: dict[str, Any] = {}
    servers: list[str] = []
    rdap_complete = bool(
        rdap and rdap.get("registrar") and (rdap.get("created") or rdap.get("name servers"))
    )
    if rdap_complete:
        findings.append(
            Finding(
                source="WHOIS",
                category="Domain",
                status=INFO,
                detail="Port-43 WHOIS skipped: the RDAP record already has the registrar, dates and name servers.",
            )
        )
    else:
        try:
            record = whois.lookup(domain, timeout=8)
            whois_data = _whois_data(record.text)
            servers = record.servers
        except whois.WhoisError as exc:
            findings.append(
                Finding(
                    source="WHOIS",
                    category="Domain",
                    status=BLOCKED,
                    detail=f"WHOIS lookup failed: {exc}",
                )
            )

    merged: dict[str, Any] = {}
    for source in (whois_data, rdap or {}):
        for key, value in source.items():
            if value not in (None, "", [], {}):
                merged[key] = value

    if merged:
        label = "RDAP + WHOIS" if rdap and whois_data else ("RDAP" if rdap else "WHOIS")
        detail = " · ".join(
            part
            for part in (
                f"Registrar: {merged.get('registrar')}" if merged.get("registrar") else "",
                f"created {merged['created']}" if merged.get("created") else "",
                f"expires {merged['expires']}" if merged.get("expires") else "",
            )
            if part
        )
        findings.insert(
            0,
            Finding(
                source=label,
                category="Domain",
                status=FOUND,
                title=domain,
                detail=detail or "Registration record.",
                url=f"https://lookup.icann.org/en/lookup?q={quote(domain)}",
                data=merged,
            ),
        )
    if servers:
        findings.append(
            Finding(
                source="WHOIS servers",
                category="Domain",
                status=INFO,
                detail="Query path: " + " → ".join(servers),
            )
        )
    if not rdap:
        findings.append(
            Finding(
                source="RDAP",
                category="Domain",
                status=INFO,
                detail=f"RDAP unavailable for this name ({rdap_error}); WHOIS data is used.",
            )
        )
    return findings, merged


# ---------------------------------------------------------------------------
# DNS, HTTP and subdomains
# ---------------------------------------------------------------------------
def _dns_data(domain: str) -> tuple[dict[str, Any], list[str]]:
    record_types = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA", "SOA")

    def worker(record_type: str) -> tuple[str, dns_util.DnsAnswer]:
        return record_type, dns_util.resolve(domain, record_type, timeout=3.5)

    records: dict[str, Any] = {}
    errors: list[str] = []
    with ThreadPoolExecutor(max_workers=len(record_types)) as pool:
        answers = list(pool.map(worker, record_types))
    for record_type, answer in answers:
        if answer.error:
            errors.append(f"{record_type}: {answer.error}")
        elif answer.records:
            records[record_type] = answer.records
    return records, errors


def _page(domain: str, http: HttpClient) -> Finding:
    response = http.get(f"https://{domain}", timeout=10)
    if response.error and "ssl" in str(response.error).lower():
        response = http.get(f"http://{domain}", timeout=10)
    if not response.status:
        return Finding(
            source="HTTP fingerprint",
            category="Domain",
            status=ERROR,
            detail=response.short_error(),
        )
    meta = images.extract_meta(response.text or "", response.url or f"https://{domain}")
    title = meta.get("title")
    data = {
        "final URL": response.url,
        "status": response.status,
        "server": response.header("server"),
        "content type": response.header("content-type"),
        "powered by": response.header("x-powered-by"),
        "title": title,
        "description": meta.get("description"),
        "favicon": meta.get("favicon"),
        "open graph image": meta.get("image"),
    }
    data = {key: value for key, value in data.items() if value not in (None, "")}
    found: list[ImageRef] = []
    if meta.get("image"):
        found.append(
            ImageRef(
                url=str(meta["image"]),
                alt=title or domain,
                kind="thumbnail",
                page_url=response.url,
            )
        )
    if meta.get("favicon"):
        found.append(
            ImageRef(
                url=str(meta["favicon"]),
                alt=f"{domain} icon",
                kind="logo",
                page_url=response.url,
            )
        )
    return Finding(
        source="HTTP fingerprint",
        category="Domain",
        status=FOUND,
        title=title,
        detail=f"HTTP {response.status} · server: {response.header('server', 'unknown')}",
        url=response.url,
        data=data,
        images=found,
    )


def _subdomains(domain: str, http: HttpClient) -> Finding:
    response = http.get(
        "https://api.hackertarget.com/hostsearch/",
        params={"q": domain},
        timeout=30,
    )
    hosts: list[tuple[str, str]] = []
    if response.ok and "error" not in response.text.lower()[:80]:
        for line in response.text.splitlines():
            parts = line.strip().split(",")
            if len(parts) >= 2 and parts[0].endswith(domain):
                hosts.append((parts[0], parts[1]))
    if not hosts:
        crt = http.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=45,
        )
        if crt.ok:
            try:
                rows = crt.json() or []
            except ValueError:
                rows = []
            for row in rows:
                for name in str(row.get("name_value", "")).splitlines():
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(domain):
                        hosts.append((name, "—"))
    unique: dict[str, str] = {}
    for host, ip in hosts:
        unique.setdefault(host.lower(), ip)
    if unique:
        return Finding(
            source="Subdomain discovery",
            category="Domain",
            status=FOUND,
            title=f"{len(unique)} subdomain(s)",
            detail="Passive sources: HackerTarget hostsearch and certificate transparency (crt.sh).",
            data={
                "subdomains": [
                    {"host": host, "ip": ip}
                    for host, ip in sorted(unique.items())[:150]
                ]
            },
        )
    if response.status in (403, 429):
        return Finding(
            source="Subdomain discovery",
            category="Domain",
            status=BLOCKED,
            detail="Passive subdomain providers are rate limited right now.",
        )
    return Finding(
        source="Subdomain discovery",
        category="Domain",
        status=INFO,
        detail="No subdomains returned by the passive sources.",
    )


def investigate_domain(
    value: str,
    http: HttpClient,
    config: Config,
    *,
    include_subdomains: bool = False,
) -> list[Finding]:
    domain = normalize_domain(value)
    findings: list[Finding] = []

    # Registration, DNS and the website are independent: query them at once.
    with ThreadPoolExecutor(max_workers=3) as pool:
        registration_future = pool.submit(_registration, domain, http)
        dns_future = pool.submit(_dns_data, domain)
        page_future = pool.submit(_page, domain, http)

    try:
        registration, _ = registration_future.result()
    except Exception as exc:  # noqa: BLE001
        registration = [
            Finding(
                source="RDAP / WHOIS",
                category="Domain",
                status=ERROR,
                detail=f"{type(exc).__name__}: {exc}",
            )
        ]
    findings.extend(registration)

    try:
        records, dns_errors = dns_future.result()
    except Exception as exc:  # noqa: BLE001
        records, dns_errors = {}, [f"{type(exc).__name__}: {exc}"]
    findings.append(
        Finding(
            source="DNS records",
            category="Domain",
            status=FOUND if records else INFO,
            title=domain,
            detail=", ".join(records.keys()) if records else "No records returned.",
            data=records,
        )
    )
    if dns_errors:
        findings.append(
            Finding(
                source="DNS notes",
                category="Domain",
                status=INFO,
                detail="; ".join(dns_errors[:4]),
            )
        )

    # SPF already lives in the TXT set we just fetched; only DMARC needs a query.
    txt = [str(item) for item in records.get("TXT", [])]
    spf = next((item for item in txt if item.lower().startswith("v=spf1")), None)
    dmarc = dns_util.dmarc(domain)
    findings.append(
        Finding(
            source="Email authentication",
            category="Domain",
            status=INFO,
            title=domain,
            detail="SPF and DMARC posture for the domain.",
            data={
                "SPF": spf or "not published",
                "DMARC": dmarc or "not published",
                "MX": records.get("MX", []),
            },
        )
    )

    try:
        findings.append(page_future.result())
    except Exception as exc:  # noqa: BLE001
        findings.append(
            Finding(
                source="HTTP fingerprint",
                category="Domain",
                status=ERROR,
                detail=f"{type(exc).__name__}: {exc}",
            )
        )

    if include_subdomains:
        findings.append(_subdomains(domain, http))

    findings.extend(
        [
            Finding(
                source="ICANN lookup",
                category="Domain",
                status=MANUAL,
                url=f"https://lookup.icann.org/en/lookup?q={quote(domain)}",
                detail="Registration data and redaction status.",
            ),
            Finding(
                source="Certificate transparency",
                category="Domain",
                status=MANUAL,
                url=f"https://crt.sh/?q=%25.{quote(domain)}",
                detail="Every certificate ever issued for the domain.",
            ),
            Finding(
                source="Wayback Machine",
                category="Domain",
                status=MANUAL,
                url=f"https://web.archive.org/web/*/{quote(domain)}",
                detail="Historical versions of the website.",
            ),
            Finding(
                source="urlscan.io",
                category="Domain",
                status=MANUAL,
                url=f"https://urlscan.io/domain/{quote(domain)}",
                detail="Public scans, resources and infrastructure.",
            ),
        ]
    )
    return findings
