"""IP address intelligence: geolocation, WHOIS, reverse DNS and services."""

from __future__ import annotations

import ipaddress
from typing import Any

from .. import dns_util, whois
from ..config import Config
from ..http import HttpClient
from ..models import BLOCKED, ERROR, FOUND, INFO, MANUAL, Finding


def _normalize_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValueError("That is not a valid IPv4 or IPv6 address.") from exc
    if getattr(address, "scope_id", None):
        raise ValueError("Scoped IPv6 addresses are not supported.")
    return address


def _ip_api(address: str, http: HttpClient) -> tuple[dict[str, Any] | None, str | None]:
    fields = (
        "status,message,country,countryCode,region,regionName,city,zip,lat,lon,"
        "timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
    )
    response = http.get(f"http://ip-api.com/json/{address}", params={"fields": fields})
    payload = response.json() or {}
    if response.ok and payload.get("status") == "success":
        return payload, None
    return None, payload.get("message") or response.short_error()


def _ipwhois(address: str, http: HttpClient) -> tuple[dict[str, Any] | None, str | None]:
    response = http.get(f"https://ipwho.is/{address}")
    payload = response.json() or {}
    if response.ok and payload.get("success"):
        return payload, None
    return None, payload.get("message") or response.short_error()


def investigate_ip(address: str, http: HttpClient, config: Config) -> list[Finding]:
    parsed = _normalize_address(address)
    address = str(parsed)
    findings: list[Finding] = []

    if parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_reserved:
        findings.append(
            Finding(
                source="Scope check",
                category="IP address",
                status=INFO,
                title=address,
                detail="Private, loopback or reserved address: no public geolocation available.",
                data={"version": parsed.version, "private": parsed.is_private},
            )
        )
        return findings

    geo, geo_error = _ip_api(address, http)
    provider = "ip-api.com"
    if not geo:
        geo, geo_error = _ipwhois(address, http)
        provider = "ipwho.is"

    if geo:
        if provider == "ip-api.com":
            data = {
                "country": geo.get("country"),
                "region": geo.get("regionName"),
                "city": geo.get("city"),
                "postal code": geo.get("zip"),
                "coordinates": f"{geo.get('lat')}, {geo.get('lon')}",
                "timezone": geo.get("timezone"),
                "ISP": geo.get("isp"),
                "organization": geo.get("org"),
                "ASN": geo.get("as"),
                "reverse DNS": geo.get("reverse"),
                "proxy / VPN": "yes" if geo.get("proxy") else "no",
                "hosting / datacenter": "yes" if geo.get("hosting") else "no",
                "mobile network": "yes" if geo.get("mobile") else "no",
            }
            coords = (geo.get("lat"), geo.get("lon"))
        else:
            connection = geo.get("connection") or {}
            data = {
                "country": geo.get("country"),
                "region": geo.get("region"),
                "city": geo.get("city"),
                "postal code": geo.get("postal"),
                "coordinates": f"{geo.get('latitude')}, {geo.get('longitude')}",
                "timezone": (geo.get("timezone") or {}).get("id"),
                "ISP": connection.get("isp"),
                "organization": connection.get("org"),
                "ASN": connection.get("asn"),
                "reverse DNS": (geo.get("connection") or {}).get("domain"),
                "proxy / VPN": "unknown",
                "hosting / datacenter": "yes" if connection.get("type") == "hosting" else "no",
            }
            coords = (geo.get("latitude"), geo.get("longitude"))
        data = {key: value for key, value in data.items() if value not in (None, "")}
        findings.append(
            Finding(
                source=f"Geolocation ({provider})",
                category="IP address",
                status=FOUND,
                title=address,
                detail=(
                    f"{data.get('city') or '?'}, {data.get('country') or '?'} · "
                    f"{data.get('ISP') or data.get('organization') or 'unknown network'}"
                ),
                data=data,
            )
        )
        if coords[0] is not None and coords[1] is not None:
            findings.append(
                Finding(
                    source="Map",
                    category="IP address",
                    status=MANUAL,
                    url=f"https://www.google.com/maps?q={coords[0]},{coords[1]}",
                    detail="Approximate location (city-level, not a street address).",
                )
            )
    else:
        findings.append(
            Finding(
                source="Geolocation",
                category="IP address",
                status=ERROR,
                detail=f"Geolocation providers failed: {geo_error}",
            )
        )

    try:
        record = whois.lookup(address, timeout=10)
        fields = whois.parse_fields(record.text)
        network = whois.first(
            fields, "netrange", "inetnum", "cidr", "netblock", "route"
        )
        organisation = whois.first(
            fields, "orgname", "organization", "organisation", "netname", "owner", "descr"
        )
        abuse = whois.first(
            fields, "orgabuseemail", "abuse-mailbox", "abuse-mailbox", "abuse email"
        )
        data = {
            "network": network,
            "organisation": organisation,
            "country": whois.first(fields, "country"),
            "abuse contact": abuse,
            "registrar / registry": whois.first(
                fields, "registrar", "authority", "organisation"
            ),
            "updated": whois.first(fields, "changed", "last-modified", "updated"),
        }
        data = {key: value for key, value in data.items() if value}
        if data:
            findings.append(
                Finding(
                    source="WHOIS",
                    category="IP address",
                    status=FOUND,
                    title=organisation or network or address,
                    detail="Network registration record.",
                    data=data,
                )
            )
    except whois.WhoisError as exc:
        findings.append(
            Finding(
                source="WHOIS",
                category="IP address",
                status=BLOCKED,
                detail=f"WHOIS lookup failed: {exc}",
            )
        )

    ptr = dns_util.resolve(parsed.reverse_pointer, "PTR")
    if ptr.records:
        findings.append(
            Finding(
                source="Reverse DNS",
                category="IP address",
                status=FOUND,
                title=", ".join(ptr.records),
                detail="PTR record for the address.",
            )
        )
    else:
        findings.append(
            Finding(
                source="Reverse DNS",
                category="IP address",
                status=INFO,
                detail=ptr.error or "No PTR record.",
            )
        )

    ipinfo_key = config.get("ipinfo_token")
    if ipinfo_key:
        response = http.get(f"https://ipinfo.io/{address}/json", params={"token": ipinfo_key})
        payload = response.json() or {}
        if response.ok and not payload.get("bogon"):
            findings.append(
                Finding(
                    source="IPinfo",
                    category="IP address",
                    status=FOUND,
                    title=payload.get("org"),
                    detail="IPinfo enrichment.",
                    data={
                        "city": payload.get("city"),
                        "region": payload.get("region"),
                        "country": payload.get("country"),
                        "postal": payload.get("postal"),
                        "org": payload.get("org"),
                        "hostname": payload.get("hostname"),
                    },
                )
            )

    shodan_key = config.get("shodan_api_key")
    if shodan_key:
        response = http.get(
            f"https://api.shodan.io/shodan/host/{address}",
            params={"key": shodan_key},
        )
        payload = response.json() or {}
        if response.ok:
            findings.append(
                Finding(
                    source="Shodan",
                    category="IP address",
                    status=FOUND,
                    title=payload.get("org") or address,
                    detail=f"{len(payload.get('ports', []))} open port(s) observed.",
                    data={
                        "ports": payload.get("ports", []),
                        "hostnames": payload.get("hostnames", []),
                        "operating system": payload.get("os"),
                        "country": payload.get("country_name"),
                        "last update": payload.get("last_update"),
                        "vulnerabilities": len(payload.get("vulns", {}) or {}),
                    },
                    url=f"https://www.shodan.io/host/{address}",
                )
            )
        else:
            findings.append(
                Finding(
                    source="Shodan",
                    category="IP address",
                    status=ERROR,
                    detail=payload.get("error") or response.short_error(),
                )
            )

    findings.extend(
        [
            Finding(
                source="Shodan (web)",
                category="IP address",
                status=MANUAL,
                url=f"https://www.shodan.io/host/{address}",
                detail="Exposed services and banners (free account may be required).",
            ),
            Finding(
                source="AbuseIPDB",
                category="IP address",
                status=MANUAL,
                url=f"https://www.abuseipdb.com/check/{address}",
                detail="Abuse reports and reputation.",
            ),
            Finding(
                source="IPinfo (web)",
                category="IP address",
                status=MANUAL,
                url=f"https://ipinfo.io/{address}",
                detail="ASN, company and privacy details.",
            ),
        ]
    )
    return findings
