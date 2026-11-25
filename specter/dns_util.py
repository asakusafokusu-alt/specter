"""DNS lookups using dnspython with a DNS-over-HTTPS fallback."""

from __future__ import annotations

from dataclasses import dataclass, field

import requests

DOH_URL = "https://dns.google/resolve"
DOH_TYPES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "CAA": 257,
}


@dataclass
class DnsAnswer:
    name: str
    record_type: str
    records: list[str] = field(default_factory=list)
    error: str | None = None
    via: str = "dns"

    @property
    def ok(self) -> bool:
        return self.error is None


def _dnspython(name: str, record_type: str, timeout: float) -> DnsAnswer:
    import dns.exception
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    try:
        answers = resolver.resolve(name, record_type, lifetime=timeout)
    except dns.resolver.NXDOMAIN:
        return DnsAnswer(name, record_type, [], None, "dns")
    except dns.resolver.NoAnswer:
        return DnsAnswer(name, record_type, [], None, "dns")
    except (dns.exception.DNSException, OSError) as exc:
        return DnsAnswer(name, record_type, [], f"{type(exc).__name__}: {exc}", "dns")

    records: list[str] = []
    for answer in answers:
        if record_type == "MX":
            exchange = str(answer.exchange).rstrip(".")
            records.append(f"{answer.preference} {exchange or '.'}")
        elif record_type == "SOA":
            records.append(
                f"{str(answer.mname).rstrip('.')} {str(answer.rname).rstrip('.')} "
                f"serial={answer.serial}"
            )
        elif record_type == "TXT":
            parts = getattr(answer, "strings", None)
            if parts:
                records.append("".join(p.decode("utf-8", "replace") for p in parts))
            else:
                records.append(str(answer).strip('"'))
        else:
            records.append(str(answer).rstrip("."))
    return DnsAnswer(name, record_type, records, None, "dns")


def _doh(name: str, record_type: str, timeout: float) -> DnsAnswer:
    rtype = DOH_TYPES.get(record_type)
    if not rtype:
        return DnsAnswer(name, record_type, [], f"unsupported type {record_type}", "doh")
    try:
        response = requests.get(
            DOH_URL,
            params={"name": name, "type": record_type},
            headers={"Accept": "application/dns-json"},
            timeout=timeout,
        )
        payload = response.json()
    except (requests.RequestException, ValueError) as exc:
        return DnsAnswer(name, record_type, [], f"DoH: {type(exc).__name__}", "doh")

    status = payload.get("Status")
    if status not in (0, 3):
        return DnsAnswer(name, record_type, [], f"DoH status {status}", "doh")
    records: list[str] = []
    for answer in payload.get("Answer", []):
        data = str(answer.get("data", "")).strip()
        if record_type == "MX":
            raw = data.strip()
            if raw in (".", "0 .", "0"):
                data = "0 ."
            else:
                data = " ".join(raw.rstrip(".").split())
        if record_type == "TXT":
            data = data.strip('"')
        if record_type == "NS":
            data = data.rstrip(".")
        if data:
            records.append(data)
    return DnsAnswer(name, record_type, records, None, "doh")


def resolve(name: str, record_type: str, timeout: float = 4.0) -> DnsAnswer:
    """Resolve a record, falling back to DoH when local DNS fails.

    The default is deliberately short: several record types are commonly
    filtered by local resolvers, and the DoH fallback then answers in well under
    a second. Waiting longer only slows every domain lookup down.
    """
    answer = _dnspython(name, record_type, timeout)
    if answer.error:
        doh = _doh(name, record_type, min(timeout, 4.0))
        if not doh.error:
            return doh
        doh.error = f"{answer.error}; {doh.error}"
        return doh
    return answer


def txt_records(name: str, timeout: float = 4.0) -> tuple[list[str], str | None]:
    answer = resolve(name, "TXT", timeout)
    return answer.records, answer.error


def spf(name: str) -> str | None:
    records, _ = txt_records(name)
    for record in records:
        if record.lower().startswith("v=spf1"):
            return record
    return None


def dmarc(name: str) -> str | None:
    records, _ = txt_records(f"_dmarc.{name}")
    for record in records:
        if record.upper().startswith("V=DMARC1"):
            return record
    return None
