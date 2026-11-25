"""Minimal WHOIS (RFC 3912) client and record parsing helpers.

RDAP endpoints are frequently blocked by CDNs, while port 43 WHOIS remains
widely available, so SPECTER speaks WHOIS directly.
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass
from datetime import datetime, timezone

IANA_SERVER = "whois.iana.org"


class WhoisError(RuntimeError):
    pass


@dataclass
class WhoisResult:
    query: str
    text: str
    servers: list[str]


def _query_server(server: str, query: str, timeout: int = 12) -> str:
    try:
        with socket.create_connection((server, 43), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(query.encode("utf-8", "replace") + b"\r\n")
            chunks: list[bytes] = []
            while True:
                try:
                    data = sock.recv(8192)
                except socket.timeout:
                    break
                if not data:
                    break
                chunks.append(data)
    except OSError as exc:
        raise WhoisError(f"{server}: {exc}") from exc
    text = b"".join(chunks).decode("utf-8", "replace")
    if not text.strip():
        raise WhoisError(f"{server}: empty response")
    return text


def _referral(text: str) -> str | None:
    for line in text.splitlines():
        lower = line.lower().strip()
        if lower.startswith(("refer:", "whois:")):
            candidate = line.split(":", 1)[1].strip()
            candidate = re.sub(r"^whois://", "", candidate)
            candidate = candidate.split()[0] if candidate else ""
            if candidate and "." in candidate:
                return candidate
    return None


def lookup(query: str, timeout: int = 12) -> WhoisResult:
    """Look up a domain, IP or ASN, following one IANA/registry referral."""
    query = query.strip()
    servers: list[str] = []
    text = _query_server(IANA_SERVER, query, timeout=timeout)
    servers.append(IANA_SERVER)
    referral = _referral(text)
    if referral:
        try:
            referred = _query_server(referral, query, timeout=timeout)
            servers.append(referral)
            # Prefer the registry response, but keep IANA notes if it is empty.
            if referred.strip():
                text = referred
        except WhoisError:
            pass
    return WhoisResult(query=query, text=text, servers=servers)


def parse_fields(text: str) -> dict[str, str]:
    """First value for every key in a WHOIS response (keys lowercased)."""
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line[0] in "%#*" or line.startswith("//"):
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if not key or not value:
            continue
        fields.setdefault(key, value)
    return fields


def all_values(text: str, *keys: str) -> list[str]:
    wanted = {key.lower() for key in keys}
    values: list[str] = []
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.strip().lower() in wanted and value.strip():
            cleaned = " ".join(value.split())
            if cleaned not in values:
                values.append(cleaned)
    return values


def first(text_or_fields: str | dict[str, str], *keys: str) -> str | None:
    if isinstance(text_or_fields, dict):
        for key in keys:
            value = text_or_fields.get(key.lower())
            if value:
                return value
        return None
    values = all_values(text_or_fields, *keys)
    return values[0] if values else None


DATE_FORMATS = (
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
    "%d-%b-%Y",
    "%d-%B-%Y",
    "%d.%m.%Y",
    "%Y.%m.%d",
    "%Y/%m/%d",
    "%d/%m/%Y",
    "%B %d %Y",
    "%b %d %Y",
)


def parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    cleaned = value.split("(")[0].strip().replace("  ", " ")
    cleaned = re.sub(r"\s*[A-Z]{2,5}$", "", cleaned)  # trailing timezone names
    for fmt in DATE_FORMATS:
        try:
            parsed = datetime.strptime(cleaned, fmt)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except ValueError:
            continue
    match = re.search(r"(\d{4})-(\d{2})-(\d{2})", value)
    if match:
        try:
            return datetime(
                int(match.group(1)),
                int(match.group(2)),
                int(match.group(3)),
                tzinfo=timezone.utc,
            )
        except ValueError:
            return None
    return None


def days_since(moment: datetime | None) -> int | None:
    if not moment:
        return None
    return max(0, (datetime.now(timezone.utc) - moment).days)


def redacted(value: str | None) -> bool:
    if not value:
        return True
    low = value.lower()
    return any(
        marker in low
        for marker in ("redacted", "not disclosed", "privacy", "withheld", "gdpr")
    )
