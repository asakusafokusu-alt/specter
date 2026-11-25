"""Breach exposure lookups.

Keyless by default. XposedOrNot's public API returns the breach list, per-breach
metadata (domain, industry, exposed data classes, record counts, references) and
a risk score without an account or key. An HIBP key is still honoured and adds
HIBP's own verified breach and paste records on top.
"""

from __future__ import annotations

import html
import re
from typing import Any

from ..config import Config
from ..http import HttpClient
from ..models import BLOCKED, ERROR, FOUND, INFO, NOT_FOUND, Finding, ImageRef

XON_ANALYTICS = "https://api.xposedornot.com/v1/breach-analytics"
XON_SITE = "https://xposedornot.com"
HIBP_BASE = "https://haveibeenpwned.com/api/v3"
HIBP_KEY_URL = "https://haveibeenpwned.com/API/Key"

# Detailed per-breach entries are capped so a badly breached address stays
# readable; the complete breach list is always reported in the summary.
MAX_DETAILS = 30


def _clean(text: str | None) -> str:
    if not text:
        return ""
    plain = re.sub(r"<[^>]+>", " ", str(text))
    return " ".join(html.unescape(plain).split())


def _split(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [part.strip() for part in re.split(r"[;,]", str(value)) if part.strip()]


def _risk(payload: dict[str, Any]) -> tuple[str | None, int | None]:
    metrics = payload.get("BreachMetrics") or {}
    entries = metrics.get("risk") or []
    if entries and isinstance(entries[0], dict):
        return entries[0].get("risk_label"), entries[0].get("risk_score")
    return None, None


def _exposed_data(payload: dict[str, Any]) -> dict[str, int]:
    """Flatten the nested exposed-data tree into {data class: count}."""
    metrics = payload.get("BreachMetrics") or {}
    found: dict[str, int] = {}

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            name = node.get("name")
            value = node.get("value")
            if isinstance(name, str) and isinstance(value, (int, float)) and name.startswith("data_"):
                label = name[5:].replace("_", " ").strip()
                if value:
                    found[label] = max(int(value), found.get(label, 0))
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(metrics.get("xposed_data"))
    return dict(sorted(found.items(), key=lambda item: item[1], reverse=True))


def _years(payload: dict[str, Any]) -> list[tuple[int, int]]:
    metrics = payload.get("BreachMetrics") or {}
    rows = metrics.get("yearwise_details") or []
    years: list[tuple[int, int]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        for key, value in row.items():
            if isinstance(key, str) and key.startswith("y") and key[1:].isdigit():
                if isinstance(value, (int, float)) and value:
                    years.append((int(key[1:]), int(value)))
    return sorted(years)


def _password_exposure(payload: dict[str, Any]) -> dict[str, int]:
    metrics = payload.get("BreachMetrics") or {}
    rows = metrics.get("passwords_strength") or []
    if rows and isinstance(rows[0], dict):
        return {str(key): int(value) for key, value in rows[0].items() if isinstance(value, (int, float))}
    return {}


def _xon_payload(email: str, http: HttpClient) -> tuple[dict[str, Any] | None, str | None]:
    response = http.get(
        XON_ANALYTICS,
        params={"email": email},
        headers={"Accept": "application/json"},
        timeout=25,
    )
    payload = response.json()
    if not response.ok:
        return None, response.short_error()
    if not isinstance(payload, dict):
        return None, "unexpected response"
    if str(payload.get("Error", "")).strip().lower() in ("not found", "notfound"):
        return {}, None
    return payload, None


def _xon_findings(
    email: str,
    payload: dict[str, Any],
    *,
    skip: set[str] | None = None,
) -> list[Finding]:
    skip = skip or set()
    summary = payload.get("BreachesSummary") or {}
    names = _split(summary.get("site"))
    details = ((payload.get("ExposedBreaches") or {}).get("breaches_details") or [])
    if isinstance(details, dict):
        details = details.get("breaches_details") or []
    details = [row for row in details if isinstance(row, dict)]
    labels = {_clean(row.get("breach")).lower() for row in details}
    for name in names:
        if name.lower() not in labels:
            details.append({"breach": name, "xposed_data": "", "xposed_records": None})
    if not details and not names:
        return []

    findings: list[Finding] = []
    risk_label, risk_score = _risk(payload)
    exposed = _exposed_data(payload)
    years = _years(payload)
    pastes = payload.get("PastesSummary") or {}
    paste_count = pastes.get("cnt") if isinstance(pastes, dict) else None

    all_names = sorted({_clean(row.get("breach")) for row in details if row.get("breach")})
    earliest = years[0][0] if years else None
    latest = years[-1][0] if years else None
    summary_data: dict[str, Any] = {
        "breaches": len(all_names),
        "breach names": all_names,
    }
    if risk_label:
        summary_data["risk"] = risk_label
    if risk_score is not None:
        summary_data["risk score"] = f"{risk_score}/100"
    if earliest:
        summary_data["first exposure"] = earliest
    if latest:
        summary_data["most recent exposure"] = latest
    if exposed:
        summary_data["exposed data"] = exposed
    if paste_count:
        summary_data["public pastes"] = paste_count
    strengths = _password_exposure(payload)
    if strengths:
        summary_data["password exposure"] = {key.replace("_", " "): value for key, value in strengths.items()}
    if years:
        summary_data["breaches per year"] = {str(year): count for year, count in years}

    findings.append(
        Finding(
            source="Breach exposure (XposedOrNot)",
            category="Breach",
            status=FOUND,
            title=f"{len(all_names)} breach{'es' if len(all_names) != 1 else ''}"
            + (f" · {risk_label} risk" if risk_label else ""),
            detail=(
                f"{email} appears in {len(all_names)} indexed breach data set(s)"
                + (f" spanning {earliest}–{latest}" if earliest and latest else "")
                + (f" · {paste_count} public paste(s)" if paste_count else "")
            ),
            url=XON_SITE,
            data=summary_data,
        )
    )

    ordered = sorted(
        details,
        key=lambda row: str(row.get("xposed_date") or row.get("added") or ""),
        reverse=True,
    )
    shown = 0
    for row in ordered:
        name = _clean(row.get("breach"))
        if not name or name.lower() in skip:
            continue
        if shown >= MAX_DETAILS:
            break
        shown += 1
        classes = _split(row.get("xposed_data"))
        records = row.get("xposed_records")
        date = _clean(str(row.get("xposed_date") or row.get("added") or ""))
        industry = _clean(row.get("industry"))
        detail_parts = [
            part
            for part in (
                f"{int(records):,} records" if isinstance(records, (int, float)) and records else "",
                date[:10] if date else "",
                industry,
            )
            if part
        ]
        data: dict[str, Any] = {}
        if row.get("domain"):
            data["domain"] = row["domain"]
        if records:
            data["affected records"] = records
        if date:
            data["exposed date"] = date
        if industry:
            data["industry"] = industry
        if classes:
            data["data classes"] = classes
        if row.get("password_risk"):
            data["password risk"] = row["password_risk"]
        if row.get("verified"):
            data["verified"] = row["verified"]
        if row.get("searchable"):
            data["searchable"] = row["searchable"]
        description = _clean(row.get("details"))
        if description:
            data["description"] = description
        references = _split(row.get("references"))
        if references:
            data["references"] = references
        logo = row.get("logo")
        images_found: list[ImageRef] = []
        if isinstance(logo, str) and logo.startswith(("http://", "https://")):
            data["logo"] = logo
            images_found.append(ImageRef(url=logo, alt=name, kind="logo", page_url=XON_SITE))
        findings.append(
            Finding(
                source=f"XposedOrNot · {name}",
                category="Breach",
                status=FOUND,
                title=name,
                url=(references[0] if references else XON_SITE),
                detail=" · ".join(detail_parts) or "Breach entry.",
                data=data,
                images=images_found,
            )
        )
    return findings


def _hibp_findings(email: str, http: HttpClient, key: str) -> tuple[list[Finding], set[str]]:
    """HIBP breach and paste records; returns findings plus the breach names seen."""
    headers = {"hibp-api-key": str(key), "Accept": "application/json"}
    findings: list[Finding] = []
    names: set[str] = set()

    response = http.get(
        f"{HIBP_BASE}/breachedaccount/{email}",
        params={"truncateResponse": "false"},
        headers=headers,
        timeout=20,
    )
    if response.status == 200:
        breaches = response.json() or []
        for breach in breaches:
            classes = ", ".join(breach.get("DataClasses", [])[:8])
            name = _clean(breach.get("Name"))
            if name:
                names.add(name.lower())
            findings.append(
                Finding(
                    source=f"HIBP · {breach.get('Name', 'breach')}",
                    category="Breach",
                    status=FOUND,
                    title=breach.get("Title") or breach.get("Name"),
                    detail=(
                        f"{breach.get('PwnCount', 0):,} accounts · "
                        f"{breach.get('BreachDate', 'unknown date')} · {classes}"
                    ),
                    url=f"https://haveibeenpwned.com/PwnedWebsites#{breach.get('Name', '')}",
                    data={
                        "domain": breach.get("Domain"),
                        "breach date": breach.get("BreachDate"),
                        "accounts": breach.get("PwnCount"),
                        "data classes": breach.get("DataClasses", []),
                        "verified": breach.get("IsVerified"),
                        "sensitive": breach.get("IsSensitive"),
                        "description": _clean(breach.get("Description"))[:400],
                    },
                )
            )
        if not breaches:
            findings.append(
                Finding(
                    source="Have I Been Pwned",
                    category="Breach",
                    status=NOT_FOUND,
                    detail="No HIBP breaches recorded for this address.",
                )
            )
    elif response.status == 404:
        findings.append(
            Finding(
                source="Have I Been Pwned",
                category="Breach",
                status=NOT_FOUND,
                detail="No HIBP breaches recorded for this address.",
            )
        )
    elif response.status == 401:
        findings.append(
            Finding(
                source="Have I Been Pwned",
                category="Breach",
                status=ERROR,
                title="Invalid API key",
                detail="HIBP rejected the configured key; the keyless results are still reported.",
                url=HIBP_KEY_URL,
            )
        )
    elif response.status == 429:
        findings.append(
            Finding(
                source="Have I Been Pwned",
                category="Breach",
                status=BLOCKED,
                detail="HIBP rate limit reached; the keyless results are still reported.",
            )
        )
    else:
        findings.append(
            Finding(
                source="Have I Been Pwned",
                category="Breach",
                status=BLOCKED if response.blocked else ERROR,
                detail=response.short_error(),
            )
        )

    pastes = http.get(f"{HIBP_BASE}/pasteaccount/{email}", headers=headers, timeout=20)
    if pastes.status == 200:
        records = pastes.json() or []
        if records:
            findings.append(
                Finding(
                    source="HIBP · pastes",
                    category="Breach",
                    status=FOUND,
                    title=f"{len(records)} paste(s)",
                    detail="This address appears in public paste dumps.",
                    data={
                        "pastes": [
                            {
                                "source": paste.get("Source"),
                                "id": paste.get("Id"),
                                "date": paste.get("Date"),
                                "emails": paste.get("EmailCount"),
                            }
                            for paste in records[:10]
                        ]
                    },
                )
            )
    return findings, names


def check_breaches(
    email: str,
    http: HttpClient,
    config: Config,
    *,
    explain_missing_key: bool = False,
) -> list[Finding]:
    """Return breach findings for an email address.

    The keyless XposedOrNot lookup always runs. A configured HIBP key adds its
    verified records; ``explain_missing_key`` only controls the wording of the
    hint shown when every source fails.
    """
    findings: list[Finding] = []
    payload, error = _xon_payload(email, http)

    hibp_names: set[str] = set()
    key = config.get("hibp_api_key")
    if key:
        hibp_findings, hibp_names = _hibp_findings(email, http, str(key))
        findings.extend(hibp_findings)

    if payload is not None:
        findings.extend(_xon_findings(email, payload, skip=hibp_names))
    elif error:
        findings.append(
            Finding(
                source="XposedOrNot (keyless)",
                category="Breach",
                status=BLOCKED if "429" in str(error) else ERROR,
                detail=f"Breach lookup failed: {error}",
            )
        )

    if not findings:
        findings.append(
            Finding(
                source="Breach exposure",
                category="Breach",
                status=INFO,
                detail=(
                    "No breaches returned. Breach indexes only cover published leaks, "
                    "so a clean result is not proof that an address is safe."
                ),
            )
        )
    elif not key:
        findings.append(
            Finding(
                source="Breach coverage",
                category="Breach",
                status=INFO,
                detail=(
                    "Results come from the keyless XposedOrNot index. An optional "
                    "HIBP_API_KEY adds Have I Been Pwned's own verified records "
                    "(specter config --set hibp_api_key=...)."
                ),
                url=HIBP_KEY_URL if explain_missing_key else None,
            )
        )
    return findings
