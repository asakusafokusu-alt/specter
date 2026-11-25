"""Phone number intelligence using libphonenumber metadata."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import phonenumbers
from phonenumbers import carrier, geocoder, timezone as pn_timezone

from ..config import Config
from ..http import HttpClient
from ..models import ERROR, FOUND, INFO, MANUAL, Finding

TYPE_NAMES = {
    0: "fixed line",
    1: "mobile",
    2: "fixed line or mobile",
    3: "toll free",
    4: "premium rate",
    5: "shared cost",
    6: "VoIP",
    7: "personal number",
    8: "pager",
    9: "UAN",
    10: "voicemail",
    27: "unknown",
}


def _label(value: str | None) -> str:
    return value.strip() if value and value.strip() else "—"


def investigate_phone(
    raw: str,
    http: HttpClient,
    config: Config,
    *,
    region: str | None = None,
) -> list[Finding]:
    """Analyze a phone number without ever contacting the target."""
    region = (region or config.get("phone_region") or "US").upper()
    try:
        number = phonenumbers.parse(raw, region)
    except phonenumbers.NumberParseException as exc:
        return [
            Finding(
                source="Phone parser",
                category="Phone",
                status=ERROR,
                title=raw,
                detail=f"Could not parse the number ({exc}). Try an international format such as +33612345678.",
            )
        ]

    valid = phonenumbers.is_valid_number(number)
    possible = phonenumbers.is_possible_number(number)
    number_type = phonenumbers.number_type(number)
    region_code = phonenumbers.region_code_for_number(number)
    carrier_name = carrier.name_for_number(number, "en")
    location = geocoder.description_for_number(number, "en")
    zones = list(pn_timezone.time_zones_for_number(number))
    national = str(number.national_number)

    data: dict[str, Any] = {
        "valid": bool(valid),
        "possible": bool(possible),
        "type": TYPE_NAMES.get(number_type, "unknown"),
        "country code": f"+{number.country_code}",
        "region": region_code or "unknown",
        "carrier": _label(carrier_name),
        "location": _label(location),
        "timezone": ", ".join(zones) if zones else "—",
        "E.164": phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164),
        "international": phonenumbers.format_number(
            number, phonenumbers.PhoneNumberFormat.INTERNATIONAL
        ),
        "national": phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.NATIONAL),
        "RFC 3966": phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.RFC3966),
    }

    findings: list[Finding] = [
        Finding(
            source="Validation",
            category="Phone",
            status=FOUND if valid else INFO,
            title=data["international"],
            detail=(
                "Valid number according to libphonenumber metadata."
                if valid
                else "Number could be parsed but is not valid for its region/prefix."
            ),
            data=data,
        )
    ]

    if number_type == 6:
        findings.append(
            Finding(
                source="Line type",
                category="Phone",
                status=INFO,
                title="VoIP / virtual number",
                detail="The prefix is allocated to VoIP or virtual numbering. Attribution is weaker.",
            )
        )
    if number_type == 3:
        findings.append(
            Finding(
                source="Line type",
                category="Phone",
                status=INFO,
                title="Toll-free number",
                detail="Toll-free numbers are usually organisations, not individuals.",
            )
        )

    e164 = data["E.164"]
    digits = e164.lstrip("+")
    truecaller_region = (region_code or region or "US").lower()

    findings.extend(
        [
            Finding(
                source="Truecaller (web)",
                category="Phone",
                status=MANUAL,
                url=f"https://www.truecaller.com/search/{truecaller_region}/{national}",
                detail="Community caller-ID lookup; requires a browser/account.",
            ),
            Finding(
                source="Sync.me",
                category="Phone",
                status=MANUAL,
                url=f"https://sync.me/search/?number={quote(digits)}",
                detail="Crowd-sourced caller name lookup.",
            ),
            Finding(
                source="WhatsApp",
                category="Phone",
                status=MANUAL,
                url=f"https://wa.me/{quote(digits)}",
                detail="Shows whether the number has a WhatsApp account (no message is sent).",
            ),
            Finding(
                source="Google",
                category="Phone",
                status=MANUAL,
                url=f"https://www.google.com/search?q=%22{quote(e164)}%22",
                detail="Search the number in international format.",
            ),
        ]
    )

    numverify_key = config.get("numverify_api_key")
    if numverify_key:
        response = http.get(
            "http://apilayer.net/api/validate",
            params={"access_key": numverify_key, "number": e164, "format": 1},
        )
        payload = response.json() or {}
        if response.ok and payload.get("valid") is not None:
            findings.append(
                Finding(
                    source="Numverify",
                    category="Phone",
                    status=FOUND if payload.get("valid") else INFO,
                    title=payload.get("international_format"),
                    detail="Carrier validation from Numverify.",
                    data={
                        "carrier": payload.get("carrier"),
                        "line type": payload.get("line_type"),
                        "location": payload.get("location"),
                        "country": payload.get("country_name"),
                    },
                )
            )
        else:
            findings.append(
                Finding(
                    source="Numverify",
                    category="Phone",
                    status=ERROR if response.ok else INFO,
                    detail=payload.get("error", {}).get("info") or response.short_error(),
                )
            )

    return findings
