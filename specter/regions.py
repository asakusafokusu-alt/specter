"""Country and region list used by the phone picker.

The region codes come from libphonenumber (the same metadata used to parse and
validate numbers) and the names/dial codes from open ISO 3166 data bundled in
``data/regions.json``. Everything is offline: no API call is involved.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

import phonenumbers

DATA_FILE = Path(__file__).resolve().parent / "data" / "regions.json"
AUTO_LABEL = "Auto-detect (from the number)"

# Regions libphonenumber knows but ISO 3166 does not name.
NAME_OVERRIDES = {"AC": "Ascension Island", "TA": "Tristan da Cunha", "XK": "Kosovo"}


@lru_cache(maxsize=1)
def _table() -> dict[str, dict[str, str]]:
    try:
        raw = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    table = {
        str(key).upper(): dict(value)
        for key, value in raw.items()
        if isinstance(value, dict)
    }
    for code, name in NAME_OVERRIDES.items():
        entry = table.setdefault(code, {"name": name, "dial": ""})
        if not entry.get("name") or entry.get("name") == code:
            entry["name"] = name
    return table


@lru_cache(maxsize=1)
def choices() -> tuple[tuple[str, str], ...]:
    """(display label, ISO region) pairs sorted by country name."""
    table = _table()
    rows: list[tuple[str, str, str]] = []
    for region in phonenumbers.SUPPORTED_REGIONS:
        entry = table.get(region) or {}
        name = entry.get("name") or region
        dial = entry.get("dial") or ""
        if not dial:
            try:
                dial = f"+{phonenumbers.country_code_for_region(region)}"
            except Exception:  # noqa: BLE001 - metadata gaps must not break the list
                dial = ""
        label = f"{name} ({dial})" if dial else name
        rows.append((name.lower(), label, region))
    rows.sort()
    return tuple((label, region) for _, label, region in rows)


def label_for(region: str | None) -> str:
    """Label for a saved ISO region, or the auto-detect label."""
    target = (region or "").upper()
    if target:
        for label, code in choices():
            if code == target:
                return label
    return AUTO_LABEL


def region_from_label(label: str) -> str | None:
    """ISO region for a picker label; ``None`` means auto-detect."""
    if not label or label == AUTO_LABEL:
        return None
    for candidate, code in choices():
        if candidate == label:
            return code
    return None


def dial_code(region: str | None) -> str:
    target = (region or "").upper()
    entry = _table().get(target) or {}
    if entry.get("dial"):
        return str(entry["dial"])
    try:
        return f"+{phonenumbers.country_code_for_region(target)}" if target else ""
    except Exception:  # noqa: BLE001
        return ""
