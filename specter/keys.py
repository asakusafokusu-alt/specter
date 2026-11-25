"""Optional API key inventory, free-tier notes and live validation.

Nothing here is required: every module runs keyless. This module exists so a key
can be proven to work in one command instead of being discovered as broken in
the middle of an investigation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .config import KEYS, Config
from .http import HttpClient

VALID = "valid"
INVALID = "invalid"
UNREACHABLE = "unreachable"


@dataclass
class KeyStatus:
    key: str
    env: str
    label: str
    state: str
    detail: str
    free: str
    signup: str


def _github(config: Config, http: HttpClient) -> tuple[str, str]:
    token = config.get("github_token")
    response = http.get(
        "https://api.github.com/user",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        timeout=12,
        use_cache=False,
    )
    if response.status == 200:
        login = (response.json() or {}).get("login", "?")
        return VALID, f"authenticated as {login}"
    if response.status in (401, 403):
        return INVALID, f"GitHub rejected the token (HTTP {response.status})"
    return UNREACHABLE, response.short_error()


def _hibp(config: Config, http: HttpClient) -> tuple[str, str]:
    response = http.get(
        "https://haveibeenpwned.com/api/v3/breachedaccount/account%40example.com",
        headers={"hibp-api-key": str(config.get("hibp_api_key")), "User-Agent": "SPECTER"},
        timeout=12,
        use_cache=False,
    )
    if response.status in (200, 404):
        return VALID, "key accepted (200 enrolled / 404 not enrolled)"
    if response.status in (401, 403):
        return INVALID, f"key rejected (HTTP {response.status})"
    return UNREACHABLE, response.short_error()


def _searxng(config: Config, http: HttpClient) -> tuple[str, str]:
    base = str(config.get("searxng_url")).rstrip("/")
    response = http.get(f"{base}/search", params={"q": "test", "format": "json"}, timeout=12, use_cache=False)
    if response.ok and isinstance(response.json(), dict):
        return VALID, "instance answered JSON"
    if response.ok:
        return INVALID, "answered, but not with SearXNG JSON (format=json disabled?)"
    return UNREACHABLE, response.short_error()


def _google(config: Config, http: HttpClient) -> tuple[str, str]:
    key = config.get("google_api_key")
    cx = config.get("google_cse_id")
    if not key or not cx:
        return INVALID, "both GOOGLE_API_KEY and GOOGLE_CSE_ID are needed"
    response = http.get(
        "https://www.googleapis.com/customsearch/v1",
        params={"key": key, "cx": cx, "q": "test", "num": 1},
        timeout=12,
        use_cache=False,
    )
    if response.status == 200:
        return VALID, "Programmable Search accepted the key and engine id"
    payload = response.json() or {}
    reason = (payload.get("error") or {}).get("message", "")
    return INVALID, f"HTTP {response.status} {reason}".strip()


def _brave(config: Config, http: HttpClient) -> tuple[str, str]:
    response = http.get(
        "https://api.search.brave.com/res/v1/web/search",
        params={"q": "test", "count": 1},
        headers={"X-Subscription-Token": str(config.get("brave_api_key")), "Accept": "application/json"},
        timeout=12,
        use_cache=False,
    )
    if response.status == 200:
        return VALID, "subscription token accepted"
    if response.status in (401, 403, 422):
        return INVALID, f"token rejected (HTTP {response.status})"
    return UNREACHABLE, response.short_error()


def _courtlistener(config: Config, http: HttpClient) -> tuple[str, str]:
    response = http.get(
        "https://www.courtlistener.com/api/rest/v4/search/",
        params={"q": "test"},
        headers={"Authorization": f"Token {config.get('courtlistener_token')}"},
        timeout=12,
        use_cache=False,
    )
    if response.status == 200:
        return VALID, "token accepted"
    if response.status in (401, 403):
        return INVALID, f"token rejected (HTTP {response.status})"
    return UNREACHABLE, response.short_error()


def _numverify(config: Config, http: HttpClient) -> tuple[str, str]:
    response = http.get(
        "https://apilayer.net/api/validate",
        params={"access_key": config.get("numverify_api_key"), "number": "14158586273"},
        timeout=12,
        use_cache=False,
    )
    payload = response.json() or {}
    if payload.get("success") is True:
        return VALID, "key accepted"
    error = payload.get("error") or {}
    if error.get("code") in (101, 102, 103):
        return INVALID, str(error.get("info") or "key rejected")
    return UNREACHABLE, response.short_error()


def _ipinfo(config: Config, http: HttpClient) -> tuple[str, str]:
    response = http.get(
        "https://ipinfo.io/8.8.8.8",
        params={"token": config.get("ipinfo_token")},
        timeout=12,
        use_cache=False,
    )
    payload = response.json() or {}
    if response.ok and payload.get("ip"):
        return VALID, f"answered for {payload.get('ip')} ({payload.get('org', 'no org')})"
    if response.status in (401, 403):
        return INVALID, f"token rejected (HTTP {response.status})"
    return UNREACHABLE, response.short_error()


def _shodan(config: Config, http: HttpClient) -> tuple[str, str]:
    response = http.get(
        "https://api.shodan.io/api-info",
        params={"key": config.get("shodan_api_key")},
        timeout=12,
        use_cache=False,
    )
    if response.ok:
        credits = (response.json() or {}).get("query_credits", "?")
        return VALID, f"key accepted, {credits} query credits"
    if response.status in (401, 403):
        return INVALID, f"key rejected (HTTP {response.status})"
    return UNREACHABLE, response.short_error()


def _opencorporates(config: Config, http: HttpClient) -> tuple[str, str]:
    response = http.get(
        "https://api.opencorporates.com/v0.4/companies/search",
        params={"q": "test", "api_token": config.get("opencorporates_api_key")},
        timeout=12,
        use_cache=False,
    )
    payload = response.json() or {}
    if response.ok and isinstance(payload.get("results"), dict):
        return VALID, "API token accepted"
    if response.status in (401, 403):
        return INVALID, f"token rejected (HTTP {response.status})"
    return UNREACHABLE, response.short_error()


def _emailrep(config: Config, http: HttpClient) -> tuple[str, str]:
    response = http.get(
        "https://emailrep.io/account%40example.com",
        headers={"Key": str(config.get("emailrep_api_key")), "User-Agent": "SPECTER"},
        timeout=12,
        use_cache=False,
    )
    if response.ok:
        return VALID, "key accepted"
    if response.status in (401, 403, 429):
        return INVALID, f"key rejected or throttled (HTTP {response.status})"
    return UNREACHABLE, response.short_error()


CHECKS: dict[str, Callable[[Config, HttpClient], tuple[str, str]]] = {
    "github_token": _github,
    "hibp_api_key": _hibp,
    "searxng_url": _searxng,
    "google_api_key": _google,
    "google_cse_id": _google,
    "brave_api_key": _brave,
    "courtlistener_token": _courtlistener,
    "numverify_api_key": _numverify,
    "ipinfo_token": _ipinfo,
    "shodan_api_key": _shodan,
    "opencorporates_api_key": _opencorporates,
    "emailrep_api_key": _emailrep,
}


def inventory(config: Config, http: HttpClient | None = None, *, check: bool = False) -> list[KeyStatus]:
    """One row per supported key: masked value, state and where to get it."""
    rows: list[KeyStatus] = []
    checked: dict[str, tuple[str, str]] = {}
    for spec in KEYS:
        value = config.get(spec.key)
        if not value:
            rows.append(
                KeyStatus(spec.key, spec.env, spec.label, "missing", "not configured", spec.free, spec.signup)
            )
            continue
        if not check:
            rows.append(
                KeyStatus(spec.key, spec.env, spec.label, "set", config.masked(spec.key), spec.free, spec.signup)
            )
            continue
        # A Google check validates the key + engine id pair once.
        cache_key = "google_api_key" if spec.key in ("google_api_key", "google_cse_id") else spec.key
        if cache_key not in checked:
            checker = CHECKS.get(cache_key)
            if checker is None:
                checked[cache_key] = ("set", "no live check available")
            else:
                try:
                    checked[cache_key] = checker(config, http)  # type: ignore[arg-type]
                except Exception as exc:  # noqa: BLE001 - a broken check is not an error
                    checked[cache_key] = (UNREACHABLE, f"{type(exc).__name__}: {exc}")
        state, detail = checked[cache_key]
        rows.append(KeyStatus(spec.key, spec.env, spec.label, state, detail, spec.free, spec.signup))
    return rows


def env_example() -> str:
    """Ready-to-fill .env with every variable, no secrets."""
    lines = [
        "# SPECTER optional keys. Copy to .env and fill in what you obtain.",
        "# Every module works without these; keys only add depth or higher limits.",
        "",
    ]
    for spec in KEYS:
        lines.append(f"# {spec.label}: {spec.free}")
        if spec.signup:
            lines.append(f"#   get it: {spec.signup}")
        lines.append(f"{spec.env}=")
        lines.append("")
    return "\n".join(lines)
