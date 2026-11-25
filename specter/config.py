"""Configuration and optional API-key management.

Settings are read from (in order of precedence):

1. Environment variables (see ``KEYS`` below)
2. A JSON file: ``$SPECTER_CONFIG``, ``./.specter.json`` or ``~/.specter/config.json``

Nothing is required to use any module: every source used by default is keyless
(Bing, Google, DuckDuckGo, Wikipedia, Wikidata, RDAP, WHOIS, DNS, GitHub's public
API, ip-api/ipwho.is and XposedOrNot). Keys only add depth or higher limits.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class KeySpec:
    key: str
    env: str
    label: str
    secret: bool = True
    help: str = ""
    signup: str = ""
    free: str = ""


KEYS: tuple[KeySpec, ...] = (
    KeySpec("github_token", "GITHUB_TOKEN", "GitHub token", True,
            "Raises GitHub API limits from 60 to 5,000 requests/hour.",
            "https://github.com/settings/tokens", "Free: 5,000 req/hour with a token (60 without)."),
    KeySpec("hibp_api_key", "HIBP_API_KEY", "Have I Been Pwned key", True,
            "Optional: adds HIBP's verified breach records to the keyless XposedOrNot lookup.",
            "https://haveibeenpwned.com/API/Key", "Paid (~$4.39/month); a free test key covers the test domain only. XposedOrNot covers breaches keyless."),
    KeySpec("searxng_url", "SEARXNG_URL", "SearXNG base URL", False,
            "Optional extra engine. Any SearXNG instance, e.g. https://searx.example.org.",
            "https://searx.space/", "Free public instances, no key needed."),
    KeySpec("google_api_key", "GOOGLE_API_KEY", "Google API key", True,
            "Optional extra engine: Programmable Search JSON key (with google_cse_id).",
            "https://console.cloud.google.com/apis/credentials", "Free: 100 queries/day, no card."),
    KeySpec("google_cse_id", "GOOGLE_CSE_ID", "Google CSE id", False,
            "Programmable Search Engine id (cx) for web results.",
            "https://programmablesearchengine.google.com/controlpanel/create", "Free: created with the search engine."),
    KeySpec("brave_api_key", "BRAVE_API_KEY", "Brave Search key", True,
            "Optional extra engine: Brave Search API subscription token.",
            "https://api-dashboard.search.brave.com/app/subscriptions", "$5 free credit each month (~1,000 queries); a card is required."),
    KeySpec("courtlistener_token", "COURTLISTENER_TOKEN", "CourtListener token", True,
            "Optional token for US federal court record search.",
            "https://www.courtlistener.com/help/api/rest/", "Free token for registered users."),
    KeySpec("numverify_api_key", "NUMVERIFY_API_KEY", "Numverify key", True,
            "Carrier and line-type enrichment for phone numbers.",
            "https://numverify.com/signup", "Free: 100 requests/month."),
    KeySpec("ipinfo_token", "IPINFO_TOKEN", "IPinfo token", True,
            "Optional: adds an IPinfo cross-check to the keyless geolocation.",
            "https://ipinfo.io/signup", "Free Lite plan ($0, no card): country-level geolocation, unlimited requests."),
    KeySpec("shodan_api_key", "SHODAN_API_KEY", "Shodan key", True,
            "Optional: open ports and services for IP targets (manual link otherwise).",
            "https://account.shodan.io/register", "Free account: limited query credits."),
    KeySpec("opencorporates_api_key", "OPENCORPORATES_API_KEY", "OpenCorporates key", True,
            "Company officer search (reserved for company investigations).",
            "https://opencorporates.com/api_accounts/new", "Free API account, rate-limited."),
    KeySpec("emailrep_api_key", "EMAILREP_API_KEY", "EmailRep key", True,
            "Reputation and profile references for email addresses.",
            "https://emailrep.io/key", "Free key, rate-limited."),
)

KEY_BY_NAME = {spec.key: spec for spec in KEYS}

DEFAULTS: dict[str, Any] = {
    "timeout": 15,
    "workers": 8,
    "phone_region": "US",
    "save_dir": "reports",
    "color": True,
}


def _first_file() -> Path:
    env_path = os.environ.get("SPECTER_CONFIG")
    if env_path:
        return Path(env_path).expanduser()
    candidates = [
        Path.cwd() / ".specter.json",
        Path.home() / ".specter" / "config.json",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    # Default to a project-local file rather than writing outside the workspace.
    return candidates[0]


def load_env_file(path: Path | None = None) -> list[str]:
    """Read KEY=VALUE pairs from .env / .env.local into os.environ.

    Existing environment variables always win, so a real CI variable or a shell
    export is never overwritten by a stale file.
    """
    loaded: list[str] = []
    candidates = [path] if path else [Path.cwd() / ".env", Path.cwd() / ".env.local"]
    for candidate in candidates:
        if candidate is None or not candidate.exists():
            continue
        try:
            lines = candidate.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            entry = line.strip()
            if not entry or entry.startswith("#") or "=" not in entry:
                continue
            key, _, value = entry.partition("=")
            key = key.strip().removeprefix("export ").strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value
                loaded.append(key)
    return loaded


class Config:
    """Loaded settings with environment overrides and safe persistence."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path).expanduser() if path else _first_file()
        self._file_data: dict[str, Any] = {}
        self._runtime: dict[str, Any] = {}
        load_env_file()
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self._file_data = raw
        except (OSError, ValueError):
            self._file_data = {}

    def get(self, key: str, default: Any = None) -> Any:
        spec = KEY_BY_NAME.get(key)
        if spec:
            env_value = os.environ.get(spec.env)
            if env_value:
                return env_value
        if key in self._runtime:
            return self._runtime[key]
        if key in self._file_data:
            return self._file_data[key]
        if key in DEFAULTS:
            return DEFAULTS[key]
        return default

    def set_runtime(self, key: str, value: Any) -> None:
        """Override a setting for this process without writing it to disk."""
        self._runtime[key] = value

    def set(self, key: str, value: Any) -> Path:
        self._file_data[key] = value
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(self._file_data, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return self.path

    def masked(self, key: str) -> str:
        value = self.get(key)
        if not value:
            return "not set"
        spec = KEY_BY_NAME.get(key)
        if spec and not spec.secret:
            return str(value)
        text = str(value)
        if len(text) <= 8:
            return "*" * len(text)
        return f"{text[:4]}…{text[-4:]}"

    def has(self, key: str) -> bool:
        return bool(self.get(key))

    def summary(self) -> list[tuple[str, str, str]]:
        rows = []
        for spec in KEYS:
            rows.append((spec.label, self.masked(spec.key), spec.help))
        return rows

    @property
    def timeout(self) -> int:
        try:
            return max(3, int(self.get("timeout")))
        except (TypeError, ValueError):
            return int(DEFAULTS["timeout"])

    @property
    def workers(self) -> int:
        try:
            return max(1, min(24, int(self.get("workers"))))
        except (TypeError, ValueError):
            return int(DEFAULTS["workers"])

    @property
    def save_dir(self) -> Path:
        return Path(str(self.get("save_dir") or DEFAULTS["save_dir"]))
