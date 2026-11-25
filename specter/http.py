"""HTTP layer: shared session, retries, polite rate limiting and block detection."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import requests

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

BLOCK_MARKERS = (
    "just a moment",
    "attention required",
    "cf-challenge",
    "challenge-platform",
    "captcha",
    "access denied",
    "enable javascript and cookies",
    "unusual traffic",
    "anomaly-modal",
)


@dataclass
class HttpResult:
    """A normalized response that never raises for network failures."""

    ok: bool
    status: int | None
    url: str
    text: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    error: str | None = None
    elapsed_ms: int = 0

    @property
    def blocked(self) -> bool:
        if self.status == 429:
            return True
        if self.status in (401, 407):
            return True
        if self.status not in (403, 503):
            return False
        low = self.text.lower()
        return any(marker in low for marker in BLOCK_MARKERS) or self.status == 403

    @property
    def not_found(self) -> bool:
        return self.status == 404

    def json(self, default: Any = None) -> Any:
        if not self.text:
            return default
        try:
            return json.loads(self.text)
        except ValueError:
            return default

    def header(self, name: str, default: str | None = None) -> str | None:
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return default

    def short_error(self) -> str:
        if self.error:
            return self.error
        return f"HTTP {self.status}"


class HttpClient:
    """Thread-local requests sessions with a small GET cache and retry policy."""

    def __init__(
        self,
        timeout: int = 15,
        user_agent: str | None = None,
        proxy: str | None = None,
        retries: int = 2,
        min_interval: float = 0.08,
        cache_ttl: float = 90.0,
    ) -> None:
        self.timeout = timeout
        self.user_agent = user_agent or DEFAULT_UA
        self.proxy = proxy
        self.retries = retries
        self.min_interval = min_interval
        self.cache_ttl = cache_ttl
        self._local = threading.local()
        self._cache: dict[str, tuple[float, HttpResult]] = {}
        self._cache_lock = threading.Lock()
        self._rate_lock = threading.Lock()
        self._last_request = 0.0

    # -- sessions ---------------------------------------------------------
    def _session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is None:
            session = requests.Session()
            session.headers.update(
                {
                    "User-Agent": self.user_agent,
                    "Accept": "text/html,application/json,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "keep-alive",
                }
            )
            if self.proxy:
                session.proxies.update({"http": self.proxy, "https": self.proxy})
            self._local.session = session
        return session

    def _throttle(self) -> None:
        with self._rate_lock:
            now = time.monotonic()
            wait = self.min_interval - (now - self._last_request)
            if wait > 0:
                time.sleep(wait)
            self._last_request = time.monotonic()

    @staticmethod
    def _cache_key(method: str, url: str, params: dict | None) -> str:
        blob = method + "|" + url + "|" + repr(sorted((params or {}).items()))
        return hashlib.sha1(blob.encode("utf-8", "replace")).hexdigest()

    # -- requests ---------------------------------------------------------
    def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        data: Any = None,
        json_body: Any = None,
        headers: dict[str, str] | None = None,
        timeout: int | None = None,
        allow_redirects: bool = True,
        use_cache: bool = True,
    ) -> HttpResult:
        key = self._cache_key(method, url, params)
        if use_cache and method == "GET":
            with self._cache_lock:
                cached = self._cache.get(key)
                if cached and (time.monotonic() - cached[0]) < self.cache_ttl:
                    return cached[1]

        request_timeout = timeout or self.timeout
        last: HttpResult | None = None
        for attempt in range(self.retries + 1):
            self._throttle()
            started = time.monotonic()
            try:
                response = self._session().request(
                    method,
                    url,
                    params=params,
                    data=data,
                    json=json_body,
                    headers=headers,
                    timeout=request_timeout,
                    allow_redirects=allow_redirects,
                )
            except requests.RequestException as exc:
                elapsed = int((time.monotonic() - started) * 1000)
                last = HttpResult(
                    ok=False,
                    status=None,
                    url=url,
                    error=f"{type(exc).__name__}: {exc}",
                    elapsed_ms=elapsed,
                )
                if attempt < self.retries:
                    time.sleep(0.5 * (attempt + 1))
                    continue
                return last

            elapsed = int((time.monotonic() - started) * 1000)
            text = response.text or ""
            result = HttpResult(
                ok=200 <= response.status_code < 300,
                status=response.status_code,
                url=str(response.url),
                text=text,
                headers={k: v for k, v in response.headers.items()},
                elapsed_ms=elapsed,
            )

            retryable = response.status_code in (429, 502, 504) or response.status_code >= 500
            if retryable and attempt < self.retries:
                delay = 0.8 * (attempt + 1)
                retry_after = response.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    delay = min(float(retry_after), 5.0)
                time.sleep(delay)
                last = result
                continue

            if use_cache and method == "GET" and result.ok:
                with self._cache_lock:
                    self._cache[key] = (time.monotonic(), result)
            return result
        return last or HttpResult(False, None, url, error="request failed")

    def get(self, url: str, **kwargs: Any) -> HttpResult:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> HttpResult:
        return self.request("POST", url, **kwargs)

    def get_json(self, url: str, **kwargs: Any) -> tuple[Any, HttpResult]:
        result = self.get(url, **kwargs)
        return result.json(), result

    @staticmethod
    def same_host(url: str, host: str) -> bool:
        try:
            return (urlsplit(url).hostname or "").lower().removeprefix("www.") == host.lower()
        except ValueError:
            return False
