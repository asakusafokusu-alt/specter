"""Username sweep across public profile endpoints."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from functools import lru_cache
from html import unescape
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote

from .. import images
from ..config import Config
from ..http import HttpClient, HttpResult
from ..models import (
    BLOCKED,
    ERROR,
    FOUND,
    MANUAL,
    NOT_FOUND,
    UNKNOWN,
    Finding,
    ImageRef,
)

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,38}$")
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


@lru_cache(maxsize=4)
def load_sites(path: str | None = None) -> list[dict[str, Any]]:
    target = Path(path) if path else DATA_DIR / "sites.json"
    data = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("sites.json must contain a list")
    return data


def validate_username(username: str) -> str:
    candidate = username.strip().lstrip("@")
    if not USERNAME_RE.match(candidate):
        raise ValueError(
            "Username must be 1-39 characters: letters, numbers, dot, dash or underscore."
        )
    return candidate


def _value(data: Any, path: str | None) -> Any:
    if not path:
        return data
    current = data
    for part in path.split("."):
        if current is None:
            return None
        if isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _fmt(value: Any, username: str) -> str:
    if isinstance(value, str):
        return value.replace("{u}", username)
    return str(value)


def _render_template(spec: dict[str, Any], username: str) -> dict[str, Any]:
    rendered: dict[str, Any] = {}
    for key, value in spec.items():
        if isinstance(value, str):
            rendered[key] = value.replace("{u}", username)
        elif isinstance(value, list):
            rendered[key] = [
                item.replace("{u}", username) if isinstance(item, str) else item
                for item in value
            ]
        elif isinstance(value, dict):
            rendered[key] = {
                key2: (val.replace("{u}", username) if isinstance(val, str) else val)
                for key2, val in value.items()
            }
        else:
            rendered[key] = value
    return rendered


def _clean(text: str) -> str:
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", text)).split())


def _page_title(text: str) -> str | None:
    match = TITLE_RE.search(text)
    if not match:
        return None
    cleaned = _clean(match.group(1))
    return cleaned or None


def _result(
    site: dict[str, Any],
    status: str,
    username: str,
    *,
    url: str | None = None,
    title: str | None = None,
    detail: str | None = None,
    data: dict[str, Any] | None = None,
    images_found: list[ImageRef] | None = None,
    elapsed: int | None = None,
    confidence: str = "high",
) -> Finding:
    return Finding(
        source=site["name"],
        category="Username",
        status=status,
        url=url or site["url"].replace("{u}", quote(username, safe="")),
        title=title,
        detail=detail,
        data=data or {},
        images=images_found or [],
        confidence=confidence,
        elapsed_ms=elapsed,
    )


def _image_ref(
    value: Any,
    username: str,
    page_url: str | None,
    kind: str = "profile",
) -> ImageRef | None:
    if value in (None, ""):
        return None
    absolute = images.absolute_image_url(str(value), page_url or "")
    if not absolute:
        return None
    return ImageRef(url=absolute, alt=username, kind=kind, page_url=page_url)


def _page_images(
    site: dict[str, Any],
    payload: Any,
    username: str,
    page_url: str | None,
    http: HttpClient,
) -> list[ImageRef]:
    kind = site.get("image_kind", "profile")
    value = _value(payload, site.get("image")) if site.get("image") else None
    if not value and site.get("image_template") and site.get("image_value"):
        dynamic = _value(payload, site["image_value"])
        if dynamic not in (None, ""):
            value = _fmt(site["image_template"], str(dynamic))
    if not value and site.get("image_api"):
        subject = _value(payload, site.get("image_api_id")) if site.get("image_api_id") else username
        endpoint = _fmt(site["image_api"], str(subject))
        response = http.get(endpoint)
        if response.ok:
            value = _value(response.json(), site.get("image_api_value"))
    image = _image_ref(value, username, page_url, kind=kind)
    return [image] if image else []


def _page_meta(
    response: HttpResult, page_url: str | None, username: str
) -> tuple[str | None, str | None, list[ImageRef]]:
    meta = images.extract_meta(response.text or "", page_url or response.url or "")
    image = _image_ref(meta.get("image"), username, page_url, kind="profile")
    return meta.get("title"), meta.get("description"), ([image] if image else [])


DATE_LABELS = {"created", "joined", "seen", "updated", "member since"}


def _enrich(site: dict[str, Any], payload: Any, username: str) -> dict[str, Any]:
    enriched: dict[str, Any] = {}
    for label, path in site.get("enrich", {}).items():
        value = _value(payload, path)
        if value in (None, "", [], {}):
            continue
        if label in DATE_LABELS and isinstance(value, (int, float)) and value > 1_000_000_000:
            seconds = value / 1000 if value > 10**12 else value
            try:
                value = datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%d")
            except (OverflowError, OSError, ValueError):
                pass
        enriched[label] = value
    return enriched


def _check_site(site: dict[str, Any], username: str, http: HttpClient) -> Finding:
    if site.get("check") == "manual":
        return _result(
            site,
            MANUAL,
            username,
            detail=site.get("note", "Open this profile manually to verify."),
        )

    request = site.get("request") or site["url"]
    request = request.replace("{u}", quote(username, safe=""))
    method = "POST" if site.get("check") == "post_json" else "GET"
    body = site.get("body")
    if body:
        body = _render_template(body, username)

    response = http.request(
        method,
        request,
        json_body=body if method == "POST" else None,
        headers={"Accept": "application/json"} if site.get("check") in ("json", "post_json") else None,
    )

    if response.error:
        return _result(site, ERROR, username, detail=response.error, elapsed=response.elapsed_ms)
    if response.status in (404, 410) and site.get("check") in ("status", "json", "post_json", "marker", "title", "steam"):
        return _result(
            site,
            NOT_FOUND,
            username,
            detail="No profile at this URL.",
            elapsed=response.elapsed_ms,
        )
    if response.blocked:
        return _result(
            site,
            BLOCKED,
            username,
            detail=f"Automated checks blocked (HTTP {response.status}). Open the profile manually.",
            elapsed=response.elapsed_ms,
        )

    check = site.get("check")
    if check in ("json", "post_json"):
        payload = response.json()
        if payload is None:
            if response.text.strip().lower() in ("null", "[]", "{}", ""):
                return _result(site, NOT_FOUND, username, elapsed=response.elapsed_ms)
            return _result(
                site,
                ERROR,
                username,
                detail=f"Unreadable JSON response (HTTP {response.status}).",
                elapsed=response.elapsed_ms,
            )
        any_paths = site.get("json_any", [])
        if any_paths and not any(_value(payload, path) not in (None, "", [], {}) for path in any_paths):
            return _result(site, NOT_FOUND, username, elapsed=response.elapsed_ms)
        for condition in site.get("json_equals", []):
            actual = _value(payload, condition["path"])
            if actual is None or str(actual).lower() != str(condition["value"]).replace("{u}", username).lower():
                return _result(site, NOT_FOUND, username, elapsed=response.elapsed_ms)
        data = _enrich(site, payload, username)
        title = (
            data.get("name")
            or data.get("full name")
            or data.get("display name")
            or data.get("username")
            or None
        )
        url = _value(payload, site.get("url_from", "")) or site["url"].replace("{u}", quote(username, safe=""))
        page_url = url if isinstance(url, str) else None
        return _result(
            site,
            FOUND,
            username,
            url=page_url,
            title=str(title) if title else None,
            data=data,
            images_found=_page_images(site, payload, username, page_url, http),
            elapsed=response.elapsed_ms,
        )

    if check == "status":
        expected = site.get("expect", [200])
        missing = site.get("missing", [404])
        absent = _fmt(site.get("absent", ""), username).lower()
        if absent and absent in response.text.lower():
            return _result(site, NOT_FOUND, username, elapsed=response.elapsed_ms)
        if response.status in missing:
            return _result(site, NOT_FOUND, username, elapsed=response.elapsed_ms)
        if response.status in expected:
            page_url = site["url"].replace("{u}", quote(username, safe=""))
            meta_title, description, found_images = _page_meta(response, page_url, username)
            return _result(
                site,
                FOUND,
                username,
                title=meta_title or _page_title(response.text),
                data={"description": description} if description else {},
                images_found=found_images,
                elapsed=response.elapsed_ms,
            )
        return _result(
            site,
            UNKNOWN,
            username,
            detail=f"Unexpected HTTP {response.status}.",
            elapsed=response.elapsed_ms,
        )

    if check == "marker":
        marker = _fmt(site.get("marker", ""), username).lower()
        if not marker:
            return _result(site, UNKNOWN, username, elapsed=response.elapsed_ms)
        if marker in response.text.lower():
            page_url = site["url"].replace("{u}", quote(username, safe=""))
            meta_title, description, found_images = _page_meta(response, page_url, username)
            return _result(
                site,
                FOUND,
                username,
                title=meta_title or _page_title(response.text),
                data={"description": description} if description else {},
                images_found=found_images,
                elapsed=response.elapsed_ms,
            )
        return _result(site, NOT_FOUND, username, elapsed=response.elapsed_ms)

    if check == "title":
        title = _page_title(response.text) or ""
        marker = _fmt(site.get("title_marker", ""), username)
        if marker and marker.lower() in title.lower():
            page_url = site["url"].replace("{u}", quote(username, safe=""))
            meta = images.extract_meta(response.text, page_url)
            image = _image_ref(meta.get("image"), username, page_url)
            return _result(
                site,
                FOUND,
                username,
                title=meta.get("title") or title,
                data={"description": meta.get("description")} if meta.get("description") else {},
                images_found=[image] if image else [],
                elapsed=response.elapsed_ms,
            )
        return _result(site, NOT_FOUND, username, elapsed=response.elapsed_ms)

    if check == "steam":
        try:
            root = ET.fromstring(response.text)
        except ET.ParseError:
            return _result(
                site,
                UNKNOWN,
                username,
                detail="Could not parse the Steam profile XML.",
                elapsed=response.elapsed_ms,
            )
        if root.find("error") is not None:
            return _result(site, NOT_FOUND, username, elapsed=response.elapsed_ms)
        steam_id = (root.findtext("steamID64") or "").strip()
        if not steam_id:
            return _result(site, NOT_FOUND, username, elapsed=response.elapsed_ms)
        data = {
            "steam id": steam_id,
            "persona": (root.findtext("steamID") or "").strip(),
            "state": (root.findtext("onlineState") or "").strip(),
            "location": (root.findtext("location") or "").strip(),
            "member since": (root.findtext("memberSince") or "").strip(),
            "profile state": (root.findtext("privacyState") or "").strip(),
            "avatar": (root.findtext("avatarFull") or "").strip(),
        }
        data = {key: value for key, value in data.items() if value}
        page_url = site["url"].replace("{u}", quote(username, safe=""))
        image = _image_ref(data.get("avatar"), username, page_url)
        return _result(
            site,
            FOUND,
            username,
            title=data.get("persona"),
            data=data,
            images_found=[image] if image else [],
            elapsed=response.elapsed_ms,
        )

    return _result(site, UNKNOWN, username, detail="Unsupported check type.", elapsed=response.elapsed_ms)


def investigate_username(
    username: str,
    http: HttpClient,
    config: Config,
    *,
    only: list[str] | None = None,
    exclude: list[str] | None = None,
    workers: int | None = None,
    on_result: Callable[[Finding], None] | None = None,
) -> list[Finding]:
    """Check a username across every configured platform concurrently."""
    username = validate_username(username)
    sites = load_sites()
    if only:
        wanted = {name.lower() for name in only}
        sites = [site for site in sites if site["name"].lower() in wanted]
    if exclude:
        unwanted = {name.lower() for name in exclude}
        sites = [site for site in sites if site["name"].lower() not in unwanted]
    if not sites:
        return [
            Finding(
                source="username",
                category="Username",
                status=ERROR,
                detail="No platforms matched the requested filters.",
            )
        ]

    results: list[Finding] = []
    total_workers = max(1, min(workers or config.workers, len(sites)))

    def task(site: dict[str, Any]) -> Finding:
        try:
            return _check_site(site, username, http)
        except Exception as exc:  # noqa: BLE001 - a module must never crash the scan
            return _result(site, ERROR, username, detail=f"{type(exc).__name__}: {exc}")

    with ThreadPoolExecutor(max_workers=total_workers) as executor:
        futures = {executor.submit(task, site): site for site in sites}
        for future in as_completed(futures):
            finding = future.result()
            results.append(finding)
            if on_result:
                try:
                    on_result(finding)
                except Exception:
                    pass

    order = {FOUND: 0, MANUAL: 1, UNKNOWN: 2, BLOCKED: 3, ERROR: 4, NOT_FOUND: 5}
    results.sort(key=lambda f: (order.get(f.status, 9), f.source.lower()))
    return results
