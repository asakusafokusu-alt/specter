"""Image discovery, safe downloading, terminal previews and report embedding.

Images are treated as untrusted input: only public HTTP(S) hosts are fetched,
responses are size-limited, and failures never interrupt an investigation.
"""

from __future__ import annotations

import base64
import io
import ipaddress
import re
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from html import unescape
from typing import Iterable
from urllib.parse import urljoin, urlsplit

import requests

MAX_BYTES = 2_500_000
MAX_EMBED_BYTES = 900_000
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

_bytes_cache: dict[str, tuple[bytes, str] | None] = {}
_preview_cache: dict[tuple[str, int], list[list[tuple[tuple[int, int, int], tuple[int, int, int]]]] | None] = {}
_data_uri_cache: dict[str, str | None] = {}
_lock = threading.Lock()
_prefetch_lock = threading.Lock()


@lru_cache(maxsize=256)
def _host_is_public(host: str) -> bool:
    if not host:
        return False
    if host.lower() in ("localhost", "localhost.localdomain"):
        return False
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    addresses: list[str] = []
    if literal is not None:
        addresses.append(str(literal))
    else:
        try:
            for info in socket.getaddrinfo(host, None):
                addresses.append(info[4][0])
        except OSError:
            return False
    if not addresses:
        return False
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return False
    return True


def is_allowed(url: str | None) -> bool:
    if not url:
        return False
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return False
    return _host_is_public(parts.hostname)


def _looks_like_image(data: bytes) -> bool:
    return data.startswith(
        (
            b"\x89PNG",
            b"\xff\xd8",
            b"GIF8",
            b"RIFF",
            b"<svg",
            b"<?xml",
            b"BM",
        )
    )


def fetch_bytes(url: str, timeout: int = 10, max_bytes: int = MAX_BYTES) -> tuple[bytes, str] | None:
    """Download an image with SSRF, MIME and size guards. Cached per URL."""
    with _lock:
        if url in _bytes_cache:
            return _bytes_cache[url]
    if not is_allowed(url):
        with _lock:
            _bytes_cache[url] = None
        return None
    try:
        response = requests.get(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "image/*,*/*;q=0.8"},
            timeout=timeout,
            stream=True,
            allow_redirects=True,
        )
        content_type = (response.headers.get("content-type") or "").split(";")[0].strip().lower()
        if not response.ok:
            raise ValueError(f"HTTP {response.status_code}")
        if content_type and not (
            content_type.startswith("image/") or content_type in ("application/octet-stream", "")
        ):
            raise ValueError(f"not an image ({content_type})")
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_content(65536):
            if not chunk:
                continue
            total += len(chunk)
            if total > max_bytes:
                raise ValueError("image too large")
            chunks.append(chunk)
        data = b"".join(chunks)
        if not data or not _looks_like_image(data):
            raise ValueError("unrecognized image data")
        if not content_type.startswith("image/"):
            content_type = "image/svg+xml" if data.lstrip().startswith(b"<svg") else "image/png"
    except (requests.RequestException, ValueError, OSError):
        with _lock:
            _bytes_cache[url] = None
        return None
    result = (data, content_type)
    with _lock:
        _bytes_cache[url] = result
    return result


def _pillow():
    try:
        from PIL import Image  # type: ignore

        return Image
    except ImportError:
        return None


def preview_rows_from_bytes(
    data: bytes, width: int = 24, max_rows: int = 22
) -> list[list[tuple[tuple[int, int, int], tuple[int, int, int]]]] | None:
    """Resize an image to half-block cells: each cell is (top pixel, bottom pixel)."""
    Image = _pillow()
    if Image is None:
        return None
    try:
        with Image.open(io.BytesIO(data)) as source:
            source.seek(0)
            image = source.convert("RGB")
            width = max(8, min(int(width), 60))
            ratio = width / max(1, image.width)
            height = max(2, int(image.height * ratio))
            if height > max_rows * 2:
                height = max_rows * 2
            if height % 2:
                height += 1
            image = image.resize((width, height), Image.LANCZOS)
            pixels = image.load()
            rows = []
            for y in range(0, height, 2):
                rows.append(
                    [
                        (pixels[x, y], pixels[x, y + 1])
                        for x in range(width)
                    ]
                )
            return rows
    except Exception:  # noqa: BLE001 - image decoding must never fail the scan
        return None


def preview_rows(url: str, width: int = 24, max_rows: int = 22):
    key = (url, width)
    with _lock:
        if key in _preview_cache:
            return _preview_cache[key]
    fetched = fetch_bytes(url)
    if not fetched:
        with _lock:
            _preview_cache[key] = None
        return None
    rows = preview_rows_from_bytes(fetched[0], width=width, max_rows=max_rows)
    with _lock:
        _preview_cache[key] = rows
    return rows


def cached_preview(url: str, width: int = 24):
    with _lock:
        return _preview_cache.get((url, width))


def prefetch(urls: Iterable[str], width: int = 24, limit: int = 8) -> None:
    """Warm the preview cache concurrently so rendering never blocks on a download."""
    targets = []
    for url in urls:
        if len(targets) >= limit:
            break
        if url and url not in targets:
            with _lock:
                if (url, width) in _preview_cache:
                    continue
            targets.append(url)
    if not targets:
        return

    def worker(url: str) -> None:
        preview_rows(url, width=width)

    with ThreadPoolExecutor(max_workers=min(6, len(targets))) as executor:
        list(executor.map(worker, targets))


def to_data_uri(url: str, max_width: int = 640, quality: int = 82) -> str | None:
    """Return a small, self-contained data URI for embedding in HTML reports."""
    with _lock:
        if url in _data_uri_cache:
            return _data_uri_cache[url]
    fetched = fetch_bytes(url, max_bytes=MAX_EMBED_BYTES * 3)
    if not fetched:
        with _lock:
            _data_uri_cache[url] = None
        return None
    data, mime = fetched
    Image = _pillow()
    result: str | None = None
    if Image is not None and mime != "image/svg+xml":
        try:
            with Image.open(io.BytesIO(data)) as source:
                source.seek(0)
                image = source.convert("RGB")
                if image.width > max_width:
                    ratio = max_width / image.width
                    image = image.resize(
                        (max_width, max(1, int(image.height * ratio))), Image.LANCZOS
                    )
                buffer = io.BytesIO()
                image.save(buffer, format="JPEG", quality=quality, optimize=True)
                encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
                result = f"data:image/jpeg;base64,{encoded}"
        except Exception:  # noqa: BLE001
            result = None
    if result is None and len(data) <= MAX_EMBED_BYTES:
        encoded = base64.b64encode(data).decode("ascii")
        result = f"data:{mime};base64,{encoded}"
    with _lock:
        _data_uri_cache[url] = result
    return result


_META_PATTERNS = {
    "og:image": (
        r'<meta[^>]+(?:property|name)=["\']og:image(?::url)?["\'][^>]+content=["\']([^"\']+)',
        r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+(?:property|name)=["\']og:image(?::url)?["\']',
    ),
    "twitter:image": (
        r'<meta[^>]+(?:property|name)=["\']twitter:image["\'][^>]+content=["\']([^"\']+)',
        r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+(?:property|name)=["\']twitter:image["\']',
    ),
    "og:description": (
        r'<meta[^>]+(?:property|name)=["\']og:description["\'][^>]+content=["\']([^"\']+)',
        r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+(?:property|name)=["\']og:description["\']',
    ),
    "description": (
        r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)',
        r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']description["\']',
    ),
    "og:title": (
        r'<meta[^>]+(?:property|name)=["\']og:title["\'][^>]+content=["\']([^"\']+)',
        r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+(?:property|name)=["\']og:title["\']',
    ),
}


def _meta_value(html_text: str, name: str) -> str | None:
    for pattern in _META_PATTERNS.get(name, ()):
        match = re.search(pattern, html_text, re.IGNORECASE | re.DOTALL)
        if match:
            value = " ".join(unescape(match.group(1)).split())
            if value:
                return value
    return None


def extract_meta(html_text: str, base_url: str) -> dict[str, str | None]:
    """Extract title, description, OpenGraph image and favicon from a page."""
    if not html_text:
        return {}
    title = None
    match = re.search(r"<title[^>]*>(.*?)</title>", html_text, re.IGNORECASE | re.DOTALL)
    if match:
        title = " ".join(unescape(re.sub(r"<[^>]+>", " ", match.group(1))).split()) or None
    image = (
        _meta_value(html_text, "og:image")
        or _meta_value(html_text, "twitter:image")
    )
    if image:
        image = urljoin(base_url, image)
        if not image.startswith(("http://", "https://")):
            image = None
    description = _meta_value(html_text, "og:description") or _meta_value(html_text, "description")
    favicon = None
    match = re.search(
        r'<link[^>]+rel=["\'][^"\']*(?:icon|apple-touch-icon)[^"\']*["\'][^>]+href=["\']([^"\']+)',
        html_text,
        re.IGNORECASE,
    )
    if not match:
        match = re.search(
            r'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\'][^"\']*icon[^"\']*["\']',
            html_text,
            re.IGNORECASE,
        )
    if match:
        favicon = urljoin(base_url, match.group(1))
        if not favicon.startswith(("http://", "https://")):
            favicon = None
    return {
        "title": title or _meta_value(html_text, "og:title"),
        "description": description,
        "image": image,
        "favicon": favicon,
    }


def absolute_image_url(value: str | None, base_url: str) -> str | None:
    if not value:
        return None
    candidate = unescape(str(value)).strip()
    if candidate.startswith("//"):
        candidate = "https:" + candidate
    elif candidate.startswith("/"):
        candidate = urljoin(base_url, candidate)
    if not candidate.startswith(("http://", "https://")):
        return None
    return candidate
