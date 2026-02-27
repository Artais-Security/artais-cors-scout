from __future__ import annotations

import re
from urllib.parse import urlparse


def normalize_base_url(url: str) -> str:
    url = url.strip()
    if not url:
        return url
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    # Strip fragment
    parsed = urlparse(url)
    clean = parsed._replace(fragment="").geturl()
    return clean.rstrip("/")


def join_url(base: str, path: str) -> str:
    base = base.rstrip("/")
    path = path.strip()
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def host_from_url(url: str) -> str:
    return urlparse(url).hostname or "target"


def safe_lower(s: str | None) -> str:
    return (s or "").strip().lower()
