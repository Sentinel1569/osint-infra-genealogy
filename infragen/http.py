"""Polite HTTP client that records provenance for every response.

* Identifies itself with a descriptive User-Agent.
* Caches responses on disk (``.cache/``) so repeated investigations do not
  hammer public services, and so an investigation can be replayed.
* Returns an :class:`Evidence` record alongside the payload, including the
  SHA-256 of the exact bytes received.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from urllib.parse import urlencode

import httpx

from .evidence import Evidence, sha256_bytes, utcnow

USER_AGENT = "InfraGenealogy/1.0 (+defensive OSINT research tool)"
CACHE_DIR = Path(os.environ.get("OSINT_CACHE_DIR", ".cache"))
DEFAULT_TTL = int(os.environ.get("OSINT_CACHE_TTL", "3600"))


class FetchError(RuntimeError):
    pass


def offline() -> bool:
    return os.environ.get("OSINT_OFFLINE", "").lower() in {"1", "true", "yes"}


def _cache_path(key: str) -> Path:
    return CACHE_DIR / f"{sha256_bytes(key)[:32]}.json"


def fetch(
    url: str,
    *,
    params: dict | None = None,
    headers: dict | None = None,
    method: str = "GET",
    json_body=None,
    source: str = "",
    reliability: str = "B",
    credibility: int = 2,
    ttl: int = DEFAULT_TTL,
    timeout: float = 30.0,
) -> tuple[bytes, Evidence]:
    """Fetch ``url`` and return ``(raw_bytes, evidence)``."""
    full = url + ("?" + urlencode(params, doseq=True) if params else "")
    key = f"{method} {full} {json.dumps(json_body, sort_keys=True) if json_body is not None else ''}"
    cp = _cache_path(key)
    if cp.exists() and (ttl < 0 or time.time() - cp.stat().st_mtime < ttl):
        cached = json.loads(cp.read_text())
        ev = Evidence.from_dict(cached["evidence"])
        ev.note = (ev.note + " (served from local cache)").strip()
        return cached["body"].encode("latin-1"), ev
    if offline():
        raise FetchError(f"offline mode: no cached response for {full}")

    h = {"User-Agent": USER_AGENT, **(headers or {})}
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, headers=h) as client:
            resp = client.request(method, url, params=params, json=json_body)
    except httpx.HTTPError as exc:
        raise FetchError(f"{type(exc).__name__} fetching {full}: {exc}") from exc
    if resp.status_code >= 400:
        raise FetchError(f"HTTP {resp.status_code} from {full}")

    body = resp.content
    ev = Evidence(
        source=source or httpx.URL(url).host,
        url=str(resp.url),
        retrieved_at=utcnow(),
        sha256=sha256_bytes(body),
        method="api",
        reliability=reliability,
        credibility=credibility,
    )
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cp.write_text(json.dumps({"evidence": ev.to_dict(), "body": body.decode("latin-1")}))
    except OSError:
        pass
    return body, ev


def fetch_json(url: str, **kw):
    body, ev = fetch(url, **kw)
    try:
        return json.loads(body), ev
    except json.JSONDecodeError as exc:
        raise FetchError(f"invalid JSON from {url}: {exc}") from exc
