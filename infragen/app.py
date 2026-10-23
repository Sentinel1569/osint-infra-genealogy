"""FastAPI application: JSON API + single-page UI."""

from __future__ import annotations

import re
from pathlib import Path

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .demo import DEMO_DOMAIN, DemoCollector
from .genealogy import investigate
from .report import to_markdown

STATIC = Path(__file__).parent / "static"
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$")


def _validate(domain: str) -> str:
    d = domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0].strip(".")
    if not DOMAIN_RE.match(d):
        raise HTTPException(422, f"'{domain}' is not a valid domain name")
    return d


def _run(domain: str, demo: bool, passive_dns: str | None = None) -> dict:
    d = _validate(domain)
    if demo and d != DEMO_DOMAIN:
        raise HTTPException(422, f"Demo mode only covers {DEMO_DOMAIN}")
    return investigate(d, collector=DemoCollector() if demo else None, passive_dns_text=passive_dns)


def create_app() -> FastAPI:
    app = FastAPI(title="Infrastructure Genealogy", version=__version__)

    @app.get("/api/health")
    def health():
        return {"ok": True, "version": __version__, "demo_domain": DEMO_DOMAIN}

    @app.get("/api/investigate")
    def api_investigate(domain: str = Query(...), demo: bool = False):
        return _run(domain, demo)

    @app.post("/api/investigate")
    def api_investigate_post(domain: str = Body(...), demo: bool = Body(False), passive_dns: str = Body("")):
        return _run(domain, demo, passive_dns or None)

    @app.get("/api/report.md", response_class=PlainTextResponse)
    def api_report(domain: str = Query(...), demo: bool = False):
        return to_markdown(_run(domain, demo))

    @app.post("/api/report.md", response_class=PlainTextResponse)
    def api_report_render(result: dict = Body(...)):
        try:
            return to_markdown(result)
        except (KeyError, TypeError) as exc:
            raise HTTPException(422, f"not an investigation result: {exc}") from exc

    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html")

    return app


app = create_app()
