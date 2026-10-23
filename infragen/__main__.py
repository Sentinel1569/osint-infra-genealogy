"""Command-line interface.

    python -m infragen investigate example.com [--json | --markdown] [--pdns file.csv]
    python -m infragen demo
    python -m infragen serve [--host 127.0.0.1] [--port 8000]
"""

from __future__ import annotations

import argparse
import json
import sys

from .demo import DEMO_DOMAIN, DemoCollector
from .genealogy import investigate
from .report import to_markdown


def _print_summary(r: dict) -> None:
    s = r["summary"]
    print(f"\n  {r['domain']}  ·  {s['first_seen'][:10]} → {s['last_seen'][:10]}")
    print(f"  {s['names']} names · {s['certificates']} certificates · {s['issuers']} issuers · "
          f"{s['ips']} IPs · {s['providers']} providers\n")
    for t in r["timeline"]:
        print(f"  {t['date'][:10]}  {t['title']}")
    if r["errors"]:
        print("\n  Collection gaps:")
        for e in r["errors"]:
            print(f"   - {e}")
    print()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="infragen", description="Digital Infrastructure Genealogy")
    sub = p.add_subparsers(dest="cmd", required=True)
    inv = sub.add_parser("investigate", help="build the genealogy of a domain from live public sources")
    inv.add_argument("domain")
    inv.add_argument("--pdns", help="passive DNS export (CSV or JSON lines) to merge in")
    inv.add_argument("--no-resolve", action="store_true", help="skip live DNS resolution")
    fmt = inv.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true")
    fmt.add_argument("--markdown", action="store_true")
    d = sub.add_parser("demo", help=f"run against the offline synthetic dataset ({DEMO_DOMAIN})")
    d.add_argument("--json", action="store_true")
    d.add_argument("--markdown", action="store_true")
    s = sub.add_parser("serve", help="start the web UI")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--reload", action="store_true")
    a = p.parse_args(argv)

    if a.cmd == "serve":
        import uvicorn
        uvicorn.run("infragen.app:app", host=a.host, port=a.port, reload=a.reload)
        return 0
    if a.cmd == "demo":
        r = investigate(DEMO_DOMAIN, collector=DemoCollector())
    else:
        pdns = open(a.pdns, encoding="utf-8").read() if a.pdns else None
        r = investigate(a.domain, passive_dns_text=pdns, resolve=not a.no_resolve)
    if getattr(a, "json", False):
        json.dump(r, sys.stdout, indent=2)
    elif getattr(a, "markdown", False):
        sys.stdout.write(to_markdown(r))
    else:
        _print_summary(r)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
