"""Render an investigation as a self-contained Markdown report."""

from __future__ import annotations


def to_markdown(r: dict) -> str:
    s = r["summary"]
    out = [
        f"# Infrastructure genealogy: `{r['domain']}`",
        "",
        f"_Generated {r['generated_at']} UTC. Observed window {s['first_seen'][:10]} → {s['last_seen'][:10]}._",
        "",
        "## Summary",
        "",
        "| Names | Certificates | Issuers | IPs | Providers |",
        "|---:|---:|---:|---:|---:|",
        f"| {s['names']} | {s['certificates']} | {s['issuers']} | {s['ips']} | {s['providers']} |",
        "",
        "## Eras",
        "",
        "| Year | Certs issued | Active names | Issuers | Hosting |",
        "|---|---:|---:|---|---|",
    ]
    for e in r["eras"]:
        out.append(f"| {e['year']} | {e['certs_issued']} | {e['active_names']} | {', '.join(e['issuers']) or '—'} | "
                   f"{', '.join(e['providers']) or '—'} |")
    out += ["", "## Timeline of changes", ""]
    for t in r["timeline"]:
        out.append(f"- **{t['date'][:10]}** · {t['title']} — {t['detail']}")
    out += ["", "## Names", "", "| Name | First seen | Last seen | Certs | Status | Live records |", "|---|---|---|---:|---|---|"]
    for n in r["subdomains"]:
        live = "; ".join(f"{k}: {', '.join(v)}" for k, v in n["live"].items()) or "—"
        out.append(f"| `{n['name']}` | {n['first_seen'][:10]} | {n['last_seen'][:10]} | {n['certificates']} | "
                   f"{n['status']} | {live} |")
    if r["shared"]:
        out += ["", "## Shared infrastructure (observations, not attributions)", ""]
        for x in r["shared"]:
            out.append(f"- `{x['value']}` ({x['kind']}): {', '.join(x['names'])}. _{x['note']}_")
    out += ["", "## Sources", "", "| # | Source | Retrieved | Grade | SHA-256 |", "|---:|---|---|---|---|"]
    for i, ev in enumerate(r["sources"]):
        src = f"[{ev['source']}]({ev['url']})" if ev.get("url") else ev["source"]
        out.append(f"| {i} | {src} | {ev['retrieved_at']} | {ev['grade']} | `{ev['sha256'][:16]}…` |")
    if r["errors"]:
        out += ["", "## Collection gaps", ""] + [f"- {e}" for e in r["errors"]]
    out += ["", "---", "_Shared IPs or certificates show co-location, not common ownership. "
            "RDAP shows who holds an address block, not who operates the service._", ""]
    return "\n".join(out)
