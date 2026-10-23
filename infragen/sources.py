"""Collectors for public infrastructure data.

Each collector returns normalised records plus the :class:`Evidence` for the
retrieval.  Parsing is separated from fetching (``parse_*`` functions) so it
can be tested against recorded responses without network access.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json

from .evidence import Evidence
from .http import FetchError, fetch_json

CRTSH_URL = "https://crt.sh/"
DOH_PROVIDERS = [
    ("Google Public DNS (DoH)", "https://dns.google/resolve", {}),
    ("Cloudflare DNS (DoH)", "https://cloudflare-dns.com/dns-query", {"accept": "application/dns-json"}),
]
RDAP_URL = "https://rdap.org/ip/"
RR_TYPES = {1: "A", 5: "CNAME", 15: "MX", 16: "TXT", 2: "NS", 28: "AAAA", 6: "SOA", 257: "CAA"}


# --------------------------------------------------------------------------- CT

def parse_crtsh(rows: list[dict], domain: str) -> list[dict]:
    """Normalise crt.sh JSON rows, de-duplicating precertificate/leaf pairs."""
    domain = domain.lower().strip(".")
    certs: dict[str, dict] = {}
    for r in rows:
        names = {
            n.strip().lower().lstrip("*.").strip(".")
            for n in str(r.get("name_value", "")).split("\n")
            if n.strip()
        }
        cn = str(r.get("common_name") or "").lower().lstrip("*.")
        if cn:
            names.add(cn)
        if not any(n == domain or n.endswith("." + domain) for n in names):
            continue
        names = sorted(names)
        # crt.sh lists the precertificate and the final certificate separately;
        # they share serial + issuer, so key on that.
        key = f"{r.get('issuer_ca_id')}:{r.get('serial_number') or r.get('id')}"
        rec = certs.get(key)
        if rec is None:
            certs[key] = {
                "id": str(r.get("id")),
                "serial": r.get("serial_number") or "",
                "issuer": _issuer_org(r.get("issuer_name", "")),
                "issuer_dn": r.get("issuer_name", ""),
                "common_name": cn,
                "names": names,
                "not_before": (r.get("not_before") or "")[:19],
                "not_after": (r.get("not_after") or "")[:19],
                "logged_at": (r.get("entry_timestamp") or "")[:19],
            }
        else:
            rec["names"] = sorted(set(rec["names"]) | set(names))
            rec["logged_at"] = min(filter(None, [rec["logged_at"], (r.get("entry_timestamp") or "")[:19]]), default="")
    return sorted(certs.values(), key=lambda c: (c["not_before"], c["id"]))


def _issuer_org(dn: str) -> str:
    parts = dict(
        p.strip().split("=", 1) for p in dn.split(",") if "=" in p
    )
    o = parts.get("O") or parts.get("CN") or dn or "Unknown issuer"
    return o.strip('"')


def ct_certificates(domain: str) -> tuple[list[dict], Evidence]:
    rows, ev = fetch_json(
        CRTSH_URL,
        params={"q": f"%.{domain}", "output": "json"},
        source="crt.sh Certificate Transparency",
        reliability="A",
        credibility=2,
        timeout=90,
    )
    ev.note = "Certificate Transparency log aggregate; issuance is cryptographically logged."
    return parse_crtsh(rows if isinstance(rows, list) else [], domain), ev


# --------------------------------------------------------------------------- DNS

def parse_doh(payload: dict) -> list[dict]:
    out = []
    for a in payload.get("Answer") or []:
        out.append({
            "name": str(a.get("name", "")).rstrip(".").lower(),
            "type": RR_TYPES.get(a.get("type"), str(a.get("type"))),
            "ttl": a.get("TTL"),
            "data": str(a.get("data", "")).rstrip("."),
        })
    return out


def doh_resolve(name: str, rtype: str = "A") -> tuple[list[dict], Evidence]:
    last: Exception | None = None
    for label, url, headers in DOH_PROVIDERS:
        try:
            payload, ev = fetch_json(url, params={"name": name, "type": rtype}, headers=headers,
                                     source=label, reliability="A", credibility=1, ttl=600)
            ev.method = "dns"
            return parse_doh(payload), ev
        except FetchError as exc:
            last = exc
    raise FetchError(f"all DoH providers failed for {name}/{rtype}: {last}")


# --------------------------------------------------------------------------- RDAP

def parse_rdap(payload: dict) -> dict:
    org = payload.get("name") or ""
    for ent in payload.get("entities") or []:
        vcard = (ent.get("vcardArray") or [None, []])[1]
        for item in vcard:
            if item and item[0] == "fn" and "registrant" in (ent.get("roles") or []):
                org = item[3] or org
    cidr = ""
    for c in payload.get("cidr0_cidrs") or []:
        prefix = c.get("v4prefix") or c.get("v6prefix")
        if prefix:
            cidr = f"{prefix}/{c.get('length')}"
            break
    if not cidr and payload.get("startAddress") and payload.get("endAddress"):
        try:
            nets = ipaddress.summarize_address_range(
                ipaddress.ip_address(payload["startAddress"]), ipaddress.ip_address(payload["endAddress"]))
            cidr = str(next(nets))
        except (ValueError, StopIteration):
            cidr = f"{payload['startAddress']} - {payload['endAddress']}"
    return {
        "network": payload.get("handle") or "",
        "provider": org or "Unknown network",
        "cidr": cidr,
        "country": payload.get("country") or "",
    }


def rdap_ip(ip: str) -> tuple[dict, Evidence]:
    payload, ev = fetch_json(RDAP_URL + ip, source="RDAP (Regional Internet Registry)",
                             reliability="A", credibility=2, ttl=86400)
    return parse_rdap(payload), ev


# --------------------------------------------------------------------------- passive DNS import

PDNS_FIELDS = ("rrname", "rrtype", "rdata", "first_seen", "last_seen")


def parse_passive_dns(text: str, source: str = "Imported passive DNS") -> list[dict]:
    """Parse passive DNS exported as CSV or JSON lines.

    Accepted columns / keys: ``rrname, rrtype, rdata, first_seen, last_seen``
    (the COF passive DNS common output format uses ``time_first`` /
    ``time_last`` epoch seconds, which are also accepted).
    """
    from datetime import datetime, timezone

    def ts(v):
        if v in (None, ""):
            return ""
        if isinstance(v, (int, float)) or str(v).isdigit():
            return datetime.fromtimestamp(int(v), timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        return str(v)[:19]

    rows: list[dict] = []
    text = text.strip()
    if not text:
        return rows
    if text.startswith("{") or text.startswith("["):
        items = json.loads(text) if text.startswith("[") else [json.loads(line) for line in text.splitlines() if line.strip()]
    else:
        items = list(csv.DictReader(io.StringIO(text)))
    for it in items:
        rdata = it.get("rdata")
        for value in rdata if isinstance(rdata, list) else [rdata]:
            rows.append({
                "rrname": str(it.get("rrname", "")).rstrip(".").lower(),
                "rrtype": str(it.get("rrtype", "A")).upper(),
                "rdata": str(value or "").rstrip("."),
                "first_seen": ts(it.get("first_seen") or it.get("time_first")),
                "last_seen": ts(it.get("last_seen") or it.get("time_last")),
                "source": source,
            })
    return [r for r in rows if r["rrname"] and r["rdata"]]
