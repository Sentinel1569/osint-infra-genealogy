"""Synthetic, fully offline demo dataset.

``northwind.example`` is a fictional organisation on a reserved TLD (RFC 2606)
and every address is from the RFC 5737 documentation ranges, so the demo can
never point at a real person or network.  The data is emitted in the *raw*
shapes the live services return (crt.sh rows, DoH JSON, RDAP JSON) so the demo
exercises exactly the same parsers as a live investigation.
"""

from __future__ import annotations

import zlib
from datetime import date, timedelta

from .evidence import Evidence, sha256_json
from .http import FetchError
from .sources import parse_crtsh, parse_doh, parse_rdap

DEMO_DOMAIN = "northwind.example"
D = DEMO_DOMAIN

# (names, issuer DN, first issuance, last issuance, lifetime days, renew every days)
_CERT_PLAN = [
    ([D, f"www.{D}"], "C=US, O=Let's Encrypt, CN=R3", "2018-03-02", "2021-02-20", 90, 60),
    ([D, f"www.{D}"], "C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1", "2021-03-15", "2026-03-15", 365, 365),
    ([f"mail.{D}"], "C=US, O=Let's Encrypt, CN=R3", "2019-01-10", "2026-08-10", 90, 60),
    ([f"shop.{D}"], "C=US, O=Let's Encrypt, CN=R3", "2019-05-04", "2023-03-01", 90, 60),
    ([f"vpn.{D}"], "C=US, O=Sectigo Limited, CN=Sectigo RSA Domain Validation Secure Server CA", "2020-04-01", "2026-04-01", 365, 365),
    ([f"api.{D}", f"api-v2.{D}"], "C=US, O=Let's Encrypt, CN=R3", "2021-06-01", "2026-09-01", 90, 60),
    ([f"staging.{D}"], "C=US, O=Let's Encrypt, CN=R3", "2021-02-01", "2022-04-01", 90, 60),
    ([f"store.{D}"], "C=US, O=Let's Encrypt, CN=E5", "2023-02-15", "2026-08-15", 90, 60),
    ([f"dev-portal.{D}"], "C=US, O=Google Trust Services, CN=WR1", "2024-05-10", "2026-09-10", 90, 60),
    ([f"auth.{D}", f"sso.{D}"], "C=US, O=Google Trust Services, CN=WR1", "2025-01-20", "2026-09-20", 90, 60),
    ([f"status.{D}", "status.partner-saas.example"], "C=US, O=Let's Encrypt, CN=R11", "2024-08-01", "2026-08-01", 90, 60),
]

_PDNS = [
    (D, "A", "192.0.2.10", "2018-03-01", "2020-06-14"),
    (D, "A", "198.51.100.20", "2020-06-15", "2024-02-01"),
    (D, "A", "203.0.113.40", "2024-02-02", ""),
    (f"www.{D}", "A", "192.0.2.10", "2018-03-01", "2020-06-14"),
    (f"www.{D}", "A", "198.51.100.20", "2020-06-15", "2024-02-01"),
    (f"www.{D}", "A", "203.0.113.40", "2024-02-02", ""),
    (f"shop.{D}", "A", "192.0.2.10", "2019-05-01", "2020-06-14"),
    (f"shop.{D}", "A", "198.51.100.21", "2020-06-15", "2023-03-30"),
    (f"mail.{D}", "A", "192.0.2.25", "2019-01-08", ""),
    (f"vpn.{D}", "A", "198.51.100.50", "2020-04-01", ""),
    (f"staging.{D}", "A", "198.51.100.77", "2021-02-01", "2022-04-20"),
    (f"api.{D}", "A", "198.51.100.30", "2021-06-01", "2024-02-01"),
    (f"api.{D}", "A", "203.0.113.41", "2024-02-02", ""),
    (f"store.{D}", "CNAME", "northwind.shops.saas-store.example", "2023-02-15", ""),
    (f"dev-portal.{D}", "A", "203.0.113.41", "2024-05-10", ""),
    (f"auth.{D}", "A", "203.0.113.60", "2025-01-20", ""),
]

_LIVE = {
    (D, "A"): ["203.0.113.40"], (D, "AAAA"): ["2001:db8:40::1"],
    (D, "MX"): ["10 mail.northwind.example."], (D, "NS"): ["ns1.dns-host.example.", "ns2.dns-host.example."],
    (f"www.{D}", "A"): ["203.0.113.40"], (f"api.{D}", "A"): ["203.0.113.41"],
    (f"mail.{D}", "A"): ["192.0.2.25"], (f"vpn.{D}", "A"): ["198.51.100.50"],
    (f"dev-portal.{D}", "A"): ["203.0.113.41"], (f"auth.{D}", "A"): ["203.0.113.60"],
    (f"sso.{D}", "CNAME"): [f"auth.{D}."], (f"store.{D}", "CNAME"): ["northwind.shops.saas-store.example."],
    (f"status.{D}", "CNAME"): ["northwind.status.partner-saas.example."],
}

_RDAP = {
    "192.0.2.": ("NET-192-0-2-0-1", "Example Shared Hosting LLC", "192.0.2.0", 24, "US"),
    "198.51.100.": ("EXCLOUD-198-51-100", "ExampleCloud Compute", "198.51.100.0", 24, "DE"),
    "203.0.113.": ("EDGE-203-0-113", "Example CDN Edge Network", "203.0.113.0", 24, "NL"),
    "2001:db8:": ("EDGE-V6", "Example CDN Edge Network", "2001:db8::", 32, "NL"),
}

_TYPES = {"A": 1, "AAAA": 28, "CNAME": 5, "MX": 15, "NS": 2}


def _crtsh_rows() -> list[dict]:
    rows, cid, serial = [], 1_000_000, 0x1F00
    for names, issuer, first, last, life, every in _CERT_PLAN:
        d, end = date.fromisoformat(first), date.fromisoformat(last)
        while d <= end:
            cid += 7
            serial += 1
            nb = f"{d.isoformat()}T00:00:00"
            na = f"{(d + timedelta(days=life)).isoformat()}T00:00:00"
            common = {"issuer_ca_id": zlib.crc32(issuer.encode()) % 10000, "issuer_name": issuer, "common_name": names[0],
                      "name_value": "\n".join(names), "not_before": nb, "not_after": na,
                      "serial_number": f"{serial:032x}"}
            # crt.sh returns both the precertificate and the leaf; include both to test de-duplication.
            rows.append({**common, "id": cid, "entry_timestamp": f"{d.isoformat()}T00:05:12.000"})
            rows.append({**common, "id": cid + 1, "entry_timestamp": f"{d.isoformat()}T00:06:40.000"})
            d += timedelta(days=every)
    return rows


def _ev(source: str, payload, rel: str, cred: int, method: str = "demo") -> Evidence:
    return Evidence(source=f"{source} [demo]", url="", sha256=sha256_json(payload), method=method,
                    reliability=rel, credibility=cred, note="Synthetic demo data")


class DemoCollector:
    """Implements the collector interface over the synthetic dataset."""

    def certificates(self, domain):
        if domain != DEMO_DOMAIN:
            raise FetchError(f"demo data only covers {DEMO_DOMAIN}")
        rows = _crtsh_rows()
        return parse_crtsh(rows, domain), _ev("crt.sh Certificate Transparency", rows, "A", 2)

    def resolve(self, name, rtype):
        data = _LIVE.get((name, rtype), [])
        payload = {"Status": 0, "Answer": [{"name": name + ".", "type": _TYPES[rtype], "TTL": 300, "data": v}
                                           for v in data]}
        return parse_doh(payload), _ev("Google Public DNS (DoH)", payload, "A", 1)

    def rdap(self, ip):
        for prefix, (handle, org, start, length, cc) in _RDAP.items():
            if ip.startswith(prefix):
                payload = {"handle": handle, "name": org, "country": cc,
                           "cidr0_cidrs": [{("v6prefix" if ":" in ip else "v4prefix"): start, "length": length}]}
                return parse_rdap(payload), _ev("RDAP (Regional Internet Registry)", payload, "A", 2)
        raise FetchError(f"no RDAP data for {ip}")

    def passive_dns(self, domain):
        rows = [{"rrname": n, "rrtype": t, "rdata": v, "first_seen": f"{a}T00:00:00",
                 "last_seen": f"{b}T00:00:00" if b else "", "source": "demo"} for n, t, v, a, b in _PDNS]
        return rows, _ev("Passive DNS sensor network", rows, "B", 2)
