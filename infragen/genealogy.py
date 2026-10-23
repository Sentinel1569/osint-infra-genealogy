"""Build the time-aware infrastructure genealogy of a domain.

The output is a graph in which **every node and edge carries a lifespan**
(``first_seen`` / ``last_seen``) and a pointer to the evidence that produced
it, plus a derived timeline of notable changes (new subdomains, certificate
authority migrations, hosting moves, apparent decommissioning).

Interpretation rules are deliberately conservative: a shared IP address or a
shared certificate is recorded as an *observation*; nothing here concludes
that two assets have the same owner.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .evidence import Evidence, utcnow
from .http import FetchError

MAX_NAMES = 60
MAX_RDAP = 30


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def _min(a: str, b: str) -> str:
    return min(x for x in (a, b) if x) if (a or b) else ""


def _max(a: str, b: str) -> str:
    return max(x for x in (a, b) if x) if (a or b) else ""


@dataclass
class Graph:
    nodes: dict[str, dict] = field(default_factory=dict)
    edges: dict[str, dict] = field(default_factory=dict)

    def node(self, nid: str, ntype: str, label: str, first: str = "", last: str = "", **meta) -> dict:
        n = self.nodes.get(nid)
        if n is None:
            n = self.nodes[nid] = {"id": nid, "type": ntype, "label": label,
                                   "first_seen": first, "last_seen": last, "meta": {}}
        else:
            n["first_seen"] = _min(n["first_seen"], first)
            n["last_seen"] = _max(n["last_seen"], last)
        n["meta"].update({k: v for k, v in meta.items() if v not in (None, "")})
        return n

    def edge(self, src: str, dst: str, rel: str, first: str, last: str, evidence: int,
             explanation: str, confidence: float) -> dict:
        eid = f"{src}|{rel}|{dst}"
        e = self.edges.get(eid)
        if e is None:
            e = self.edges[eid] = {"id": eid, "source": src, "target": dst, "rel": rel,
                                   "first_seen": first, "last_seen": last, "evidence": [evidence],
                                   "explanation": explanation, "confidence": confidence, "observations": 1}
        else:
            e["first_seen"] = _min(e["first_seen"], first)
            e["last_seen"] = _max(e["last_seen"], last)
            e["observations"] += 1
            e["confidence"] = max(e["confidence"], confidence)
            if evidence not in e["evidence"]:
                e["evidence"].append(evidence)
        return e


class Investigation:
    """Accumulates observations from collectors into a genealogy."""

    def __init__(self, domain: str):
        self.domain = domain.lower().strip().strip(".")
        self.g = Graph()
        self.sources: list[dict] = []
        self.errors: list[str] = []
        self.certs: list[dict] = []
        self.dns: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
        self.pdns: list[dict] = []
        self.ip_info: dict[str, dict] = {}
        self.now = _now()
        self.g.node(f"domain:{self.domain}", "apex", self.domain)

    # -- evidence registry -------------------------------------------------
    def cite(self, ev: Evidence) -> int:
        self.sources.append(ev.to_dict())
        return len(self.sources) - 1

    def _name_node(self, name: str, first: str, last: str) -> str:
        if name == self.domain:
            nid = f"domain:{name}"
            self.g.node(nid, "apex", name, first, last)
            return nid
        nid = f"name:{name}"
        self.g.node(nid, "subdomain" if name.endswith("." + self.domain) else "external", name, first, last)
        if name.endswith("." + self.domain):
            self.g.edge(f"domain:{self.domain}", nid, "has_subdomain", first, last, -1,
                        "Name is a child of the investigated domain.", 1.0)
        return nid

    # -- ingest ------------------------------------------------------------
    def add_certificates(self, certs: list[dict], ev: Evidence) -> None:
        ref = self.cite(ev)
        self.certs.extend(certs)
        for c in certs:
            cid = f"cert:{c['id']}"
            nb, na = c["not_before"], min(c["not_after"] or c["not_before"], self.now)
            self.g.node(cid, "certificate", f"#{c['id']}", nb, na, issuer=c["issuer"], serial=c["serial"],
                        names=c["names"], logged_at=c["logged_at"])
            iid = f"issuer:{c['issuer']}"
            self.g.node(iid, "issuer", c["issuer"], nb, na)
            self.g.edge(iid, cid, "issued", nb, nb, ref,
                        "CT log entry names this CA as issuer.", ev.confidence)
            for name in c["names"]:
                nid = self._name_node(name, nb, na)
                self.g.edge(cid, nid, "covers", nb, na, ref,
                            "Name appears in the certificate subject/SAN; the CA validated control of it at issuance.",
                            ev.confidence)

    def add_dns(self, name: str, records: list[dict], ev: Evidence) -> None:
        ref = self.cite(ev)
        for r in records:
            self.dns[r["name"] or name][r["type"]].append(r["data"])
        self._link_records(name, records, self.now, self.now, ref, ev.confidence, "Live DNS answer at collection time.")

    def add_passive_dns(self, rows: list[dict], ev: Evidence) -> None:
        ref = self.cite(ev)
        self.pdns.extend(rows)
        for r in rows:
            recs = [{"name": r["rrname"], "type": r["rrtype"], "data": r["rdata"]}]
            self._link_records(r["rrname"], recs, r["first_seen"], r["last_seen"] or self.now, ref,
                               ev.confidence, "Historical resolution observed by a passive DNS sensor.")

    def _link_records(self, qname, records, first, last, ref, conf, why) -> None:
        for r in records:
            name, rtype, data = (r.get("name") or qname), r["type"], r["data"]
            if not name.endswith(self.domain) and rtype != "A" and rtype != "AAAA":
                continue
            src = self._name_node(name, first, last)
            if rtype in ("A", "AAAA"):
                iid = f"ip:{data}"
                self.g.node(iid, "ip", data, first, last, family=rtype)
                self.g.edge(src, iid, "resolves_to", first, last, ref, why, conf)
            elif rtype == "CNAME":
                dst = self._name_node(data, first, last)
                self.g.edge(src, dst, "alias_of", first, last, ref, why, conf)
            elif rtype in ("MX", "NS"):
                host = data.split()[-1].rstrip(".")
                sid = f"svc:{rtype}:{host}"
                self.g.node(sid, "mail" if rtype == "MX" else "nameserver", host, first, last)
                self.g.edge(src, sid, "mail_handled_by" if rtype == "MX" else "delegated_to", first, last, ref, why, conf)

    def add_ip_info(self, ip: str, info: dict, ev: Evidence) -> None:
        ref = self.cite(ev)
        self.ip_info[ip] = info
        ipn = self.g.nodes.get(f"ip:{ip}")
        if not ipn:
            return
        ipn["meta"].update(info)
        pid = f"provider:{info['provider']}"
        self.g.node(pid, "provider", info["provider"], ipn["first_seen"], ipn["last_seen"], country=info.get("country"))
        self.g.edge(f"ip:{ip}", pid, "allocated_to", ipn["first_seen"], ipn["last_seen"], ref,
                    f"RDAP lists this address inside {info.get('cidr') or 'a block'} registered to the provider "
                    "(the registrant of the block, not necessarily the operator of the service).",
                    ev.confidence)

    # -- analysis ----------------------------------------------------------
    def names(self) -> list[str]:
        return sorted({n["label"] for n in self.g.nodes.values() if n["type"] in ("apex", "subdomain")})

    def ips(self) -> list[str]:
        return sorted({n["label"] for n in self.g.nodes.values() if n["type"] == "ip"})

    def timeline(self) -> list[dict]:
        ev: list[dict] = []
        apex_node = self.g.nodes[f"domain:{self.domain}"]
        if self.certs:
            c0 = self.certs[0]
            ev.append({"date": c0["not_before"], "kind": "origin", "title": "Earliest certificate observed",
                       "detail": f"{c0['issuer']} issued #{c0['id']} for {', '.join(c0['names'][:4])}"})
        # New subdomains (first appearance)
        for n in sorted(self.g.nodes.values(), key=lambda x: x["first_seen"] or "9"):
            if n["type"] == "subdomain" and n["first_seen"]:
                ev.append({"date": n["first_seen"], "kind": "new_name", "title": f"New subdomain: {n['label']}",
                           "detail": "First observation in certificate or DNS data."})
        # Apparent decommissioning: no live DNS and last cert long expired
        for n in self.g.nodes.values():
            if n["type"] != "subdomain":
                continue
            live = bool(self.dns.get(n["label"]))
            if not live and n["last_seen"] and n["last_seen"] < self.now[:10]:
                ev.append({"date": n["last_seen"], "kind": "gone", "title": f"Last seen: {n['label']}",
                           "detail": "No current DNS answer and no newer certificate. Possibly decommissioned "
                                     "(or simply moved behind a wildcard certificate)."})
        # Certificate-authority migrations for the apex + www
        apex_certs = [c for c in self.certs if self.domain in c["names"] or f"www.{self.domain}" in c["names"]]
        prev = None
        for c in apex_certs:
            if prev and c["issuer"] != prev:
                ev.append({"date": c["not_before"], "kind": "ca_change", "title": f"CA change: {prev} → {c['issuer']}",
                           "detail": f"Certificate #{c['id']} for the primary site switched issuer."})
            prev = c["issuer"]
        # Hosting moves per name, from resolution history
        by_name: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for r in self.pdns:
            if r["rrtype"] in ("A", "AAAA"):
                by_name[r["rrname"]].append((r["first_seen"], r["rdata"]))
        for name, seq in by_name.items():
            seq.sort()
            prev_ip = prev_prov = None
            for when, ip in seq:
                prov = self.ip_info.get(ip, {}).get("provider")
                if prev_ip and ip != prev_ip:
                    if prov and prev_prov and prov != prev_prov:
                        ev.append({"date": when, "kind": "hosting_move", "title": f"Hosting move: {name}",
                                   "detail": f"{prev_ip} ({prev_prov}) → {ip} ({prov})"})
                    else:
                        ev.append({"date": when, "kind": "ip_change", "title": f"IP change: {name}",
                                   "detail": f"{prev_ip} → {ip}"})
                prev_ip, prev_prov = ip, prov
        _ = apex_node
        return sorted(ev, key=lambda e: e["date"])

    def eras(self) -> list[dict]:
        years: dict[str, dict] = {}

        def yr(y):
            return years.setdefault(y, {"year": y, "certs_issued": 0, "issuers": Counter(),
                                        "providers": Counter(), "active_names": set()})
        for c in self.certs:
            y = yr(c["not_before"][:4])
            y["certs_issued"] += 1
            y["issuers"][c["issuer"]] += 1
            start, end = int(c["not_before"][:4]), int((c["not_after"] or c["not_before"])[:4])
            for year in range(start, min(end, int(self.now[:4])) + 1):
                yr(str(year))["active_names"].update(c["names"])
        for r in self.pdns:
            if r["rrtype"] not in ("A", "AAAA") or not r["first_seen"]:
                continue
            prov = self.ip_info.get(r["rdata"], {}).get("provider", "unattributed")
            for year in range(int(r["first_seen"][:4]), int((r["last_seen"] or self.now)[:4]) + 1):
                yr(str(year))["providers"][prov] += 1
        out = []
        for y in sorted(years):
            d = years[y]
            out.append({"year": y, "certs_issued": d["certs_issued"],
                        "issuers": [k for k, _ in d["issuers"].most_common()],
                        "providers": [k for k, _ in d["providers"].most_common()],
                        "active_names": len(d["active_names"])})
        return out

    def shared_infrastructure(self) -> list[dict]:
        """IPs and certificates shared by several names - observations, not conclusions."""
        out = []
        by_ip = defaultdict(set)
        for e in self.g.edges.values():
            if e["rel"] == "resolves_to":
                by_ip[e["target"]].add(self.g.nodes[e["source"]]["label"])
        for ip, names in by_ip.items():
            if len(names) > 1:
                out.append({"kind": "shared_ip", "value": ip.split(":", 1)[1], "names": sorted(names),
                            "note": "Co-hosted names. Common on shared hosting and CDNs; not evidence of common ownership."})
        for c in self.certs:
            ext = [n for n in c["names"] if not n.endswith(self.domain)]
            if ext:
                out.append({"kind": "shared_cert", "value": c["id"], "names": c["names"],
                            "note": "Certificate also covers names outside this domain."})
        return out

    def subdomain_table(self) -> list[dict]:
        rows = []
        cert_count = Counter(n for c in self.certs for n in c["names"])
        for name in self.names():
            nid = f"domain:{name}" if name == self.domain else f"name:{name}"
            n = self.g.nodes[nid]
            live = self.dns.get(name, {})
            rows.append({"name": name, "first_seen": n["first_seen"], "last_seen": n["last_seen"],
                         "certificates": cert_count.get(name, 0),
                         "live": {k: sorted(set(v)) for k, v in live.items()},
                         "status": "live" if live else ("historical" if n["last_seen"] < self.now else "unresolved")})
        return rows

    def to_dict(self) -> dict:
        nodes = list(self.g.nodes.values())
        dates = [d for n in nodes for d in (n["first_seen"], n["last_seen"]) if d]
        providers = {n["label"] for n in nodes if n["type"] == "provider"}
        issuers = {n["label"] for n in nodes if n["type"] == "issuer"}
        return {
            "domain": self.domain,
            "generated_at": utcnow(),
            "summary": {
                "names": len(self.names()), "certificates": len(self.certs), "issuers": len(issuers),
                "ips": len(self.ips()), "providers": len(providers),
                "first_seen": min(dates) if dates else "", "last_seen": max(dates) if dates else "",
            },
            "nodes": nodes,
            "edges": list(self.g.edges.values()),
            "timeline": self.timeline(),
            "eras": self.eras(),
            "subdomains": self.subdomain_table(),
            "certificates": self.certs,
            "ips": [{"ip": ip, **self.ip_info.get(ip, {})} for ip in self.ips()],
            "shared": self.shared_infrastructure(),
            "sources": self.sources,
            "errors": self.errors,
        }


# --------------------------------------------------------------------------- orchestration

class LiveCollector:
    from . import sources as _src

    def certificates(self, domain):
        return self._src.ct_certificates(domain)

    def resolve(self, name, rtype):
        return self._src.doh_resolve(name, rtype)

    def rdap(self, ip):
        return self._src.rdap_ip(ip)

    def passive_dns(self, domain):
        return None


def investigate(domain: str, *, collector=None, passive_dns_text: str | None = None,
                resolve: bool = True, max_names: int = MAX_NAMES) -> dict:
    """Run a full collection and return the genealogy as a dict."""
    from .sources import parse_passive_dns

    collector = collector or LiveCollector()
    inv = Investigation(domain)

    try:
        certs, ev = collector.certificates(inv.domain)
        inv.add_certificates(certs, ev)
    except FetchError as exc:
        inv.errors.append(f"Certificate Transparency: {exc}")

    pd = collector.passive_dns(inv.domain)
    if pd:
        inv.add_passive_dns(*pd)
    if passive_dns_text:
        rows = parse_passive_dns(passive_dns_text)
        inv.add_passive_dns(rows, Evidence(source="Analyst-imported passive DNS", method="file",
                                           reliability="B", credibility=2,
                                           sha256=__import__("hashlib").sha256(passive_dns_text.encode()).hexdigest()))

    if resolve:
        for rtype in ("A", "AAAA", "MX", "NS"):
            try:
                inv.add_dns(inv.domain, *collector.resolve(inv.domain, rtype))
            except FetchError as exc:
                inv.errors.append(f"DNS {inv.domain}/{rtype}: {exc}")
        for name in [n for n in inv.names() if n != inv.domain][:max_names]:
            for rtype in ("A", "CNAME"):
                try:
                    recs, ev = collector.resolve(name, rtype)
                    if recs:
                        inv.add_dns(name, recs, ev)
                except FetchError as exc:
                    inv.errors.append(f"DNS {name}/{rtype}: {exc}")
                    break

    for ip in inv.ips()[:MAX_RDAP]:
        try:
            info, ev = collector.rdap(ip)
            inv.add_ip_info(ip, info, ev)
        except FetchError as exc:
            inv.errors.append(f"RDAP {ip}: {exc}")
    return inv.to_dict()
