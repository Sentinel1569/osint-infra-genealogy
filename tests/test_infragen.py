from fastapi.testclient import TestClient

from infragen.app import app
from infragen.demo import DEMO_DOMAIN, DemoCollector, _crtsh_rows
from infragen.evidence import admiralty_confidence, combine_confidence
from infragen.genealogy import investigate
from infragen.report import to_markdown
from infragen.sources import parse_crtsh, parse_doh, parse_passive_dns, parse_rdap


def test_crtsh_dedupes_precert_and_leaf():
    rows = _crtsh_rows()
    certs = parse_crtsh(rows, DEMO_DOMAIN)
    assert len(certs) == len(rows) // 2
    assert all(c["names"] for c in certs)


def test_crtsh_strips_wildcards_and_keeps_cohosted_names():
    rows = [{"id": 1, "issuer_ca_id": 1, "issuer_name": "C=US, O=Test CA, CN=X", "common_name": "*.a.example",
             "name_value": "*.a.example\nother.test", "not_before": "2024-01-01T00:00:00",
             "not_after": "2024-04-01T00:00:00", "serial_number": "01", "entry_timestamp": "2024-01-01T00:00:00"}]
    certs = parse_crtsh(rows, "a.example")
    assert certs[0]["names"] == ["a.example", "other.test"]
    assert parse_crtsh(rows, "b.example") == []
    assert certs[0]["issuer"] == "Test CA"


def test_parse_doh_and_rdap():
    recs = parse_doh({"Answer": [{"name": "x.example.", "type": 1, "TTL": 60, "data": "192.0.2.1"},
                                 {"name": "x.example.", "type": 5, "TTL": 60, "data": "y.example."}]})
    assert recs[0] == {"name": "x.example", "type": "A", "ttl": 60, "data": "192.0.2.1"}
    assert recs[1]["type"] == "CNAME" and recs[1]["data"] == "y.example"
    info = parse_rdap({"handle": "H", "name": "Org", "startAddress": "192.0.2.0", "endAddress": "192.0.2.255"})
    assert info["cidr"] == "192.0.2.0/24" and info["provider"] == "Org"


def test_parse_passive_dns_formats():
    csv_rows = parse_passive_dns(
        "rrname,rrtype,rdata,first_seen,last_seen\nA.example.,A,192.0.2.1,2020-01-01,2021-01-01")
    assert csv_rows[0]["rrname"] == "a.example"
    cof = parse_passive_dns('{"rrname":"b.example","rrtype":"A","rdata":["192.0.2.2","192.0.2.3"],'
                            '"time_first":1577836800,"time_last":1609459200}')
    assert [r["rdata"] for r in cof] == ["192.0.2.2", "192.0.2.3"]
    assert cof[0]["first_seen"].startswith("2020-01-01")


def test_demo_genealogy_detects_key_changes():
    r = investigate(DEMO_DOMAIN, collector=DemoCollector())
    kinds = {t["kind"] for t in r["timeline"]}
    assert {"new_name", "ca_change", "hosting_move", "gone"} <= kinds
    titles = " ".join(t["title"] for t in r["timeline"])
    assert "Let's Encrypt → DigiCert Inc" in titles
    assert "staging.northwind.example" in titles
    assert r["summary"]["providers"] == 3
    # every edge with evidence points to a recorded source
    for e in r["edges"]:
        for i in e["evidence"]:
            assert i == -1 or 0 <= i < len(r["sources"])
    # lifespans never run into the future
    assert all(n["last_seen"] <= r["generated_at"].replace("+00:00", "") or not n["last_seen"] for n in r["nodes"])


def test_shared_infrastructure_is_observation_only():
    r = investigate(DEMO_DOMAIN, collector=DemoCollector())
    shared_ip = [x for x in r["shared"] if x["kind"] == "shared_ip"]
    assert shared_ip and all("not evidence of common ownership" in x["note"] for x in shared_ip)
    assert any(x["kind"] == "shared_cert" for x in r["shared"])


def test_markdown_report():
    md = to_markdown(investigate(DEMO_DOMAIN, collector=DemoCollector()))
    assert md.startswith("# Infrastructure genealogy")
    assert "## Sources" in md and "DigiCert" in md


def test_confidence_math():
    assert admiralty_confidence("A", 1) > admiralty_confidence("C", 3) > admiralty_confidence("E", 5)
    one = combine_confidence([("s1", 0.6)])
    same = combine_confidence([("s1", 0.6), ("s1", 0.6)])
    indep = combine_confidence([("s1", 0.6), ("s2", 0.6)])
    assert one < same < indep


def test_api():
    c = TestClient(app)
    assert c.get("/api/health").json()["ok"]
    r = c.post("/api/investigate", json={"domain": DEMO_DOMAIN, "demo": True})
    assert r.status_code == 200 and r.json()["summary"]["names"] > 5
    assert c.post("/api/investigate", json={"domain": "not a domain", "demo": True}).status_code == 422
    assert c.post("/api/investigate", json={"domain": "other.example", "demo": True}).status_code == 422
    md = c.post("/api/report.md", json=r.json())
    assert md.status_code == 200 and "Eras" in md.text
    assert c.get("/").status_code == 200
    assert c.get("/static/vendor/cytoscape.min.js").status_code == 200


def test_offline_live_run_degrades_gracefully(monkeypatch, tmp_path):
    monkeypatch.setenv("OSINT_OFFLINE", "1")
    monkeypatch.setattr("infragen.http.CACHE_DIR", tmp_path)
    r = investigate("example.com")
    assert r["errors"] and r["summary"]["certificates"] == 0
