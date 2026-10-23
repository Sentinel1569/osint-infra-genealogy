"use strict";
let R = null, cy = null, dates = [], playing = null;

const TYPE_COLOR = { apex: "--n-apex", subdomain: "--n-sub", external: "--n-ext", certificate: "--n-cert",
  issuer: "--n-issuer", ip: "--n-ip", provider: "--n-prov", mail: "--n-svc", nameserver: "--n-svc" };

async function run(demo) {
  const domain = demo ? "northwind.example" : $("#domain").value.trim();
  if (!domain) { toast("Enter a domain first"); return; }
  $("#domain").value = domain;
  const btn = demo ? $("#demo") : $("#go");
  await busy(btn, async () => {
    R = await api("/api/investigate", { json: { domain, demo, passive_dns: $("#pdns").value } });
    render();
  });
}

function render() {
  const s = R.summary;
  $("#stats").hidden = false;
  $("#exportCard").hidden = false;
  $("#stats").innerHTML = [
    ["Names", s.names], ["Certificates", s.certificates], ["Addresses", s.ips], ["Network owners", s.providers],
  ].map(([l, v]) => `<div class="card stat"><div class="v">${v}</div><div class="l">${l}</div></div>`).join("");
  $("#errors").innerHTML = R.errors.length
    ? `<div class="banner"><b>Collection gaps (${R.errors.length})</b> · ${R.errors.slice(0, 4).map(esc).join(" · ")}${R.errors.length > 4 ? " …" : ""}</div>` : "";
  buildGraph();
  renderTimeline();
  renderEras();
  renderTab("names");
}

// ---------------------------------------------------------------- graph
function elements() {
  const collapse = $("#collapse").checked;
  const nodes = R.nodes.filter((n) => !(collapse && n.type === "certificate"));
  const keep = new Set(nodes.map((n) => n.id));
  const els = nodes.map((n) => ({ data: { id: n.id, label: n.label, type: n.type, first: n.first_seen, last: n.last_seen } }));
  const edges = [];
  if (collapse) {
    const certIssuer = {}, agg = {};
    R.edges.forEach((e) => { if (e.rel === "issued") certIssuer[e.target] = e.source; });
    R.edges.forEach((e) => {
      if (e.rel !== "covers") return;
      const iss = certIssuer[e.source]; if (!iss) return;
      const k = iss + "|" + e.target;
      const a = agg[k] || (agg[k] = { id: "agg|" + k, source: iss, target: e.target, rel: "issued_for", first_seen: e.first_seen, last_seen: e.last_seen, count: 0, evidence: e.evidence, explanation: "CA issued certificate(s) covering this name (certificates collapsed).", confidence: e.confidence });
      a.first_seen = a.first_seen < e.first_seen ? a.first_seen : e.first_seen;
      a.last_seen = a.last_seen > e.last_seen ? a.last_seen : e.last_seen;
      a.count++;
    });
    edges.push(...Object.values(agg));
  }
  R.edges.forEach((e) => { if (keep.has(e.source) && keep.has(e.target)) edges.push(e); });
  edges.forEach((e) => els.push({ data: { id: e.id, source: e.source, target: e.target, rel: e.rel, first: e.first_seen, last: e.last_seen } }));
  return els;
}

function buildGraph() {
  const all = [...R.nodes.flatMap((n) => [n.first_seen, n.last_seen])].filter(Boolean).sort();
  dates = [...new Set(all.map((d) => d.slice(0, 10)))];
  const t = $("#time");
  t.disabled = false; t.min = 0; t.max = dates.length - 1; t.value = dates.length - 1;
  $("#cy").innerHTML = "";
  if (cy) cy.destroy();
  cy = cytoscape({
    container: $("#cy"),
    elements: elements(),
    wheelSensitivity: 0.25,
    style: graphStyle(),
    layout: { name: "cose", animate: false, nodeRepulsion: 9000, idealEdgeLength: 70, padding: 20 },
  });
  cy.on("tap", "node", (ev) => showNode(ev.target.id()));
  cy.on("tap", "edge", (ev) => showEdge(ev.target.id()));
  applyTime();
}

function graphStyle() {
  const text = cssVar("--text"), muted = cssVar("--muted"), border = cssVar("--border");
  const st = [
    { selector: "node", style: { "background-color": muted, label: "data(label)", color: text, "font-size": 9, "text-valign": "bottom", "text-margin-y": 3, width: 14, height: 14, "text-max-width": 120, "text-wrap": "ellipsis" } },
    { selector: "edge", style: { width: 1.2, "line-color": border, "curve-style": "bezier", "target-arrow-shape": "triangle", "target-arrow-color": border, "arrow-scale": 0.7 } },
    { selector: "node[type='apex']", style: { width: 30, height: 30, "font-size": 12, "font-weight": 700 } },
    { selector: "node[type='provider'], node[type='issuer']", style: { shape: "round-rectangle", width: 22, height: 16 } },
    { selector: "node[type='certificate']", style: { shape: "diamond", width: 9, height: 9, label: "" } },
    { selector: "edge[rel='resolves_to']", style: { "line-color": cssVar("--n-ip"), "target-arrow-color": cssVar("--n-ip") } },
    { selector: "edge[rel='alias_of']", style: { "line-style": "dashed" } },
    { selector: ".past", style: { opacity: 0.12 } },
    { selector: ".future", style: { display: "none" } },
    { selector: ":selected", style: { "border-width": 3, "border-color": cssVar("--accent") } },
  ];
  Object.entries(TYPE_COLOR).forEach(([t, v]) => st.push({ selector: `node[type='${t}']`, style: { "background-color": cssVar(v) } }));
  return st;
}

function applyTime() {
  if (!cy) return;
  const all = $("#showAll").checked;
  const d = dates[+$("#time").value] || "";
  $("#timeLabel").textContent = all ? "all time" : d;
  cy.batch(() => cy.elements().forEach((el) => {
    el.removeClass("past future");
    if (all) return;
    const f = (el.data("first") || "").slice(0, 10), l = (el.data("last") || "9999").slice(0, 10);
    if (f && f > d) el.addClass("future");
    else if (l < d) el.addClass("past");
  }));
}

function togglePlay() {
  if (playing) { clearInterval(playing); playing = null; $("#play").textContent = "▶"; return; }
  $("#showAll").checked = false;
  const t = $("#time");
  if (+t.value >= +t.max) t.value = 0;
  $("#play").textContent = "❚❚";
  const step = Math.max(1, Math.round(dates.length / 120));
  playing = setInterval(() => {
    t.value = Math.min(+t.max, +t.value + step);
    applyTime();
    if (+t.value >= +t.max) togglePlay();
  }, 80);
}

function showNode(id) {
  const n = R.nodes.find((x) => x.id === id);
  if (!n) return;
  const rels = R.edges.filter((e) => e.source === id || e.target === id);
  const meta = Object.entries(n.meta || {}).filter(([k]) => k !== "names")
    .map(([k, v]) => `<div>${esc(k)}</div><div class="mono">${esc(Array.isArray(v) ? v.join(", ") : v)}</div>`).join("");
  $("#detail").innerHTML = `
    <div style="font-size:14px;font-weight:650;color:var(--text);word-break:break-all">${esc(n.label)}</div>
    <div class="kv" style="margin:8px 0">
      <div>type</div><div>${esc(n.type)}</div>
      <div>first seen</div><div class="mono">${fmtDate(n.first_seen)}</div>
      <div>last seen</div><div class="mono">${fmtDate(n.last_seen)}</div>${meta}
    </div>
    <div class="small muted">${rels.length} relationship(s)</div>
    <div class="scroll" style="max-height:260px">${rels.slice(0, 60).map((e) => {
      const other = e.source === id ? e.target : e.source;
      const lbl = (R.nodes.find((x) => x.id === other) || {}).label || other;
      return `<div style="padding:4px 0;border-bottom:1px solid var(--border)"><span class="badge b-muted">${esc(e.rel)}</span> ${esc(lbl)}
        <div class="small muted">${fmtDate(e.first_seen)} → ${fmtDate(e.last_seen)} · ${e.observations} obs.</div></div>`;
    }).join("")}</div>`;
}

function showEdge(id) {
  const e = R.edges.find((x) => x.id === id);
  if (!e) { $("#detail").innerHTML = `<div class="small">Aggregated edge (certificates collapsed). Uncheck "Collapse certificates" to inspect each certificate.</div>`; return; }
  const lbl = (nid) => (R.nodes.find((x) => x.id === nid) || {}).label || nid;
  const evs = e.evidence.filter((i) => i >= 0).map((i) => R.sources[i]).filter(Boolean);
  $("#detail").innerHTML = `
    <div style="font-weight:650;color:var(--text)">${esc(lbl(e.source))} <span class="badge b-muted">${esc(e.rel)}</span> ${esc(lbl(e.target))}</div>
    <div class="kv" style="margin:8px 0">
      <div>first seen</div><div class="mono">${fmtDate(e.first_seen)}</div>
      <div>last seen</div><div class="mono">${fmtDate(e.last_seen)}</div>
      <div>confidence</div><div>${confBadge(e.confidence)}</div>
      <div>observations</div><div>${e.observations}</div>
    </div>
    <p class="small" style="color:var(--text)">${esc(e.explanation)}</p>
    ${evs.slice(0, 5).map((ev) => `<div class="small" style="margin-top:6px">${evidenceCell(ev)}</div>`).join("") || '<div class="small muted">Structural (derived from the name hierarchy).</div>'}`;
}

// ---------------------------------------------------------------- panels
function renderTimeline() {
  $("#timeline").innerHTML = R.timeline.length ? R.timeline.map((t, i) => `
    <div class="ev" data-i="${i}"><div class="d">${fmtDate(t.date)}</div>
    <div><div class="t kind-${esc(t.kind)}">${esc(t.title)}</div><div class="small muted">${esc(t.detail)}</div></div></div>`).join("")
    : '<div class="empty">No changes detected.</div>';
  $$("#timeline .ev").forEach((el) => el.onclick = () => {
    const d = R.timeline[+el.dataset.i].date.slice(0, 10);
    let idx = dates.findIndex((x) => x >= d);
    if (idx < 0) idx = dates.length - 1;
    $("#showAll").checked = false;
    $("#time").value = idx;
    applyTime();
    $("#cy").scrollIntoView({ behavior: "smooth", block: "center" });
  });
}

function renderEras() {
  $("#eras").innerHTML = `<table><thead><tr><th>Year</th><th>Certs</th><th>Names</th><th>Issuers</th><th>Network owners</th></tr></thead><tbody>
    ${R.eras.map((e) => `<tr><td class="mono">${e.year}</td><td>${e.certs_issued}</td><td>${e.active_names}</td>
      <td class="chips">${e.issuers.map((x) => `<span>${esc(x)}</span>`).join("") || "—"}</td>
      <td class="chips">${e.providers.map((x) => `<span>${esc(x)}</span>`).join("") || "—"}</td></tr>`).join("")}</tbody></table>`;
}

function renderTab(tab) {
  $$("#tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  const el = $("#tab");
  if (!R) { el.innerHTML = '<div class="empty">No data yet.</div>'; return; }
  if (tab === "names") {
    el.innerHTML = `<table><thead><tr><th>Name</th><th>First seen</th><th>Last seen</th><th>Certs</th><th>Status</th><th>Live records</th></tr></thead><tbody>
      ${R.subdomains.map((n) => `<tr><td class="mono">${esc(n.name)}</td><td>${fmtDate(n.first_seen)}</td><td>${fmtDate(n.last_seen)}</td><td>${n.certificates}</td>
      <td><span class="badge ${n.status === "live" ? "b-ok" : "b-muted"}">${n.status}</span></td>
      <td class="mono small">${Object.entries(n.live).map(([k, v]) => `${k}: ${v.map(esc).join(", ")}`).join("<br>") || "—"}</td></tr>`).join("")}</tbody></table>`;
  } else if (tab === "certs") {
    el.innerHTML = `<table><thead><tr><th>ID</th><th>Issuer</th><th>Not before</th><th>Not after</th><th>Names</th></tr></thead><tbody>
      ${[...R.certificates].reverse().map((c) => `<tr><td class="mono">${esc(c.id)}</td><td>${esc(c.issuer)}</td><td>${fmtDate(c.not_before)}</td><td>${fmtDate(c.not_after)}</td>
      <td class="mono small">${c.names.map(esc).join("<br>")}</td></tr>`).join("")}</tbody></table>`;
  } else if (tab === "ips") {
    el.innerHTML = `<table><thead><tr><th>Address</th><th>Network owner (RDAP)</th><th>Block</th><th>Country</th><th>Handle</th></tr></thead><tbody>
      ${R.ips.map((i) => `<tr><td class="mono">${esc(i.ip)}</td><td>${esc(i.provider || "—")}</td><td class="mono">${esc(i.cidr || "")}</td><td>${esc(i.country || "")}</td><td class="mono">${esc(i.network || "")}</td></tr>`).join("")}</tbody></table>`;
  } else if (tab === "shared") {
    el.innerHTML = R.shared.length ? `<p class="small muted">These are co-location observations. Shared hosting, CDNs and multi-tenant SaaS make them common between unrelated parties; treat them as leads, not attributions.</p>
      <table><thead><tr><th>Kind</th><th>Value</th><th>Names</th><th>Note</th></tr></thead><tbody>
      ${R.shared.map((x) => `<tr><td>${esc(x.kind)}</td><td class="mono">${esc(x.value)}</td><td class="mono small">${x.names.map(esc).join("<br>")}</td><td class="small">${esc(x.note)}</td></tr>`).join("")}</tbody></table>`
      : '<div class="empty">No shared infrastructure observed.</div>';
  } else if (tab === "sources") {
    el.innerHTML = `<table><thead><tr><th>#</th><th>Source</th><th>Method</th><th>Note</th></tr></thead><tbody>
      ${R.sources.map((s, i) => `<tr><td>${i}</td><td>${evidenceCell(s)}</td><td>${esc(s.method)}</td><td class="small">${esc(s.note)}</td></tr>`).join("")}</tbody></table>`;
  }
}

// ---------------------------------------------------------------- wiring
document.addEventListener("DOMContentLoaded", () => {
  $("#go").onclick = () => run(false);
  $("#demo").onclick = () => run(true);
  $("#domain").addEventListener("keydown", (e) => { if (e.key === "Enter") run(false); });
  $("#time").oninput = applyTime;
  $("#showAll").onchange = applyTime;
  $("#collapse").onchange = () => R && buildGraph();
  $("#play").onclick = togglePlay;
  $$("#tabs button").forEach((b) => b.onclick = () => renderTab(b.dataset.tab));
  $("#dlJson").onclick = () => download(`${R.domain}-genealogy.json`, JSON.stringify(R, null, 2));
  $("#dlMd").onclick = async () => {
    const res = await fetch("/api/report.md", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(R) });
    download(`${R.domain}-genealogy.md`, await res.text(), "text/markdown");
  };
  window.addEventListener("themechange", () => cy && cy.style(graphStyle()));
  renderTab("names");
});
