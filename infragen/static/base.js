// Shared front-end helpers. No framework: small, auditable, offline.
"use strict";

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

async function api(path, opts = {}) {
  const init = { headers: {}, ...opts };
  if (opts.json !== undefined) {
    init.method = init.method || "POST";
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.json);
  }
  const res = await fetch(path, init);
  const text = await res.text();
  let data;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!res.ok) {
    const msg = (data && data.detail) ? (typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail)) : res.statusText;
    throw new Error(msg);
  }
  return data;
}

function toast(msg, kind = "bad") {
  let box = $("#toast");
  if (!box) { box = document.createElement("div"); box.id = "toast"; document.body.appendChild(box); }
  const d = document.createElement("div");
  d.className = kind;
  d.textContent = msg;
  box.appendChild(d);
  setTimeout(() => d.remove(), 6000);
}

async function busy(btn, fn) {
  const label = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = "Working…";
  try { return await fn(); }
  catch (e) { toast(e.message || String(e)); }
  finally { btn.disabled = false; btn.innerHTML = label; }
}

function fmtDate(s) {
  if (!s) return "—";
  const d = new Date(s);
  return isNaN(d) ? esc(s) : d.toISOString().slice(0, 10);
}

function confBadge(c) {
  const pct = Math.round((c ?? 0) * 100);
  const cls = c >= 0.8 ? "b-ok" : c >= 0.55 ? "b-info" : c >= 0.3 ? "b-warn" : "b-bad";
  return `<span class="badge ${cls}" title="confidence">${pct}%</span>`;
}

function bar(v, max = 1) {
  const pct = Math.max(0, Math.min(100, (v / (max || 1)) * 100));
  return `<div class="bar"><span style="width:${pct}%"></span></div>`;
}

function evidenceCell(ev) {
  if (!ev) return "";
  const src = ev.url ? `<a href="${esc(ev.url)}" target="_blank" rel="noopener noreferrer">${esc(ev.source)}</a>` : esc(ev.source);
  return `${src} <span class="badge b-muted" title="Admiralty grade">${esc(ev.grade || "")}</span>
    <div class="small muted mono" title="SHA-256 of retrieved content">${esc((ev.sha256 || "").slice(0, 16))}${ev.sha256 ? "…" : ""} · ${fmtDate(ev.retrieved_at)}</div>`;
}

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function download(name, content, type = "application/json") {
  const blob = new Blob([content], { type });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

function initTheme() {
  const btn = $("#theme");
  if (!btn) return;
  try { const t = localStorage.getItem("theme"); if (t) document.documentElement.dataset.theme = t; } catch {}
  btn.onclick = () => {
    const dark = matchMedia("(prefers-color-scheme: dark)").matches;
    const cur = document.documentElement.dataset.theme || (dark ? "dark" : "light");
    const next = cur === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("theme", next); } catch {}
    window.dispatchEvent(new Event("themechange"));
  };
}
document.addEventListener("DOMContentLoaded", initTheme);
