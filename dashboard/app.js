"use strict";
// All DOM is built with textContent / createElement; markup strings are never assigned. API data is untrusted.
let token = null, me = null, view = "overview";
const root = document.getElementById("app");

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v === true) el.setAttribute(k, "");
    else if (v !== false && v != null) el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) if (kid != null) el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  return el;
}

async function api(method, path, body) {
  const res = await fetch(path, { method, headers: { ...(token ? { Authorization: "Bearer " + token } : {}),
    ...(body !== undefined ? { "Content-Type": "application/json" } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) { if (res.status === 401 && token) { token = null; me = null; render(); } throw new Error((data && data.error) || res.statusText); }
  return data;
}

const fmtTime = (t) => (t ? new Date(t * 1000).toLocaleString() : "never");
const canWrite = () => me && (me.role === "superadmin" || me.role === "tenant_admin");
let flash = null;
function setFlash(text, kind) { flash = text ? { text, kind } : null; }
const flashBox = () => (flash ? h("div", { class: "msg " + flash.kind, role: "status" }, flash.text) : null);

function table(cols, rows, actions) {
  return h("div", { class: "scroll" }, h("table", {},
    h("thead", {}, h("tr", {}, cols.map((c) => h("th", { class: c.num ? "num" : "" }, c.label)), actions ? h("th", {}, "") : null)),
    h("tbody", {}, rows.length ? rows.map((r) => h("tr", {}, cols.map((c) => h("td", { class: (c.num ? "num " : "") + (c.addr ? "addr" : "") }, c.get(r))), actions ? h("td", {}, actions(r)) : null))
      : h("tr", {}, h("td", { colspan: cols.length + 1 }, "Nothing here yet.")))));
}

function formRow(fields, submitLabel, onSubmit) {
  const inputs = {};
  const row = h("form", { class: "row", onsubmit: async (e) => { e.preventDefault();
    try { await onSubmit(Object.fromEntries(Object.entries(inputs).map(([k, el]) => [k, el.value]))); } catch (err) { setFlash(err.message, "err"); } render(); } },
    fields.map((f) => { const el = f.options ? h("select", {}, f.options.map((o) => h("option", { value: o }, o))) : h("input", { type: f.type || "text", placeholder: f.placeholder || "", required: f.required !== false, autocomplete: "off" });
      inputs[f.name] = el; return h("label", {}, f.label, el); }),
    h("button", { class: "act", type: "submit" }, submitLabel));
  return row;
}

const views = {
  async overview() {
    const [nodes, events, assets] = await Promise.all([api("GET", "/api/nodes"), api("GET", "/api/events?limit=10"), api("GET", "/api/assets")]);
    const now = Date.now() / 1000;
    const state = (n) => (!n.last_seen ? "never" : now - n.last_seen < 120 ? "ok" : now - n.last_seen < 600 ? "warn" : "stale");
    return [h("h2", {}, "Overview"),
      h("div", { class: "panel" }, h("strong", {}, `${nodes.length} node(s), ${assets.length} protected asset(s)`),
        h("div", { class: "beat", role: "img", "aria-label": "Node check-in freshness" }, nodes.map((n) => h("span", { class: state(n), title: `${n.name}: ${state(n)}` }))),
        h("small", {}, "Each bar is a node: tall green checked in within 2 min, amber within 10 min, short red stale, grey never.")),
      h("div", { class: "panel" }, h("h3", {}, "Recent events"), table([{ label: "Time", get: (e) => fmtTime(e.ts) }, { label: "Type", get: (e) => e.type }, { label: "Node", addr: true, get: (e) => e.node_id || "-" }], events))];
  },
  async assets() {
    const assets = await api("GET", "/api/assets");
    return [h("h2", {}, "Protected assets"), flashBox(),
      canWrite() ? h("div", { class: "panel" }, formRow([{ name: "name", label: "Name" }, { name: "kind", label: "Kind", options: ["vps", "game_server", "web", "api", "dns", "other"] }, { name: "address", label: "IP or CIDR", placeholder: "203.0.113.0/24" }].concat(me.role === "superadmin" ? [{ name: "tenant_id", label: "Tenant id", type: "number" }] : []), "Add asset",
        async (v) => { const b = { name: v.name, kind: v.kind, address: v.address }; if (v.tenant_id) b.tenant_id = Number(v.tenant_id); await api("POST", "/api/assets", b); setFlash("Asset added.", "ok"); })) : null,
      h("div", { class: "panel" }, table([{ label: "Name", get: (a) => a.name }, { label: "Kind", get: (a) => a.kind }, { label: "Address", addr: true, get: (a) => a.address }], assets,
        canWrite() ? (a) => h("button", { class: "act danger", onclick: async () => { try { await api("DELETE", "/api/assets/" + a.id); setFlash("Asset deleted.", "ok"); } catch (e) { setFlash(e.message, "err"); } render(); } }, "Delete") : null))];
  },
  async nodes() {
    const nodes = await api("GET", "/api/nodes");
    let policyBox;
    return [h("h2", {}, "Nodes and policy"), flashBox(),
      canWrite() ? h("div", { class: "panel" }, formRow([{ name: "name", label: "Node name" }, { name: "region", label: "Region" }].concat(me.role === "superadmin" ? [{ name: "tenant_id", label: "Tenant id", type: "number" }] : []), "Register node",
        async (v) => { const b = { name: v.name, region: v.region }; if (v.tenant_id) b.tenant_id = Number(v.tenant_id); const r = await api("POST", "/api/nodes", b);
          setFlash(null); window.__creds = r; })) : null,
      window.__creds ? h("div", { class: "panel" }, h("strong", {}, "Node credentials (shown once; copy them now)"),
        h("p", {}, "Node id: ", h("code", {}, window.__creds.node_id)), h("div", { class: "secret" }, h("div", {}, "PROTOCOLZ_NODE_AUTH_TOKEN=" + window.__creds.auth_token), h("div", {}, "PROTOCOLZ_NODE_SIGN_KEY=" + window.__creds.sign_key)),
        h("button", { class: "act", onclick: () => { window.__creds = null; render(); } }, "I have saved them")) : null,
      h("div", { class: "panel" }, table([{ label: "Node", get: (n) => n.name }, { label: "Id", addr: true, get: (n) => n.id }, { label: "Region", get: (n) => n.region }, { label: "Policy v", num: true, get: (n) => n.version }, { label: "Last seen", get: (n) => fmtTime(n.last_seen) }], nodes)),
      canWrite() && nodes.length ? h("div", { class: "panel" }, h("h3", {}, "Set policy"), h("p", {}, "JSON, validated by the server; nodes dry-run and roll back automatically. management_cidrs is required."),
        formRow([{ name: "node", label: "Node", options: nodes.map((n) => n.id) }, { name: "policy", label: "Policy JSON", placeholder: '{"management_cidrs":["203.0.113.0/24"],"services":[]}' }], "Publish policy",
          async (v) => { let p; try { p = JSON.parse(v.policy); } catch { throw new Error("Policy is not valid JSON"); } const r = await api("PUT", `/api/nodes/${v.node}/policy`, { policy: p }); setFlash(`Published version ${r.version}.`, "ok"); })) : null];
  },
  async providers() {
    const ps = await api("GET", "/api/providers");
    return [h("h2", {}, "Mitigation providers"), h("div", { class: "panel" }, table([{ label: "Name", get: (p) => p.name }, { label: "Kind", get: (p) => p.kind }, { label: "Endpoint", addr: true, get: (p) => (p.config ? p.config.url : "(hidden)") }], ps)),
      h("p", {}, "Only the generic signed-webhook adapter is implemented. Register providers via the API (superadmin).")];
  },
  async mitigations() {
    const [ms, ps] = await Promise.all([api("GET", "/api/mitigations"), api("GET", "/api/providers")]);
    return [h("h2", {}, "Upstream mitigations"), flashBox(),
      canWrite() && ps.length ? h("div", { class: "panel" }, formRow([{ name: "provider", label: "Provider", options: ps.map((p) => p.name) }, { name: "target", label: "Target (inside your assets)" }, { name: "reason", label: "Reason", required: false }], "Request mitigation",
        async (v) => { await api("POST", "/api/mitigations", { provider: v.provider, target: v.target, reason: v.reason || "" }); setFlash("Mitigation requested.", "ok"); })) : null,
      h("div", { class: "panel" }, table([{ label: "Time", get: (m) => fmtTime(m.created) }, { label: "Target", addr: true, get: (m) => m.target }, { label: "Provider", get: (m) => m.provider }, { label: "Status", get: (m) => m.status }], ms,
        canWrite() ? (m) => (m.status === "active" ? h("button", { class: "act danger", onclick: async () => { try { await api("DELETE", "/api/mitigations/" + m.id); setFlash("Withdrawn.", "ok"); } catch (e) { setFlash(e.message, "err"); } render(); } }, "Withdraw") : null) : null))];
  },
  async events() {
    const ev = await api("GET", "/api/events?limit=200");
    return [h("h2", {}, "Security events"), h("div", { class: "panel" }, table([{ label: "Time", get: (e) => fmtTime(e.ts) }, { label: "Type", get: (e) => e.type }, { label: "Node", addr: true, get: (e) => e.node_id || "-" }, { label: "Data", addr: true, get: (e) => JSON.stringify(e.data) }], ev))];
  },
  async audit() {
    const rows = await api("GET", "/api/audit?limit=200");
    let integrity = null;
    if (me.role === "superadmin") { const v = await api("GET", "/api/audit/verify"); integrity = h("div", { class: "msg " + (v.intact ? "ok" : "err") }, v.intact ? "Audit hash chain verified intact." : "AUDIT CHAIN BROKEN at row " + v.first_bad_id); }
    return [h("h2", {}, "Audit trail"), integrity, h("div", { class: "panel" }, table([{ label: "Time", get: (r) => fmtTime(r.ts) }, { label: "Actor", get: (r) => r.actor }, { label: "Action", get: (r) => r.action }, { label: "Target", addr: true, get: (r) => r.target || "-" }, { label: "Detail", addr: true, get: (r) => JSON.stringify(r.detail) }], rows))];
  },
};

function loginView() {
  const msg = h("div", { id: "login-msg", role: "alert" });
  const f = h("form", { class: "panel login", onsubmit: async (e) => { e.preventDefault();
    const [u, p, o] = [...f.querySelectorAll("input")].map((i) => i.value);
    try { const r = await api("POST", "/api/login", { username: u, password: p, otp: o || null }); token = r.token; me = await api("GET", "/api/me"); view = "overview"; render(); }
    catch (err) { msg.textContent = err.message; msg.className = "msg err"; } } },
    h("h1", {}, "ProtocolZ console"), h("div", { class: "row" },
      h("label", {}, "Username", h("input", { required: true, autocomplete: "username" })),
      h("label", {}, "Password", h("input", { type: "password", required: true, autocomplete: "current-password" })),
      h("label", {}, "One-time code (if enabled)", h("input", { inputmode: "numeric", autocomplete: "one-time-code" })),
      h("button", { class: "act", type: "submit" }, "Sign in")), msg);
  return f;
}

async function render() {
  if (!token) { root.replaceChildren(loginView()); return; }
  const names = { overview: "Overview", assets: "Assets", nodes: "Nodes", mitigations: "Mitigations", providers: "Providers", events: "Events" };
  if (me.role !== "viewer") names.audit = "Audit";
  const nav = h("nav", {}, h("h1", {}, "ProtocolZ"), Object.entries(names).map(([k, label]) => h("button", { "aria-current": k === view ? "page" : null, onclick: () => { view = k; setFlash(null); render(); } }, label)),
    h("div", { class: "who" }, `${me.username} (${me.role})`), h("button", { onclick: async () => { try { await api("POST", "/api/logout"); } catch {} token = null; me = null; render(); } }, "Sign out"));
  const main = h("main", {});
  root.replaceChildren(h("div", { class: "shell" }, nav, main));
  try { main.append(...(await views[view]()).filter(Boolean)); } catch (err) { main.append(h("div", { class: "msg err" }, err.message)); }
}

render();
