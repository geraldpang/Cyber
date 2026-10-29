// Cloudflare Pages Function: /api/incidents
// Stores Cyber Incident Management records and the escalation party settings in the D1 database bound as "DB".
// Incident records are restricted information, so every request (read and write) needs sign-in:
// the shared editor ID and password (ADMIN_USER and ADMIN_PASSWORD secrets on the Pages project, never in page code),
// or Cloudflare Access if ACCESS_TEAM_DOMAIN and ACCESS_AUD are set. If neither is configured, access is refused.
//
// GET  /api/incidents                         all incidents (with their data) and the escalation parties
// POST /api/incidents { action: "save", incident, version }      create or update one incident.
//        version is the version the page last loaded (0 for a new incident). A mismatch returns 409 with the
//        stored copy, so two people editing the same incident never silently overwrite each other.
// POST /api/incidents { action: "delete", id }                    permanently delete one incident
// POST /api/incidents { action: "saveParties", parties }          replace the escalation party list
//
// The tables are created automatically on first use (CREATE TABLE IF NOT EXISTS). Every save and delete is
// written to incident_audit with who did it and when.

const ID_RE = /^INC-[A-Za-z0-9-]{1,40}$/;
const PARTY_ID_RE = /^[A-Za-z0-9:_-]{1,40}$/;
const MAX_DATA = 512 * 1024;
const CLOCKS = new Set(["aware", "sociRel", "sociSig"]);
const KINDS = new Set(["External", "Internal"]);

let tablesReady = false;
async function ensureTables(db) {
  if (tablesReady) return;
  await db.batch([
    db.prepare("CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, ref TEXT, title TEXT, stage TEXT, data TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, created_by TEXT, updated_at TEXT NOT NULL, updated_by TEXT)"),
    db.prepare("CREATE TABLE IF NOT EXISTS incident_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL, updated_by TEXT)"),
    db.prepare("CREATE TABLE IF NOT EXISTS incident_audit (n INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT, action TEXT NOT NULL, ref TEXT, at TEXT NOT NULL, by TEXT)"),
  ]);
  tablesReady = true;
}

export async function onRequestGet({ request, env }) {
  const auth = await verifyAccess(request, env);
  if (!auth.ok) return json({ error: auth.msg }, auth.status);
  if (!env.DB) return json({ error: "The D1 database is not bound to this Pages project as DB." }, 500);
  try {
    await ensureTables(env.DB);
    const [inc, set] = await env.DB.batch([
      env.DB.prepare("SELECT id, data, version, created_at, created_by, updated_at, updated_by FROM incidents ORDER BY created_at DESC"),
      env.DB.prepare("SELECT value, updated_at, updated_by FROM incident_settings WHERE key = 'parties'"),
    ]);
    const incidents = [];
    for (const r of inc.results) {
      try { incidents.push({ id: r.id, data: JSON.parse(r.data), version: r.version, created_at: r.created_at, created_by: r.created_by || "", updated_at: r.updated_at, updated_by: r.updated_by || "" }); } catch { /* skip a damaged row */ }
    }
    const p = set.results[0];
    let parties = null;
    if (p) { try { parties = JSON.parse(p.value); } catch { parties = null; } }
    return json({ user: auth.email || "", incidents, parties, parties_updated_at: p ? p.updated_at : null, parties_updated_by: p ? p.updated_by || "" : "" });
  } catch {
    return json({ error: "The incident records could not be read." }, 500);
  }
}

export async function onRequestPost({ request, env }) {
  const auth = await verifyAccess(request, env);
  if (!auth.ok) return json({ error: auth.msg }, auth.status);
  if (!env.DB) return json({ error: "The D1 database is not bound to this Pages project as DB." }, 500);
  const raw = await request.text();
  if (raw.length > MAX_DATA + 4096) return json({ error: "That incident record is too large to save." }, 413);
  let body;
  try { body = JSON.parse(raw); } catch { return json({ error: "The request body must be JSON." }, 400); }
  const by = auth.email || "";
  try {
    await ensureTables(env.DB);
    switch (body && body.action) {
      case "save": {
        const x = body.incident;
        if (!x || typeof x !== "object" || Array.isArray(x)) throw bad("Missing incident.");
        const id = String(x.id || "");
        if (!ID_RE.test(id)) throw bad("Invalid incident ID.");
        const data = JSON.stringify(x);
        if (data.length > MAX_DATA) throw bad("That incident record is too large to save (maximum 512 KB).");
        const ov = x.ov && typeof x.ov === "object" ? x.ov : {};
        const ref = short(ov.ref), title = short(ov.title), stage = short(body.stage);
        const want = Number(body.version) || 0;
        const cur = await env.DB.prepare("SELECT data, version, updated_at, updated_by FROM incidents WHERE id = ?").bind(id).first();
        if (cur && cur.version !== want) {
          let stored = null; try { stored = JSON.parse(cur.data); } catch {}
          return json({ error: `This incident was changed by ${cur.updated_by || "someone else"} at ${cur.updated_at} UTC. Reload it to see their changes.`, conflict: true, version: cur.version, data: stored, updated_at: cur.updated_at, updated_by: cur.updated_by || "" }, 409);
        }
        if (!cur && want !== 0) return json({ error: "This incident has been deleted by someone else.", deleted: true }, 409);
        const version = want + 1;
        const q = cur
          ? env.DB.prepare("UPDATE incidents SET ref = ?, title = ?, stage = ?, data = ?, version = ?, updated_at = datetime('now'), updated_by = ? WHERE id = ? AND version = ?").bind(ref, title, stage, data, version, by, id, want)
          : env.DB.prepare("INSERT INTO incidents (id, ref, title, stage, data, version, created_at, created_by, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, 1, datetime('now'), ?, datetime('now'), ?)").bind(id, ref, title, stage, data, by, by);
        const [res] = await env.DB.batch([q, audit(env.DB, id, cur ? "update" : "create", ref, by)]);
        if (cur && !(res.meta && res.meta.changes)) return json({ error: "This incident was changed by someone else while you were saving. Reload it to see their changes.", conflict: true }, 409);
        const row = await env.DB.prepare("SELECT updated_at FROM incidents WHERE id = ?").bind(id).first();
        return json({ ok: true, id, version, updated_at: row ? row.updated_at : "", updated_by: by });
      }
      case "delete": {
        const id = String(body.id || "");
        if (!ID_RE.test(id)) throw bad("Invalid incident ID.");
        const cur = await env.DB.prepare("SELECT ref FROM incidents WHERE id = ?").bind(id).first();
        if (!cur) return json({ ok: true, id, already: true });
        await env.DB.batch([env.DB.prepare("DELETE FROM incidents WHERE id = ?").bind(id), audit(env.DB, id, "delete", cur.ref || "", by)]);
        return json({ ok: true, id });
      }
      case "saveParties": {
        const list = cleanParties(body.parties);
        await env.DB.batch([
          env.DB.prepare("INSERT INTO incident_settings (key, value, updated_at, updated_by) VALUES ('parties', ?, datetime('now'), ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by").bind(JSON.stringify(list), by),
          audit(env.DB, null, "parties", "", by),
        ]);
        return json({ ok: true, parties: list, updated_by: by });
      }
      default:
        throw bad("Unknown action.");
    }
  } catch (e) {
    if (e && e.userError) return json({ error: e.message }, 400);
    return json({ error: "The change could not be saved." }, 500);
  }
}

function audit(db, id, action, ref, by) {
  return db.prepare("INSERT INTO incident_audit (incident_id, action, ref, at, by) VALUES (?, ?, ?, datetime('now'), ?)").bind(id, action, ref || "", by);
}
function cleanParties(v) {
  if (!Array.isArray(v)) throw bad("Missing escalation parties.");
  if (v.length > 60) throw bad("Too many escalation parties (maximum 60).");
  const ids = new Set(), names = new Set();
  return v.map((p, i) => {
    if (!p || typeof p !== "object") throw bad("Escalation party " + (i + 1) + " is not valid.");
    const id = String(p.id || "");
    if (!PARTY_ID_RE.test(id) || ids.has(id)) throw bad("Escalation party " + (i + 1) + " has an invalid ID.");
    ids.add(id);
    const name = String(p.name || "").trim();
    if (!name) throw bad("Escalation party " + (i + 1) + " needs a name.");
    if (name.length > 120) throw bad(`"${name.slice(0, 30)}…" is too long (maximum 120 characters).`);
    if (names.has(name.toLowerCase())) throw bad(`"${name}" is listed twice.`);
    names.add(name.toLowerCase());
    let hours = p.hours === "" || p.hours == null ? "" : Number(p.hours);
    if (hours !== "" && (!Number.isFinite(hours) || hours < 0 || hours > 8760)) throw bad(`The timeframe for "${name}" must be between 0 and 8760 hours, or blank.`);
    return {
      id, name,
      kind: KINDS.has(p.kind) ? p.kind : "External",
      hours,
      clock: CLOCKS.has(p.clock) ? p.clock : "aware",
      how: String(p.how || "").trim().slice(0, 200),
      trigger: String(p.trigger || "").trim().slice(0, 500),
    };
  });
}
function short(v) { return String(v == null ? "" : v).slice(0, 300); }
function bad(msg) { const e = new Error(msg); e.userError = true; return e; }

let certCache = { at: 0, keys: [] };
async function verifyAccess(request, env) {
  if (!(env.ACCESS_TEAM_DOMAIN && env.ACCESS_AUD)) return verifyPassword(request, env);
  const team = String(env.ACCESS_TEAM_DOMAIN || "").replace(/^https?:\/\//, "").replace(/\/+$/, "");
  const aud = String(env.ACCESS_AUD || "").trim();
  if (!team || !aud) return { ok: false, status: 503, msg: "Sign-in is not set up yet. Add the ACCESS_TEAM_DOMAIN and ACCESS_AUD variables to the Pages project." };
  const token = request.headers.get("cf-access-jwt-assertion");
  if (!token) return { ok: false, status: 401, msg: "Sign in through Cloudflare Access to open the incident records." };
  try {
    const [h, p, s] = token.split(".");
    const header = JSON.parse(b64text(h));
    const payload = JSON.parse(b64text(p));
    if (header.alg !== "RS256") throw new Error("alg");
    if (Date.now() - certCache.at > 3600000 || !certCache.keys.some((k) => k.kid === header.kid)) {
      const r = await fetch(`https://${team}/cdn-cgi/access/certs`);
      if (!r.ok) throw new Error("certs");
      certCache = { at: Date.now(), keys: (await r.json()).keys || [] };
    }
    const jwk = certCache.keys.find((k) => k.kid === header.kid);
    if (!jwk) throw new Error("kid");
    const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64bytes(s), new TextEncoder().encode(h + "." + p));
    const audOk = Array.isArray(payload.aud) ? payload.aud.includes(aud) : payload.aud === aud;
    const now = Math.floor(Date.now() / 1000);
    if (!valid || !audOk || !(payload.exp > now) || payload.iss !== `https://${team}`) throw new Error("claims");
    return { ok: true, email: payload.email || "" };
  } catch {
    return { ok: false, status: 403, msg: "Your Cloudflare Access sign-in could not be verified. Reload the page and sign in again." };
  }
}
async function verifyPassword(request, env) {
  const user = String(env.ADMIN_USER || ""), pass = String(env.ADMIN_PASSWORD || "");
  if (!user || !pass) return { ok: false, status: 503, msg: "Sign-in is not set up yet. Add the ADMIN_USER and ADMIN_PASSWORD secrets to the Pages project." };
  const h = request.headers.get("authorization") || "";
  if (!h.startsWith("Basic ")) return { ok: false, status: 401, msg: "Sign in with the editor ID and password." };
  let u = "", p = "";
  try { const d = b64text(h.slice(6).trim()); const i = d.indexOf(":"); u = d.slice(0, i); p = d.slice(i + 1); } catch {}
  const ok = (await same(u, user)) & (await same(p, pass));
  if (!ok) { await new Promise((r) => setTimeout(r, 800)); return { ok: false, status: 401, msg: "The editor ID or password is incorrect." }; }
  return { ok: true, email: u };
}
async function same(a, b) {
  const enc = new TextEncoder();
  const [x, y] = await Promise.all([crypto.subtle.digest("SHA-256", enc.encode(a)), crypto.subtle.digest("SHA-256", enc.encode(b))]);
  const ax = new Uint8Array(x), by = new Uint8Array(y);
  let diff = 0;
  for (let i = 0; i < ax.length; i++) diff |= ax[i] ^ by[i];
  return diff === 0 ? 1 : 0;
}
function b64bytes(s) {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}
function b64text(s) { return new TextDecoder().decode(b64bytes(s)); }

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}
