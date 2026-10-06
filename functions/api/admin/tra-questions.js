// Cloudflare Pages Function: POST /api/admin/tra-questions
// Edits the TRA question bank in the D1 database bound as "DB".
// Sign-in: a shared editor ID and password, checked against the ADMIN_USER and ADMIN_PASSWORD
// secrets set on the Pages project (never stored in page code). If Cloudflare Access is set up later
// (ACCESS_TEAM_DOMAIN and ACCESS_AUD variables), the Access token is checked instead.
// If neither is configured, editing is refused.

const THREAT_RE = /^T\d{2}$/;
const STATEMENT_RE = /^R\d{2}$/;
const QUESTION_RE = /^[EV]\d{1,2}$/;
const CONTEXTS = ["Safety", "Financial", "Reputation / Political", "Legal", "Engineering / Technical"];
const MAX_TEXT = 1000;

export async function onRequestPost({ request, env }) {
  const auth = await verifyAccess(request, env);
  if (!auth.ok) return json({ error: auth.msg }, auth.status);
  if (!env.DB) return json({ error: "The D1 database is not bound to this Pages project as DB." }, 500);

  let body;
  try { body = await request.json(); } catch { return json({ error: "The request body must be JSON." }, 400); }

  try {
    const known = new Set((await env.DB.prepare("SELECT id FROM threats").all()).results.map((r) => r.id));
    const threats = (list) => {
      if (!Array.isArray(list)) throw bad("threats must be a list of threat IDs.");
      const out = [...new Set(list.map(String))];
      const unknown = out.filter((t) => !THREAT_RE.test(t) || !known.has(t));
      if (unknown.length) throw bad("Unknown threat IDs: " + unknown.join(", "));
      return out;
    };

    switch (body.action) {
      case "updateStatement": {
        const id = String(body.id || "");
        if (!STATEMENT_RE.test(id)) throw bad("Unknown risk statement ID.");
        const event = text(body.event, "Event");
        const hazard = text(body.hazard, "Hazard");
        const ctx = Array.isArray(body.risk_contexts) ? [...new Set(body.risk_contexts.map(String))] : [];
        const badCtx = ctx.filter((c) => !CONTEXTS.includes(c));
        if (badCtx.length) throw bad("Unknown risk contexts: " + badCtx.join(", "));
        if (!ctx.length) throw bad("Choose at least one risk context.");
        const thr = threats(body.threats);
        const exists = await env.DB.prepare("SELECT id FROM risk_statements WHERE id = ?").bind(id).first();
        if (!exists) throw bad("Risk statement " + id + " was not found.");
        await env.DB.batch([
          env.DB.prepare("UPDATE risk_statements SET event = ?, hazard = ?, risk_contexts = ?, updated_at = datetime('now') WHERE id = ?").bind(event, hazard, ctx.join(", "), id),
          env.DB.prepare("DELETE FROM risk_statement_threats WHERE statement_id = ?").bind(id),
          ...thr.map((t) => env.DB.prepare("INSERT INTO risk_statement_threats (statement_id, threat_id) VALUES (?, ?)").bind(id, t)),
        ]);
        return json({ ok: true, saved: id, by: auth.email });
      }

      case "updateQuestion": {
        const id = String(body.id || "");
        if (!QUESTION_RE.test(id)) throw bad("Unknown question ID.");
        const question = text(body.question, "Question");
        const likelihood = level(body.likelihood);
        const thr = threats(body.threats);
        const exists = await env.DB.prepare("SELECT id FROM questions WHERE id = ?").bind(id).first();
        if (!exists) throw bad("Question " + id + " was not found.");
        await env.DB.batch([
          env.DB.prepare("UPDATE questions SET question = ?, likelihood = ?, updated_at = datetime('now') WHERE id = ?").bind(question, likelihood, id),
          env.DB.prepare("DELETE FROM question_threats WHERE question_id = ?").bind(id),
          ...thr.map((t) => env.DB.prepare("INSERT INTO question_threats (question_id, threat_id) VALUES (?, ?)").bind(id, t)),
        ]);
        return json({ ok: true, saved: id, by: auth.email });
      }

      case "addQuestion": {
        const set = body.question_set === "exposure" ? "exposure" : body.question_set === "vulnerability" ? "vulnerability" : null;
        if (!set) throw bad("question_set must be exposure or vulnerability.");
        const question = text(body.question, "Question");
        const likelihood = level(body.likelihood);
        const thr = threats(body.threats || []);
        const prefix = set === "exposure" ? "E" : "V";
        const rows = (await env.DB.prepare("SELECT id, sort_order FROM questions WHERE question_set = ?").bind(set).all()).results;
        let n = rows.length + 1;
        const ids = new Set(rows.map((r) => r.id));
        while (ids.has(prefix + n)) n++;
        const id = prefix + n;
        if (!QUESTION_RE.test(id)) throw bad("No more question IDs are available in this set.");
        const order = rows.reduce((m, r) => Math.max(m, r.sort_order || 0), 0) + 1;
        await env.DB.batch([
          env.DB.prepare("INSERT INTO questions (id, question_set, sort_order, question, likelihood) VALUES (?, ?, ?, ?, ?)").bind(id, set, order, question, likelihood),
          ...thr.map((t) => env.DB.prepare("INSERT INTO question_threats (question_id, threat_id) VALUES (?, ?)").bind(id, t)),
        ]);
        return json({ ok: true, saved: id, by: auth.email });
      }

      case "deleteQuestion": {
        const id = String(body.id || "");
        if (!QUESTION_RE.test(id)) throw bad("Unknown question ID.");
        await env.DB.batch([
          env.DB.prepare("DELETE FROM question_threats WHERE question_id = ?").bind(id),
          env.DB.prepare("DELETE FROM questions WHERE id = ?").bind(id),
        ]);
        return json({ ok: true, deleted: id, by: auth.email });
      }

      default:
        throw bad("Unknown action.");
    }
  } catch (err) {
    if (err && err.userError) return json({ error: err.message }, 400);
    return json({ error: "Could not save the change.", detail: String((err && err.message) || err) }, 500);
  }
}

export async function onRequestGet({ request, env }) {
  // Lets the edit page check who is signed in and whether editing is set up.
  const auth = await verifyAccess(request, env);
  if (!auth.ok) return json({ error: auth.msg }, auth.status);
  return json({ ok: true, email: auth.email });
}

function bad(msg) { const e = new Error(msg); e.userError = true; return e; }
function text(v, label) {
  const s = String(v == null ? "" : v).trim();
  if (!s) throw bad(label + " cannot be empty.");
  if (s.length > MAX_TEXT) throw bad(label + " is too long (maximum " + MAX_TEXT + " characters).");
  return s;
}
function level(v) {
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1 || n > 5) throw bad("Likelihood must be a whole number from 1 to 5.");
  return n;
}

// ---- Cloudflare Access token check ----
let certCache = { at: 0, keys: [] };
async function verifyAccess(request, env) {
  if (!(env.ACCESS_TEAM_DOMAIN && env.ACCESS_AUD)) return verifyPassword(request, env);
  const team = String(env.ACCESS_TEAM_DOMAIN || "").replace(/^https?:\/\//, "").replace(/\/+$/, "");
  const aud = String(env.ACCESS_AUD || "").trim();
  if (!team || !aud) return { ok: false, status: 503, msg: "Editing is not set up yet. Add the ACCESS_TEAM_DOMAIN and ACCESS_AUD variables to the Pages project." };
  const token = request.headers.get("cf-access-jwt-assertion");
  if (!token) return { ok: false, status: 401, msg: "Sign in through Cloudflare Access to edit the question bank." };
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
  if (!user || !pass) return { ok: false, status: 503, msg: "Editing is not set up yet. Add the ADMIN_USER and ADMIN_PASSWORD secrets to the Pages project." };
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
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}
