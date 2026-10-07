// Cloudflare Pages Function: POST /api/admin/tra-questions
// Edits the TRA question bank in the D1 database bound as "DB": risk statements (add, edit, delete) and likelihood questions rated 1–5 (add, edit, delete).
// Sign-in: a shared editor ID and password, checked against the ADMIN_USER and ADMIN_PASSWORD
// secrets set on the Pages project (never stored in page code). If Cloudflare Access is set up later
// (ACCESS_TEAM_DOMAIN and ACCESS_AUD variables), the Access token is checked instead.
// If neither is configured, editing is refused.

const THREAT_RE = /^T\d{2}$/;
const STATEMENT_RE = /^R\d{2}$/;
const QUESTION_RE = /^Q\d{1,2}$/;
const MAX_LEVEL = 300;
const CONTEXTS = ["Safety", "Financial", "Reputation / Political", "Legal", "Engineering / Technical"];
const MAX_TEXT = 1000;
const MAX_TAG = 40;
// R07 was merged into R02; never reuse it, so saved TRAs that still mention R07 map correctly
const RESERVED_STATEMENT_IDS = new Set(["R07"]);

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
        const { tag, event, hazard, ctx } = statementFields(body);
        const thr = threats(body.threats);
        const exists = await env.DB.prepare("SELECT id FROM risk_statements WHERE id = ?").bind(id).first();
        if (!exists) throw bad("Risk statement " + id + " was not found.");
        await env.DB.batch([
          env.DB.prepare("UPDATE risk_statements SET tag = ?, event = ?, hazard = ?, risk_contexts = ?, updated_at = datetime('now') WHERE id = ?").bind(tag, event, hazard, ctx.join(", "), id),
          env.DB.prepare("DELETE FROM risk_statement_threats WHERE statement_id = ?").bind(id),
          ...thr.map((t) => env.DB.prepare("INSERT INTO risk_statement_threats (statement_id, threat_id) VALUES (?, ?)").bind(id, t)),
        ]);
        return json({ ok: true, saved: id, by: auth.email });
      }

      case "addStatement": {
        const { tag, event, hazard, ctx } = statementFields(body);
        const thr = threats(body.threats || []);
        const rows = (await env.DB.prepare("SELECT id, sort_order FROM risk_statements").all()).results;
        const ids = new Set(rows.map((r) => r.id));
        let n = 1;
        const idFor = (k) => "R" + String(k).padStart(2, "0");
        while (ids.has(idFor(n)) || RESERVED_STATEMENT_IDS.has(idFor(n))) n++;
        const id = idFor(n);
        if (!STATEMENT_RE.test(id)) throw bad("No more risk statement IDs are available.");
        const order = rows.reduce((m, r) => Math.max(m, r.sort_order || 0), 0) + 1;
        // system_type is no longer used (statements apply to IT and OT); the column still requires a value.
        await env.DB.batch([
          env.DB.prepare("INSERT INTO risk_statements (id, sort_order, system_type, tag, event, hazard, risk_contexts) VALUES (?, ?, 'IT', ?, ?, ?, ?)").bind(id, order, tag, event, hazard, ctx.join(", ")),
          ...thr.map((t) => env.DB.prepare("INSERT INTO risk_statement_threats (statement_id, threat_id) VALUES (?, ?)").bind(id, t)),
        ]);
        return json({ ok: true, saved: id, by: auth.email });
      }

      case "deleteStatement": {
        const id = String(body.id || "");
        if (!STATEMENT_RE.test(id)) throw bad("Unknown risk statement ID.");
        const count = (await env.DB.prepare("SELECT COUNT(*) AS n FROM risk_statements").first()).n;
        const exists = await env.DB.prepare("SELECT id FROM risk_statements WHERE id = ?").bind(id).first();
        if (!exists) throw bad("Risk statement " + id + " was not found.");
        if (count <= 1) throw bad("Keep at least one risk statement.");
        await env.DB.batch([
          env.DB.prepare("DELETE FROM risk_statement_threats WHERE statement_id = ?").bind(id),
          env.DB.prepare("DELETE FROM risk_statements WHERE id = ?").bind(id),
        ]);
        return json({ ok: true, deleted: id, by: auth.email });
      }

      case "updateQuestion": {
        const id = String(body.id || "");
        if (!QUESTION_RE.test(id)) throw bad("Unknown question ID.");
        const { question, guidance, levels } = questionFields(body);
        const thr = threats(body.threats);
        const exists = await env.DB.prepare("SELECT id FROM likelihood_questions WHERE id = ?").bind(id).first();
        if (!exists) throw bad("Question " + id + " was not found.");
        await env.DB.batch([
          env.DB.prepare("UPDATE likelihood_questions SET question = ?, guidance = ?, level_1 = ?, level_2 = ?, level_3 = ?, level_4 = ?, level_5 = ?, updated_at = datetime('now') WHERE id = ?").bind(question, guidance, ...levels, id),
          env.DB.prepare("DELETE FROM likelihood_question_threats WHERE question_id = ?").bind(id),
          ...thr.map((t) => env.DB.prepare("INSERT INTO likelihood_question_threats (question_id, threat_id) VALUES (?, ?)").bind(id, t)),
        ]);
        return json({ ok: true, saved: id, by: auth.email });
      }

      case "addQuestion": {
        const { question, guidance, levels } = questionFields(body);
        const thr = threats(body.threats || []);
        const rows = (await env.DB.prepare("SELECT id, sort_order FROM likelihood_questions").all()).results;
        // Always the next number after the highest ever used here, so a deleted question's answers never attach to a new one
        const n = rows.reduce((m, r) => Math.max(m, Number(String(r.id).slice(1)) || 0), 0) + 1;
        const id = "Q" + n;
        if (!QUESTION_RE.test(id)) throw bad("No more question IDs are available.");
        const order = rows.reduce((m, r) => Math.max(m, r.sort_order || 0), 0) + 1;
        await env.DB.batch([
          env.DB.prepare("INSERT INTO likelihood_questions (id, sort_order, question, guidance, level_1, level_2, level_3, level_4, level_5) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").bind(id, order, question, guidance, ...levels),
          ...thr.map((t) => env.DB.prepare("INSERT INTO likelihood_question_threats (question_id, threat_id) VALUES (?, ?)").bind(id, t)),
        ]);
        return json({ ok: true, saved: id, by: auth.email });
      }

      case "deleteQuestion": {
        const id = String(body.id || "");
        if (!QUESTION_RE.test(id)) throw bad("Unknown question ID.");
        await env.DB.batch([
          env.DB.prepare("DELETE FROM likelihood_question_threats WHERE question_id = ?").bind(id),
          env.DB.prepare("DELETE FROM likelihood_questions WHERE id = ?").bind(id),
        ]);
        return json({ ok: true, deleted: id, by: auth.email });
      }

      default:
        throw bad("Unknown action.");
    }
  } catch (err) {
    if (err && err.userError) return json({ error: err.message }, 400);
    const detail = String((err && err.message) || err);
    if (/no such table: likelihood_question/i.test(detail)) return json({ error: "The likelihood question tables have not been created yet. Run likelihood-steps.txt in the D1 Console." }, 500);
    return json({ error: "Could not save the change.", detail }, 500);
  }
}

export async function onRequestGet({ request, env }) {
  // Lets the edit page check who is signed in and whether editing is set up.
  const auth = await verifyAccess(request, env);
  if (!auth.ok) return json({ error: auth.msg }, auth.status);
  return json({ ok: true, email: auth.email });
}

function statementFields(body) {
  const tag = text(body.tag, "Tag");
  if (tag.length > MAX_TAG) throw bad("Tag is too long (maximum " + MAX_TAG + " characters).");
  const event = text(body.event, "Event");
  const hazard = text(body.hazard, "Hazard");
  const ctx = Array.isArray(body.risk_contexts) ? [...new Set(body.risk_contexts.map(String))] : [];
  const badCtx = ctx.filter((c) => !CONTEXTS.includes(c));
  if (badCtx.length) throw bad("Unknown risk contexts: " + badCtx.join(", "));
  if (!ctx.length) throw bad("Choose at least one risk context.");
  return { tag, event, hazard, ctx };
}
function questionFields(body) {
  const question = text(body.question, "Question");
  const guidance = String(body.guidance == null ? "" : body.guidance).trim();
  if (guidance.length > MAX_TEXT) throw bad("Description is too long (maximum " + MAX_TEXT + " characters).");
  if (!Array.isArray(body.levels) || body.levels.length !== 5) throw bad("Give a description for each level, 1 to 5.");
  const levels = body.levels.map((v, i) => {
    const s = text(v, "Level " + (i + 1) + " description");
    if (s.length > MAX_LEVEL) throw bad("Level " + (i + 1) + " description is too long (maximum " + MAX_LEVEL + " characters).");
    return s;
  });
  return { question, guidance, levels };
}
function bad(msg) { const e = new Error(msg); e.userError = true; return e; }
function text(v, label) {
  const s = String(v == null ? "" : v).trim();
  if (!s) throw bad(label + " cannot be empty.");
  if (s.length > MAX_TEXT) throw bad(label + " is too long (maximum " + MAX_TEXT + " characters).");
  return s;
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
