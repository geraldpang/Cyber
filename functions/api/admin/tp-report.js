// Cloudflare Pages Function: POST /api/admin/tp-report
// Saves the default wording of the Third-Party Assessment Report in the D1 database bound as "DB".
// Actions:
//   { action: "updateAdvisory", n, area, obs, rec, ev, refs }   one recommended advisory item (n = 1–11)
//   { action: "updateText", key, body }                          one report section (intro, Low, Med, High, cond, scope, soci)
// Sign-in: the same editor ID and password as the TRA question bank (ADMIN_USER and ADMIN_PASSWORD secrets on the
// Pages project, never stored in page code), or Cloudflare Access if ACCESS_TEAM_DOMAIN and ACCESS_AUD are set.
// If neither is configured, editing is refused.

const TEXT_KEYS = new Set(["intro", "Low", "Med", "High", "cond", "scope", "soci"]);
const MAX_SHORT = 200;
const MAX_LONG = 4000;

export async function onRequestPost({ request, env }) {
  const auth = await verifyAccess(request, env);
  if (!auth.ok) return json({ error: auth.msg }, auth.status);
  if (!env.DB) return json({ error: "The D1 database is not bound to this Pages project as DB." }, 500);
  let body;
  try { body = await request.json(); } catch { return json({ error: "The request body must be JSON." }, 400); }
  try {
    switch (body.action) {
      case "updateAdvisory": {
        const n = Number(body.n);
        if (!Number.isInteger(n) || n < 1 || n > 11) throw bad("Unknown advisory item.");
        const area = text(body.area, "Area", MAX_SHORT), obs = text(body.obs, "Observation", MAX_LONG),
          rec = text(body.rec, "Recommendation", MAX_LONG), ev = text(body.ev, "Recommended evidence", MAX_LONG),
          refs = text(body.refs, "Industry references", MAX_LONG, true);
        await env.DB.prepare(
          "INSERT INTO tp_advisory (n, area, observation, recommendation, evidence, refs, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?, datetime('now'), ?) " +
          "ON CONFLICT(n) DO UPDATE SET area = excluded.area, observation = excluded.observation, recommendation = excluded.recommendation, evidence = excluded.evidence, refs = excluded.refs, updated_at = excluded.updated_at, updated_by = excluded.updated_by"
        ).bind(n, area, obs, rec, ev, refs, auth.email || "").run();
        return json({ ok: true, saved: "advisory " + n, by: auth.email });
      }
      case "updateText": {
        const key = String(body.key || "");
        if (!TEXT_KEYS.has(key)) throw bad("Unknown report section.");
        const b = text(body.body, "Section text", MAX_LONG);
        await env.DB.prepare(
          "INSERT INTO tp_report_text (key, body, updated_at, updated_by) VALUES (?, ?, datetime('now'), ?) " +
          "ON CONFLICT(key) DO UPDATE SET body = excluded.body, updated_at = excluded.updated_at, updated_by = excluded.updated_by"
        ).bind(key, b, auth.email || "").run();
        return json({ ok: true, saved: key, by: auth.email });
      }
      default:
        throw bad("Unknown action.");
    }
  } catch (e) {
    if (e && e.userError) return json({ error: e.message }, 400);
    if (/no such table/i.test(String(e && e.message))) return json({ error: "The report wording tables have not been created yet. Run tp-report-steps.txt in the D1 console." }, 500);
    return json({ error: "The wording could not be saved." }, 500);
  }
}

function bad(msg) { const e = new Error(msg); e.userError = true; return e; }
function text(v, label, max, optional) {
  const s = String(v == null ? "" : v).replace(/\r\n/g, "\n").trim();
  if (!s && !optional) throw bad(label + " cannot be empty.");
  if (s.length > max) throw bad(label + " is too long (maximum " + max + " characters).");
  return s;
}

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
