// Cloudflare Pages Function: POST /api/admin/tra-questions
// Edits the TRA question bank in the D1 database bound as "DB": risk statements (add, edit, delete) likelihood questions rated 1–5 (add, edit, delete),
// the MTM and IEC 62443 control sets (add, edit, delete; threats, CIA, IEC SL-T, specifications and evidence),
// and the control assurance questions with the controls each one covers (add, edit, delete, load the built-in set).
// Sign-in: a shared editor ID and password, checked against the ADMIN_USER and ADMIN_PASSWORD
// secrets set on the Pages project (never stored in page code). If Cloudflare Access is set up later
// (ACCESS_TEAM_DOMAIN and ACCESS_AUD variables), the Access token is checked instead.
// If neither is configured, editing is refused.

const THREAT_RE = /^T\d{2}$/;
const STATEMENT_RE = /^R\d{2}$/;
const QUESTION_RE = /^Q\d{1,2}$/;
const MAX_LEVEL = 300;
const AQ_RE = /^Q\d{2,3}$/;
const CONTROL_ID_RE = /^(MTM|IEC):[A-Za-z0-9 .\-()]{1,40}$/;
const CODE_RE = /^[A-Za-z0-9 .\-()]{1,40}$/;
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
          ...multiInsert(env, "risk_statement_threats", ["statement_id", "threat_id"], thr.map((t) => [id, t])),
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
          ...multiInsert(env, "risk_statement_threats", ["statement_id", "threat_id"], thr.map((t) => [id, t])),
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
          ...multiInsert(env, "likelihood_question_threats", ["question_id", "threat_id"], thr.map((t) => [id, t])),
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
          ...multiInsert(env, "likelihood_question_threats", ["question_id", "threat_id"], thr.map((t) => [id, t])),
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

      case "updateControl": {
        const id = String(body.id || "");
        if (!CONTROL_ID_RE.test(id)) throw bad("Unknown control ID.");
        const set = id.slice(0, 3);
        const f = controlFields(body, set);
        const thr = threats(body.threats);
        const exists = await env.DB.prepare("SELECT id FROM controls WHERE id = ?").bind(id).first();
        if (!exists) throw bad("Control " + id + " was not found.");
        const qLinks = await controlQuestions(env, id, body.questions);
        await env.DB.batch([
          env.DB.prepare("UPDATE controls SET title = ?, description = ?, domain = ?, sl = ?, cia = ?, updated_at = datetime('now') WHERE id = ?").bind(f.title, f.description, f.domain, f.sl, f.cia, id),
          env.DB.prepare("DELETE FROM control_threats WHERE control_id = ?").bind(id),
          ...multiInsert(env, "control_threats", ["control_id", "threat_id"], thr.map((t) => [id, t])),
          ...(body.specs !== undefined || body.evidence !== undefined ? detailStatements(env, id, details(body)) : []),
          ...qLinks,
        ]);
        return json({ ok: true, saved: id, by: auth.email });
      }

      case "addControl": {
        const set = body.control_set === "MTM" || body.control_set === "IEC" ? body.control_set : null;
        if (!set) throw bad("control_set must be MTM or IEC.");
        const code = String(body.code || "").trim();
        if (!CODE_RE.test(code)) throw bad("Control ID must be 1 to 40 letters, numbers, spaces, dots, dashes or brackets.");
        const id = set + ":" + code;
        const f = controlFields(body, set);
        const thr = threats(body.threats || []);
        const exists = await env.DB.prepare("SELECT id FROM controls WHERE id = ?").bind(id).first();
        if (exists) throw bad("Control " + code + " already exists in the " + set + " set.");
        const qLinks = await controlQuestions(env, id, body.questions);
        const order = ((await env.DB.prepare("SELECT MAX(sort_order) AS m FROM controls").first()).m || 0) + 1;
        await env.DB.batch([
          env.DB.prepare("INSERT INTO controls (id, control_set, code, sort_order, title, description, domain, sl, cia) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").bind(id, set, code, order, f.title, f.description, f.domain, f.sl, f.cia),
          ...multiInsert(env, "control_threats", ["control_id", "threat_id"], thr.map((t) => [id, t])),
          ...(body.specs !== undefined || body.evidence !== undefined ? detailStatements(env, id, details(body)) : []),
          ...qLinks,
        ]);
        return json({ ok: true, saved: id, by: auth.email });
      }

      case "importControlDetails": {
        // Loads specifications and evidence for up to 5 controls at a time (to stay within D1's per-request query limit). Controls that already
        // have specifications or evidence are left alone unless overwrite is true.
        const items = Array.isArray(body.items) ? body.items : [];
        if (!items.length || items.length > 5) throw bad("Send between 1 and 5 controls at a time.");
        const ids = items.map((x) => String((x && x.id) || ""));
        if (ids.some((x) => !CONTROL_ID_RE.test(x))) throw bad("Unknown control ID in the import.");
        const known = new Set((await env.DB.prepare("SELECT id FROM controls").all()).results.map((r) => r.id));
        const filled = new Set([
          ...(await env.DB.prepare("SELECT DISTINCT control_id FROM control_specs").all()).results.map((r) => r.control_id),
          ...(await env.DB.prepare("SELECT DISTINCT control_id FROM control_evidence").all()).results.map((r) => r.control_id),
        ]);
        const stmts = [];
        let loaded = 0, skipped = 0;
        items.forEach((x, i) => {
          const id = ids[i];
          if (!known.has(id) || (filled.has(id) && !body.overwrite)) { skipped++; return; }
          stmts.push(...detailStatements(env, id, details(x)));
          loaded++;
        });
        if (stmts.length) await env.DB.batch(stmts);
        return json({ ok: true, loaded, skipped, by: auth.email });
      }

      case "deleteControl": {
        const id = String(body.id || "");
        if (!CONTROL_ID_RE.test(id)) throw bad("Unknown control ID.");
        await env.DB.batch([
          env.DB.prepare("DELETE FROM control_threats WHERE control_id = ?").bind(id),
          env.DB.prepare("DELETE FROM controls WHERE id = ?").bind(id),
        ]);
        return json({ ok: true, deleted: id, by: auth.email });
      }

      case "updateAssurance": {
        const id = String(body.id || "");
        if (!AQ_RE.test(id)) throw bad("Unknown assurance question ID.");
        const f = assuranceFields(body);
        const ctl = await assuranceControls(env, body.controls);
        const exists = await env.DB.prepare("SELECT id FROM assurance_questions WHERE id = ?").bind(id).first();
        if (!exists) throw bad("Assurance question " + id + " was not found.");
        await env.DB.batch([
          env.DB.prepare("UPDATE assurance_questions SET topic = ?, question = ?, required = ?, evidence = ?, applicability = ?, updated_at = datetime('now') WHERE id = ?").bind(f.topic, f.question, f.required, f.evidence, f.applicability, id),
          env.DB.prepare("DELETE FROM assurance_question_controls WHERE question_id = ?").bind(id),
          ...multiInsert(env, "assurance_question_controls", ["question_id", "control_id"], ctl.map((c) => [id, c])),
        ]);
        return json({ ok: true, saved: id, by: auth.email });
      }

      case "addAssurance": {
        const f = assuranceFields(body);
        const ctl = await assuranceControls(env, body.controls || []);
        const rows = (await env.DB.prepare("SELECT id, sort_order FROM assurance_questions").all()).results;
        const n = rows.reduce((m, r) => Math.max(m, Number(String(r.id).slice(1)) || 0), 0) + 1;
        const id = "Q" + String(n).padStart(2, "0");
        if (!AQ_RE.test(id)) throw bad("No more assurance question IDs are available.");
        const order = rows.reduce((m, r) => Math.max(m, r.sort_order || 0), 0) + 1;
        await env.DB.batch([
          env.DB.prepare("INSERT INTO assurance_questions (id, sort_order, topic, question, required, evidence, applicability) VALUES (?, ?, ?, ?, ?, ?, ?)").bind(id, order, f.topic, f.question, f.required, f.evidence, f.applicability),
          ...multiInsert(env, "assurance_question_controls", ["question_id", "control_id"], ctl.map((c) => [id, c])),
        ]);
        return json({ ok: true, saved: id, by: auth.email });
      }

      case "deleteAssurance": {
        const id = String(body.id || "");
        if (!AQ_RE.test(id)) throw bad("Unknown assurance question ID.");
        await env.DB.batch([
          env.DB.prepare("DELETE FROM assurance_question_controls WHERE question_id = ?").bind(id),
          env.DB.prepare("DELETE FROM assurance_questions WHERE id = ?").bind(id),
        ]);
        return json({ ok: true, deleted: id, by: auth.email });
      }

      case "importAssurance": {
        // Loads the built-in assurance questions into empty tables. Mapped controls that are not in the control sets are skipped.
        const items = Array.isArray(body.questions) ? body.questions : [];
        if (!items.length || items.length > 60) throw bad("Send between 1 and 60 assurance questions.");
        const count = (await env.DB.prepare("SELECT COUNT(*) AS n FROM assurance_questions").first()).n;
        if (count > 0) throw bad("The assurance question table already has " + count + " questions. Delete them first to reload the built-in set.");
        const known = new Set((await env.DB.prepare("SELECT id FROM controls").all()).results.map((r) => r.id));
        const seen = new Set(), qs = [], links = [];
        let skipped = 0;
        items.forEach((x, i) => {
          const id = String((x && x.id) || "");
          if (!AQ_RE.test(id) || seen.has(id)) throw bad("Question " + (i + 1) + " has a missing or repeated ID.");
          seen.add(id);
          const f = assuranceFields(x || {});
          qs.push([id, i + 1, f.topic, f.question, f.required, f.evidence, f.applicability]);
          [...new Set((Array.isArray(x.controls) ? x.controls : []).map(String))].forEach((c) => { if (known.has(c)) links.push([id, c]); else skipped++; });
        });
        await env.DB.batch([
          ...multiInsert(env, "assurance_questions", ["id", "sort_order", "topic", "question", "required", "evidence", "applicability"], qs),
          ...multiInsert(env, "assurance_question_controls", ["question_id", "control_id"], links),
        ]);
        return json({ ok: true, loaded: qs.length, links: links.length, skipped, by: auth.email });
      }

      default:
        throw bad("Unknown action.");
    }
  } catch (err) {
    if (err && err.userError) return json({ error: err.message }, 400);
    const detail = String((err && err.message) || err);
    if (/no such table: control_(specs|evidence)/i.test(detail)) return json({ error: "The specification and evidence tables have not been created yet. Run details-steps.txt in the D1 Console." }, 500);
    if (/no such table: control/i.test(detail)) return json({ error: "The control tables have not been created yet. Run controls-steps.txt in the D1 Console." }, 500);
    if (/no such table: assurance_question/i.test(detail)) return json({ error: "The assurance question tables have not been created yet. Run assurance-steps.txt in the D1 Console." }, 500);
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
const MAX_SPECS = 80, MAX_SPEC_TEXT = 2000, MAX_EVIDENCE = 40, MAX_EVIDENCE_TEXT = 500;
const SCOPE_RE = /^[A-Za-z /&-]{1,40}$/;
// Specifications ({code, text, level, scope[], threats[]}) and supporting evidence (text) for one control.
function details(body) {
  const specsIn = Array.isArray(body.specs) ? body.specs : [];
  const evIn = Array.isArray(body.evidence) ? body.evidence : [];
  if (specsIn.length > MAX_SPECS) throw bad("A control can have at most " + MAX_SPECS + " specifications.");
  if (evIn.length > MAX_EVIDENCE) throw bad("A control can have at most " + MAX_EVIDENCE + " evidence items.");
  const specs = specsIn.map((x, i) => {
    const t = String((x && x.text) || "").trim();
    if (!t) throw bad("Specification " + (i + 1) + " has no text.");
    if (t.length > MAX_SPEC_TEXT) throw bad("Specification " + (i + 1) + " is too long (maximum " + MAX_SPEC_TEXT + " characters).");
    const code = String((x && x.code) || "").trim().slice(0, 40);
    const level = String((x && x.level) || "").trim().slice(0, 40);
    const scope = (Array.isArray(x && x.scope) ? x.scope : []).map((v) => String(v).trim()).filter((v) => SCOPE_RE.test(v)).slice(0, 20);
    const thr = (Array.isArray(x && x.threats) ? x.threats : []).map(String).filter((v) => THREAT_RE.test(v));
    return { code, text: t, level, scope: scope.join(", "), threats: [...new Set(thr)].join(",") };
  });
  const evidence = evIn.map((v, i) => {
    const t = String(v == null ? "" : v).trim();
    if (!t) throw bad("Evidence item " + (i + 1) + " is empty.");
    if (t.length > MAX_EVIDENCE_TEXT) throw bad("Evidence item " + (i + 1) + " is too long (maximum " + MAX_EVIDENCE_TEXT + " characters).");
    return t;
  });
  return { specs, evidence };
}
// One INSERT per chunk of rows, keeping each query within D1's limit of 100 bound values.
// Fewer statements also keeps each save within the free plan's 50 queries per request.
function multiInsert(env, table, cols, rows) {
  const per = Math.max(1, Math.floor(100 / cols.length)), out = [];
  for (let i = 0; i < rows.length; i += per) {
    const chunk = rows.slice(i, i + per);
    const sql = "INSERT INTO " + table + " (" + cols.join(", ") + ") VALUES " + chunk.map(() => "(" + cols.map(() => "?").join(", ") + ")").join(", ");
    out.push(env.DB.prepare(sql).bind(...chunk.flat()));
  }
  return out;
}
function detailStatements(env, id, d) {
  return [
    env.DB.prepare("DELETE FROM control_specs WHERE control_id = ?").bind(id),
    env.DB.prepare("DELETE FROM control_evidence WHERE control_id = ?").bind(id),
    ...multiInsert(env, "control_specs", ["control_id", "sort_order", "code", "text", "level", "scope", "threats"], d.specs.map((x, i) => [id, i + 1, x.code, x.text, x.level, x.scope, x.threats])),
    ...multiInsert(env, "control_evidence", ["control_id", "sort_order", "text"], d.evidence.map((t, i) => [id, i + 1, t])),
  ];
}
function controlFields(body, set) {
  const title = text(body.title, "Title");
  if (title.length > 200) throw bad("Title is too long (maximum 200 characters).");
  const description = String(body.description == null ? "" : body.description).trim();
  if (description.length > MAX_TEXT) throw bad("Description is too long (maximum " + MAX_TEXT + " characters).");
  const domain = String(body.domain == null ? "" : body.domain).trim();
  if (domain.length > 120) throw bad("Domain is too long (maximum 120 characters).");
  const cia = Array.isArray(body.cia) ? ["C", "I", "A"].filter((x) => body.cia.includes(x)) : [];
  if (!cia.length) throw bad("Tick at least one of C, I and A.");
  let sl = "";
  if (set === "IEC") {
    const levels = Array.isArray(body.sl) ? [1, 2, 3, 4].filter((n) => body.sl.map(Number).includes(n)) : [];
    if (!levels.length) throw bad("Tick at least one SL-T level for an IEC 62443 control.");
    sl = levels.join(",");
  }
  return { title, description, domain, sl, cia: cia.join(",") };
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
const AQ_LIMITS = { topic: 200, question: 1000, required: 6000, evidence: 3000, applicability: 1000 };
function assuranceFields(body) {
  const out = {};
  for (const [k, max] of Object.entries(AQ_LIMITS)) {
    const v = String(body[k] == null ? "" : body[k]).replace(/\r\n/g, "\n").trim();
    const label = { topic: "Topic", question: "Question", required: "What is required?", evidence: "Recommended evidence", applicability: "Applicability guidance" }[k];
    if ((k === "topic" || k === "question") && !v) throw bad(label + " cannot be empty.");
    if (v.length > max) throw bad(label + " is too long (maximum " + max + " characters).");
    out[k] = v;
  }
  return out;
}
// The assurance questions a control sits under, set from the control's own editor (only when "questions" is sent).
async function controlQuestions(env, id, list) {
  if (list === undefined) return [];
  if (!Array.isArray(list)) throw bad("questions must be a list of assurance question IDs.");
  const ids = [...new Set(list.map(String))];
  if (ids.some((x) => !AQ_RE.test(x))) throw bad("Unknown assurance question ID.");
  const known = new Set((await env.DB.prepare("SELECT id FROM assurance_questions").all()).results.map((r) => r.id));
  const unknown = ids.filter((x) => !known.has(x));
  if (unknown.length) throw bad("These assurance questions were not found: " + unknown.join(", "));
  return [
    env.DB.prepare("DELETE FROM assurance_question_controls WHERE control_id = ?").bind(id),
    ...multiInsert(env, "assurance_question_controls", ["question_id", "control_id"], ids.map((q) => [q, id])),
  ];
}
// Control IDs a question covers; every one must be in the control sets.
async function assuranceControls(env, list) {
  if (!Array.isArray(list)) throw bad("controls must be a list of control IDs.");
  const ids = [...new Set(list.map(String))];
  if (ids.length > 300) throw bad("A question can cover at most 300 controls.");
  if (ids.some((x) => !CONTROL_ID_RE.test(x))) throw bad("Unknown control ID in the mapping.");
  if (!ids.length) return ids;
  const known = new Set((await env.DB.prepare("SELECT id FROM controls").all()).results.map((r) => r.id));
  const unknown = ids.filter((x) => !known.has(x));
  if (unknown.length) throw bad("These controls are not in the control sets: " + unknown.join(", "));
  return ids;
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
