// Cloudflare Pages Function: GET /api/tra-questions
// Returns the TRA question bank from the D1 database bound as "DB".
// Read-only and public. Editing is done by functions/api/admin/tra-questions.js (sign-in required).
//
// likelihood_questions: the questions the TRA asks, each rated 1 (Rare) to 5 (Almost certain),
//   with a description for every level and the threats the answer applies to.
// controls: the MTM and IEC 62443 control sets, with threats, CIA and (IEC) SL-T.
// questions: the older exposure / vulnerability (Yes/No) questions, kept for pages not yet updated.

export async function onRequestGet({ env }) {
  if (!env.DB) {
    return json({ error: "The D1 database is not bound to this Pages project as DB." }, 500);
  }
  try {
    const [threats, statements, statementThreats] = await env.DB.batch([
      env.DB.prepare("SELECT id, name FROM threats ORDER BY sort_order"),
      env.DB.prepare("SELECT id, tag, event, hazard, risk_contexts, updated_at FROM risk_statements ORDER BY sort_order"),
      env.DB.prepare("SELECT statement_id, threat_id FROM risk_statement_threats ORDER BY threat_id"),
    ]);
    const group = (rows, key) => rows.reduce((m, r) => ((m[r[key]] ||= []).push(r.threat_id), m), {});
    const stThreats = group(statementThreats.results, "statement_id");

    return json({
      threats: threats.results,
      risk_statements: statements.results.map((s) => ({
        id: s.id,
        tag: s.tag,
        event: s.event,
        hazard: s.hazard,
        risk_contexts: String(s.risk_contexts || "").split(",").map((x) => x.trim()).filter(Boolean),
        statement: `Risk of ${s.event} due to ${s.hazard}.`,
        threats: stThreats[s.id] || [],
        updated_at: s.updated_at,
      })),
      likelihood_questions: await likelihoodQuestions(env),
      controls: await controlSets(env),
      questions: await legacyQuestions(env),
    });
  } catch (err) {
    return json({ error: "Could not read the question bank.", detail: String((err && err.message) || err) }, 500);
  }
}

// Returns [] (not an error) until the likelihood question tables have been created.
async function likelihoodQuestions(env) {
  try {
    const [qs, links] = await env.DB.batch([
      env.DB.prepare("SELECT id, question, guidance, level_1, level_2, level_3, level_4, level_5, updated_at FROM likelihood_questions WHERE active = 1 ORDER BY sort_order"),
      env.DB.prepare("SELECT question_id, threat_id FROM likelihood_question_threats ORDER BY threat_id"),
    ]);
    const byQ = links.results.reduce((m, r) => ((m[r.question_id] ||= []).push(r.threat_id), m), {});
    return qs.results.map((q) => ({
      id: q.id,
      question: q.question,
      guidance: q.guidance || "",
      levels: [q.level_1, q.level_2, q.level_3, q.level_4, q.level_5],
      threats: byQ[q.id] || [],
      updated_at: q.updated_at,
    }));
  } catch (err) {
    if (/no such table/i.test(String(err && err.message))) return [];
    throw err;
  }
}

// MTM and IEC 62443 controls with their threats, CIA and (IEC) SL-T. Returns [] until the control tables exist.
async function controlSets(env) {
  try {
    const [cs, links] = await env.DB.batch([
      env.DB.prepare("SELECT id, control_set, code, title, description, domain, sl, cia, updated_at FROM controls WHERE active = 1 ORDER BY control_set DESC, sort_order"),
      env.DB.prepare("SELECT control_id, threat_id FROM control_threats ORDER BY threat_id"),
    ]);
    const byC = links.results.reduce((m, r) => ((m[r.control_id] ||= []).push(r.threat_id), m), {});
    const list = (v) => String(v || "").split(",").map((x) => x.trim()).filter(Boolean);
    return cs.results.map((c) => ({
      id: c.id,
      set: c.control_set,
      code: c.code,
      title: c.title,
      description: c.description || "",
      domain: c.domain || "",
      sl: list(c.sl).map(Number).filter((n) => n >= 1 && n <= 4),
      cia: list(c.cia).filter((x) => ["C", "I", "A"].includes(x)),
      threats: byC[c.id] || [],
      updated_at: c.updated_at,
    }));
  } catch (err) {
    if (/no such table/i.test(String(err && err.message))) return [];
    throw err;
  }
}

async function legacyQuestions(env) {
  try {
    const [qs, links] = await env.DB.batch([
      env.DB.prepare("SELECT id, question_set, question, likelihood, updated_at FROM questions WHERE active = 1 ORDER BY question_set, sort_order"),
      env.DB.prepare("SELECT question_id, threat_id FROM question_threats ORDER BY threat_id"),
    ]);
    const byQ = links.results.reduce((m, r) => ((m[r.question_id] ||= []).push(r.threat_id), m), {});
    const out = { exposure: [], vulnerability: [] };
    qs.results.forEach((q) => {
      (out[q.question_set] ||= []).push({ id: q.id, question: q.question, likelihood: q.likelihood, threats: byQ[q.id] || [], updated_at: q.updated_at });
    });
    return out;
  } catch (err) {
    if (/no such table/i.test(String(err && err.message))) return { exposure: [], vulnerability: [] };
    throw err;
  }
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "public, max-age=60",
    },
  });
}
