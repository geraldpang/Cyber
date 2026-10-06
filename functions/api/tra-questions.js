// Cloudflare Pages Function: GET /api/tra-questions
// Returns the TRA question bank from the D1 database bound as "DB".
// Read-only. Editing will be added separately behind Cloudflare Access.

export async function onRequestGet({ env }) {
  if (!env.DB) {
    return json({ error: "The D1 database is not bound to this Pages project as DB." }, 500);
  }
  try {
    const [threats, statements, statementThreats, questions, questionThreats] = await env.DB.batch([
      env.DB.prepare("SELECT id, name FROM threats ORDER BY sort_order"),
      env.DB.prepare("SELECT id, system_type, tag, event, hazard, risk_contexts, updated_at FROM risk_statements ORDER BY sort_order"),
      env.DB.prepare("SELECT statement_id, threat_id FROM risk_statement_threats ORDER BY threat_id"),
      env.DB.prepare("SELECT id, question_set, question, likelihood, updated_at FROM questions WHERE active = 1 ORDER BY question_set, sort_order"),
      env.DB.prepare("SELECT question_id, threat_id FROM question_threats ORDER BY threat_id"),
    ]);

    const group = (rows, key) => rows.reduce((m, r) => ((m[r[key]] ||= []).push(r.threat_id), m), {});
    const stThreats = group(statementThreats.results, "statement_id");
    const qThreats = group(questionThreats.results, "question_id");

    const qs = questions.results.map((q) => ({
      id: q.id,
      question: q.question,
      likelihood: q.likelihood,
      threats: qThreats[q.id] || [],
      updated_at: q.updated_at,
    }));

    return json({
      threats: threats.results,
      risk_statements: statements.results.map((s) => ({
        id: s.id,
        system_type: s.system_type,
        tag: s.tag,
        event: s.event,
        hazard: s.hazard,
        risk_contexts: s.risk_contexts.split(",").map((x) => x.trim()).filter(Boolean),
        statement: `Risk of ${s.event} due to ${s.hazard}.`,
        threats: stThreats[s.id] || [],
        updated_at: s.updated_at,
      })),
      questions: {
        exposure: qs.filter((q, i) => questions.results[i].question_set === "exposure"),
        vulnerability: qs.filter((q, i) => questions.results[i].question_set === "vulnerability"),
      },
    });
  } catch (err) {
    return json({ error: "Could not read the question bank.", detail: String((err && err.message) || err) }, 500);
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
