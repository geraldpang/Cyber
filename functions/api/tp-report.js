// Cloudflare Pages Function: GET /api/tp-report
// Returns the default wording for the Third-Party Assessment Report from the D1 database bound as "DB":
//   advisory: the recommended advisory items (1–10 match questionnaire Q1–Q10; 11 = external cybersecurity intelligence)
//   text: the report sections (intro, Low, Med, High, cond, scope, soci)
// Read-only and public. Editing is done by functions/api/admin/tp-report.js (sign-in required).
// Wording may contain {ORG} and {ORGFULL}; the page fills these with the organisation names.
// ready is false until the tables have been created (see tp-report-steps.txt).

export async function onRequestGet({ env }) {
  if (!env.DB) return json({ ready: false, error: "The D1 database is not bound to this Pages project as DB." }, 500);
  try {
    const [adv, txt] = await env.DB.batch([
      env.DB.prepare("SELECT n, area, observation, recommendation, evidence, refs, updated_at FROM tp_advisory ORDER BY n"),
      env.DB.prepare("SELECT key, body, updated_at FROM tp_report_text"),
    ]);
    return json({
      ready: true,
      advisory: adv.results.map((r) => ({
        n: r.n, area: r.area, obs: r.observation, rec: r.recommendation, ev: r.evidence, refs: r.refs || "", updated_at: r.updated_at,
      })),
      text: Object.fromEntries(txt.results.map((r) => [r.key, { body: r.body, updated_at: r.updated_at }])),
    });
  } catch (e) {
    // Tables not created yet: the page keeps its built-in wording
    if (/no such table/i.test(String(e && e.message))) return json({ ready: false, error: "The report wording tables have not been created yet." });
    return json({ ready: false, error: "The report wording could not be read." }, 500);
  }
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}
