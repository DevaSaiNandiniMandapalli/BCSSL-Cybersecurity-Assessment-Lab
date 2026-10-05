/* BCSSL Cybersecurity Assessment Lab - dashboard client.
   Standard library only: no build step, no external dependencies. */
"use strict";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const TABS = ["dashboard","target","preflight","tools","run","findings","correlation",
              "evidence","reports","lab","progress","docs","about"];
const VERIFY_STATUSES = ["DETECTED","CORROBORATED","SINGLE-TOOL OBSERVATION","NOT VERIFIED"];

const state = {
  data: null, findings: [], exercises: [], evidence: [],
  correlation: null, preflight: null, docs: [], target: null, selectedDoc: null,
};

/* ---------- helpers ---------- */
const el = (id) => document.getElementById(id);
function esc(v) {
  return String(v === null || v === undefined ? "" : v)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function sevBadge(sev) {
  const level = String(sev || "INFO").toUpperCase();
  return `<span class="badge sev-${level.toLowerCase()}">${esc(level)}</span>`;
}
function verifyBadge(status) {
  const key = String(status || "").toLowerCase().replace(/[^a-z]+/g, "-");
  return `<span class="verify verify-${esc(key)}">${esc(status || "-")}</span>`;
}
async function api(path, options) {
  try {
    const r = await fetch(path, options);
    const t = await r.text();
    try { return JSON.parse(t); } catch (e) { return { error: t }; }
  } catch (e) { return { error: String(e) }; }
}
function stat(n, l) {
  return `<div class="stat"><div class="n">${esc(n)}</div><div class="l">${esc(l)}</div></div>`;
}
function empty(text) { return `<div class="empty">${esc(text)}</div>`; }

/* ---------- theme + tabs ---------- */
function initTheme() {
  const saved = localStorage.getItem("bcssl-theme");
  if (saved) document.documentElement.setAttribute("data-theme", saved);
  el("theme-toggle").addEventListener("click", () => {
    const root = document.documentElement;
    const next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
    root.setAttribute("data-theme", next);
    localStorage.setItem("bcssl-theme", next);
  });
}
function showTab(name) {
  document.querySelectorAll("nav button[data-tab]").forEach((b) =>
    b.classList.toggle("active", b.dataset.tab === name));
  TABS.forEach((t) => el("tab-" + t).classList.toggle("hidden", t !== name));
  if (name === "preflight" && !state.preflight) runPreflight();
  if (name === "correlation" && !state.correlation) loadCorrelation();
  if (name === "docs" && !state.docs.length) loadDocs();
}
function initTabs() {
  document.querySelectorAll("nav button[data-tab]").forEach((b) =>
    b.addEventListener("click", () => showTab(b.dataset.tab)));
}

/* ---------- renderers ---------- */
function renderBanner() {
  const t = state.data.target, banner = el("target-banner");
  if (!t.authorized) {
    banner.classList.add("bad");
    banner.innerHTML = "TARGET REJECTED - NOT AUTHORIZED<small>" + esc(t.reason) + "</small>";
    return;
  }
  banner.classList.remove("bad");
  let detail = esc(t.url) + " &middot; ";
  detail += t.reachable
    ? `<span class="ok">reachable</span> (HTTP ${esc(t.status_code)})`
    : `<span class="bad">unreachable</span>: ${esc(t.reachability_error || "no response")}`;
  detail += "<br>" + esc(state.data.authorization_statement || "");
  banner.innerHTML = "AUTHORIZED TARGET<small>" + detail + "</small>";
}

function renderOverview() {
  const counts = {}; SEVERITIES.forEach((s) => { counts[s] = 0; });
  state.findings.forEach((f) => {
    const k = String(f.severity || "INFO").toUpperCase();
    if (counts[k] !== undefined) counts[k] += 1;
  });
  const c = state.data.correlation || { confirmed_by_multiple_tools: 0, single_tool_observations: 0 };
  const cards = [stat(state.findings.length, "Findings")];
  SEVERITIES.forEach((s) => cards.push(stat(counts[s], s)));
  cards.push(stat(c.confirmed_by_multiple_tools, "Corroborated"));
  cards.push(stat(c.single_tool_observations, "Single-tool"));
  el("overview-stats").innerHTML = cards.join("");
}

function toolTable(tools) {
  return `<table><tr><th>Tool</th><th>Status</th><th>Version</th><th>Install hint</th></tr>` +
    tools.map((t) => `<tr>
      <td><strong>${esc(t.tool)}</strong><div class="meta">${esc(t.executable)}</div></td>
      <td class="${t.available ? "ok" : "bad"}">${esc(t.available ? "TOOL AVAILABLE" : t.message)}</td>
      <td class="meta">${esc(t.version || "-")}<div>${esc(t.transport)}</div></td>
      <td class="meta">${esc(t.install_hint || "")}</td></tr>`).join("") + "</table>";
}
function renderTools() {
  el("dashboard-tools").innerHTML = toolTable(state.data.tools);
  el("tool-cards").innerHTML = state.data.tools.map((t) => `<div class="card tight">
      <h3>${esc(t.tool)}</h3>
      <div class="${t.available ? "ok" : "bad"}">${esc(t.available ? "TOOL AVAILABLE" : t.message)}</div>
      <div class="meta">version: ${esc(t.version || "not detected")}</div>
      <div class="meta">transport: ${esc(t.transport)}</div>
      ${t.available ? "" : `<div class="meta">install: ${esc(t.install_hint || "see docs/installation.md")}</div>`}
    </div>`).join("");

  const select = el("tool-select"), cur = select.value;
  select.innerHTML = state.data.tools.map((t) =>
    `<option value="${esc(t.tool)}">${esc(t.tool)}${t.available ? "" : " (not installed)"}</option>`).join("");
  if (cur) select.value = cur;
}

function renderRuns() {
  const runs = state.data.runs || [];
  if (!runs.length) { el("dashboard-runs").innerHTML = empty("No scan results available."); return; }
  el("dashboard-runs").innerHTML = `<table><tr><th>Tool</th><th>Status</th><th>Finished</th>
    <th>Findings</th><th>Notes</th></tr>` + runs.map((r) => {
    const good = r.status === "ok" || r.status === "partial";
    return `<tr><td><strong>${esc(r.tool)}</strong></td>
      <td class="${good ? "ok" : "bad"}">${esc(r.status_label)}</td>
      <td class="meta">${esc(r.finished_at || "-")}</td><td>${esc(r.finding_count)}</td>
      <td class="meta">${esc((r.errors || []).concat(r.warnings || []).join("; ") || "-")}</td></tr>`;
  }).join("") + "</table>";
}

function renderVerification() {
  const counts = {};
  VERIFY_STATUSES.forEach((s) => { counts[s] = 0; });
  state.findings.forEach((f) => {
    const s = String(f.verification_status || "NOT VERIFIED");
    counts[s] = (counts[s] || 0) + 1;
  });
  el("dashboard-verification").innerHTML = VERIFY_STATUSES.map((s) => stat(counts[s] || 0, s)).join("") +
    `<div class="card"><p class="meta">DETECTED = the lab reproduced the condition itself.
     CORROBORATED = two or more tools reported the same fingerprint.
     SINGLE-TOOL OBSERVATION = exactly one tool. NOT VERIFIED = reported but not independently confirmed.</p></div>`;
}

function renderFindings() {
  const sev = el("severity-filter").value, tool = el("tool-filter").value,
        st = el("status-filter").value;
  const tools = [...new Set(state.findings.map((f) => f.tool))];
  const tf = el("tool-filter"), cur = tf.value;
  tf.innerHTML = '<option value="">All</option>' + tools.map((t) =>
    `<option value="${esc(t)}">${esc(t)}</option>`).join("");
  if (cur) tf.value = cur;
  const sf = el("status-filter"), scur = sf.value;
  const statuses = [...new Set(state.findings.map((f) => f.verification_status))];
  sf.innerHTML = '<option value="">All</option>' + statuses.map((s) =>
    `<option value="${esc(s)}">${esc(s)}</option>`).join("");
  if (scur) sf.value = scur;

  if (!state.findings.length) {
    el("findings-list").innerHTML = empty("No scan results available.");
    return;
  }
  const rows = state.findings.filter((f) =>
    (!sev || String(f.severity).toUpperCase() === sev) &&
    (!tool || f.tool === tool) && (!st || f.verification_status === st));
  if (!rows.length) { el("findings-list").innerHTML = empty("No findings match the current filter."); return; }

  rows.sort((a, b) => (SEVERITIES.indexOf(String(b.severity).toUpperCase()) -
                       SEVERITIES.indexOf(String(a.severity).toUpperCase())) ||
                      String(a.title).localeCompare(String(b.title)));
  el("findings-list").innerHTML = rows.map((f) => `<div class="card">
      <div>${sevBadge(f.severity)} <strong>${esc(f.title)}</strong> ${verifyBadge(f.verification_status)}</div>
      <div class="meta">tool: ${esc(f.tool)} &middot; category: ${esc(f.category)} &middot;
        endpoint: <code>${esc(f.endpoint || "-")}</code></div>
      ${f.description ? `<p>${esc(f.description)}</p>` : ""}
      ${f.evidence ? `<pre>${esc(String(f.evidence).slice(0, 800))}</pre>` : ""}
      ${f.recommendation ? `<p><strong>Recommendation:</strong> ${esc(f.recommendation)}</p>` : ""}
    </div>`).join("");
}

function renderEvidence() {
  if (!state.evidence.length) { el("evidence-list").innerHTML = empty("No evidence records yet."); return; }
  el("evidence-list").innerHTML = `<table><tr><th>Tool</th><th>Finding</th><th>Endpoint</th>
    <th>Raw artifact</th><th>SHA-256</th></tr>` + state.evidence.map((r) => `<tr>
      <td>${esc(r.tool)}</td><td>${esc(r.finding_title)}</td>
      <td class="meta"><code>${esc(r.endpoint || "-")}</code></td>
      <td class="meta"><code>${esc(r.raw_artifact || "-")}</code></td>
      <td class="meta"><code>${esc(String(r.raw_sha256 || "").slice(0, 16))}</code></td></tr>`).join("") + "</table>";
}

function renderLab() {
  const box = el("lab-list");
  if (!state.exercises.length) { box.innerHTML = empty("No exercise data available."); return; }
  ["beginner", "intermediate", "advanced"].forEach((level) => {
    const items = state.exercises.filter((e) => e.level === level);
    if (!items.length) return;
    const done = items.filter((e) => e.progress && e.progress.complete).length;
    box.insertAdjacentHTML("beforeend",
      `<h3>${esc(level)} (${done}/${items.length})</h3>` + items.map((e) => exerciseCard(e)).join(""));
  });
}

function exerciseCard(e) {
  const p = e.progress || {};
  const cls = p.complete ? "complete" : (p.started ? "started" : "");
  const mark = p.complete ? "&#10003;" : (p.started ? "&#9679;" : "&#9675;");
  const checks = (e.checklist || []).map((c) => {
    const done = (p.checks_done_ids || []).indexOf(c.id) >= 0;
    return `<label class="meta" style="display:block"><input type="checkbox"
      data-ex="${esc(e.id)}" data-check="${esc(c.id)}" ${done ? "checked" : ""}>
      ${esc(c.id)}. ${esc(c.label)}</label>`;
  }).join("");
  const questions = (e.questions || []).map((q) => `<label class="q">
      <span>${esc(q.id)} [${esc(q.type || "freeform")}${q.gradable ? "" : ", reviewed"}]. ${esc(q.question)}</span>
      <textarea data-ex="${esc(e.id)}" data-q="${esc(q.id)}"
        placeholder="Answer in your own words">${esc(p.answers ? (p.answers[q.id] || "") : "")}</textarea></label>`).join("");

  return `<div class="card ex ${cls}" data-exercise="${esc(e.id)}">
    <h3>${mark} ${esc(e.id)} &mdash; ${esc(e.title)}</h3>
    <div class="meta">tool: ${esc(e.tool)} &middot; command: <code>${esc(e.command)}</code></div>
    <div class="progress"><span style="width:${esc(p.percent || 0)}%"></span></div>
    <div class="meta">${esc(p.percent || 0)}% &middot; checklist ${esc(p.checks_done||0)}/${esc(p.checks_total||0)}
      &middot; questions ${esc(p.questions_answered||0)}/${esc(p.questions_total||0)}
      &middot; evidence ${p.evidence_recorded ? "recorded" : "not recorded"}</div>
    <details><summary class="meta">Objective, task and safety note</summary>
      <p>${esc(e.objective)}</p>
      <p class="meta"><strong>Authorized target:</strong> ${esc(e.authorized_target)}</p>
      <p class="bad">${esc(e.safety_note)}</p>
      <p class="meta"><strong>Expected observation:</strong> ${esc(e.expected_observation)}</p></details>
    <details><summary class="meta">Checklist, questions and evidence</summary>
      ${checks}
      <label class="q"><span>Evidence file(s) you saved (one path per line)</span>
        <textarea data-ex="${esc(e.id)}" data-ev="1"
          placeholder="reports/raw/...">${esc((p.evidence || []).join("\n"))}</textarea></label>
      ${questions}
      <div class="toolbar">
        <button class="primary small" data-ack="${esc(e.id)}">Save acknowledgements</button>
        <button class="small" data-grade="${esc(e.id)}">Check my answers</button>
        <span class="meta" data-grademsg="${esc(e.id)}"></span>
      </div></details></div>`;
}

async function loadCorrelation() {
  const data = await api("/api/correlation");
  state.correlation = data;
  const summary = el("correlation-summary"), list = el("correlation-list");
  if (!data.has_results) {
    summary.innerHTML = ""; list.innerHTML = empty(data.message || "No scan results available.");
    return;
  }
  const s = data.summary;
  summary.innerHTML = `<div class="grid">${stat(s.total_groups, "Groups")}${stat(s.confirmed_by_multiple_tools, "Corroborated")}${stat(s.single_tool_observations, "Single-tool")}${stat(s.contributing_tools.length, "Tools contributing")}</div>`;
  list.innerHTML = data.groups.map((g) => `<div class="card">
      <div>${sevBadge(g.severity)} <strong>${esc(g.title)}</strong></div>
      <div class="meta">${g.confirmed_by_multiple_tools ? '<span class="ok">Confirmed by multiple tools</span>' : '<span class="muted">Single-tool observation</span>'}</div>
      <p class="meta">${esc(g.reasoning || "")}</p>
      <div class="meta">tools: ${esc((g.tools || []).join(", "))}</div>
      <div class="meta">endpoints: ${esc((g.endpoints || []).slice(0, 6).join(", ") || "-")}</div>
      <div class="meta">findings in group: ${esc(g.finding_count)}</div>
    </div>`).join("");
}

async function runPreflight() {
  el("preflight-status").textContent = "running...";
  const data = await api("/api/preflight");
  state.preflight = data;
  el("preflight-status").textContent = data.ready ? "Lab is ready" :
    "Blocking: " + (data.blocking || []).join(", ");
  el("preflight-table").innerHTML = `<pre>${esc(data.table || "")}</pre>`;
  const rem = el("preflight-remedies");
  if (data.remedies) { rem.textContent = data.remedies; rem.classList.remove("hidden"); }
  else rem.classList.add("hidden");
}

async function loadDocs() {
  state.docs = (await api("/api/docs")) || [];
  el("docs-list").innerHTML = state.docs.map((d) => `<label style="display:block;margin:.2rem 0">
      <input type="radio" name="doc" value="${esc(d.path)}"> <strong>${esc(d.title)}</strong>
      <span class="meta">(${esc(d.name)}, ${Math.round(d.bytes / 1024)} KB)</span></label>`).join("") || empty("No documents found.");
  document.querySelectorAll('input[name="doc"]').forEach((r) =>
    r.addEventListener("change", async () => {
      const doc = state.docs.find((x) => x.path === r.value);
      if (!doc) return;
      const pre = el("docs-content");
      const raw = await api("/docs/" + doc.name);
      pre.textContent = typeof raw === "string" ? raw : (raw.error || "");
      pre.classList.remove("hidden");
    }));
}

function renderProgress(data) {
  const s = data.summary || {};
  el("progress-stats").innerHTML = (s.total !== undefined)
    ? stat(s.complete + "/" + s.total, "Exercises complete") +
      Object.keys(s.by_level || {}).map((l) => stat(s.by_level[l].complete + "/" + s.by_level[l].total, l)).join("")
    : empty("No progress data.");
  el("progress-badges").innerHTML = (data.badges || []).length
    ? data.badges.map((b) => `<div class="card tight"><strong>${esc(b.name)}</strong>
        <div class="meta">${esc(b.detail)}</div></div>`).join("")
    : empty("No achievements yet.");
  el("progress-table").innerHTML = `<table><tr><th>Exercise</th><th>Level</th><th>Progress</th>
    <th>Checklist</th><th>Questions</th><th>Evidence</th><th>Status</th></tr>` +
    (data.exercises || []).map((e) => `<tr>
      <td>${esc(e.id)} ${esc(e.title)}</td><td class="meta">${esc(e.level)}</td>
      <td>${esc(e.percent)}%</td><td>${esc(e.checks_done)}/${esc(e.checks_total)}</td>
      <td>${esc(e.questions_answered)}/${esc(e.questions_total)}</td>
      <td>${e.evidence_recorded ? "yes" : "no"}</td>
      <td class="${e.complete ? "ok" : "muted"}">${e.complete ? "COMPLETE" : "in progress"}</td></tr>`).join("") + "</table>";
}

/* ---------- actions ---------- */
async function refresh() {
  state.data = await api("/api/state");
  el("lab-name").textContent = state.data.lab;
  const f = await api("/api/findings");
  state.findings = f.findings || [];
  state.exercises = (await api("/api/exercises")) || [];
  state.evidence = (await api("/api/evidence")) || [];

  renderBanner(); renderOverview(); renderTools(); renderRuns();
  renderVerification(); renderFindings(); renderEvidence();
  el("lab-list").innerHTML = ""; renderLab();
  renderProgress(await api("/api/progress"));

  const rs = state.data.run_state || {};
  if (rs.running) {
    el("run-status").textContent = "running " + (rs.tool || "") + " ...";
    el("run-log").innerHTML = `<pre>${esc((rs.log || []).join("\n"))}</pre>`;
    setTimeout(refresh, 2500);
  } else if (el("run-status").textContent.startsWith("running")) {
    el("run-status").textContent = "finished";
  }
}

async function runTool(tool) {
  el("run-status").textContent = "starting " + tool + " ...";
  const r = await api("/api/run", { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ tool: tool }) });
  if (r.error) { el("run-status").textContent = r.error; return; }
  setTimeout(refresh, 1200);
}

async function runFullAssessment() {
  el("run-status").textContent = "starting full assessment ...";
  const r = await api("/api/run-all", { method: "POST",
    headers: { "Content-Type": "application/json" }, body: "{}" });
  if (r.error) { el("run-status").textContent = r.error; return; }
  setTimeout(refresh, 1500);
}

async function acknowledge(exerciseId) {
  const card = document.querySelector('[data-exercise="' + exerciseId + '"]');
  const checks = [...card.querySelectorAll("input[data-check]")].filter((b) => b.checked).map((b) => b.dataset.check);
  const answers = {};
  card.querySelectorAll("textarea[data-q]").forEach((a) => {
    const v = a.value.trim(); if (v) answers[a.dataset.q] = v;
  });
  const evidence = [];
  card.querySelectorAll("textarea[data-ev]").forEach((a) =>
    a.value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean).forEach((s) => evidence.push(s)));

  const r = await api("/api/ack", { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ exercise_id: exerciseId, checks: checks, answers: answers, evidence: evidence }) });
  if (r.error) { alert(r.error); return; }
  const p = r.progress || {};
  alert(`Saved.\nChecklist ${p.checks_done}/${p.checks_total}, questions ${p.questions_answered}/${p.questions_total}, evidence ${p.evidence_recorded ? "recorded" : "missing"}.\nExercise ${p.complete ? "COMPLETE" : "still incomplete"}.`);
  refresh();
}

async function gradeAnswers(exerciseId) {
  const card = document.querySelector('[data-exercise="' + exerciseId + '"]');
  const answers = {};
  card.querySelectorAll("textarea[data-q]").forEach((a) => {
    const v = a.value.trim(); if (v) answers[a.dataset.q] = v;
  });
  const r = await api("/api/grade", { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ exercise_id: exerciseId, answers: answers }) });
  const msg = el(`grademsg-${exerciseId}`);
  if (r.error) { msg.textContent = r.error; return; }
  msg.innerHTML = `${r.passed}/${r.total} correct. ` + r.results
    .filter((x) => !x.passed)
    .map((x) => `<div>${esc(x.question_id)}: ${esc(x.feedback)}</div>`).join("");
}

async function makeReport() {
  el("report-status").textContent = "generating ...";
  const r = await api("/api/report", { method: "POST" });
  if (r.error) { el("report-status").textContent = r.error; return; }
  el("report-status").textContent = r.has_results
    ? `${r.findings} finding(s); ${r.correlation.confirmed_by_multiple_tools} corroborated`
    : (r.message || "");
  const items = Object.keys(r.files || {}).map((f) =>
    `<li><code>${esc(r.files[f])}</code> (${esc(f)})</li>`).join("");
  el("report-files").innerHTML = `<div class="card"><ul>${items}</ul></div>`;
}

async function probeTarget() {
  const url = el("probe-url").value.trim();
  el("probe-status").textContent = "validating ...";
  const r = await api("/api/validate-target", { method: "POST",
    headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: url }) });
  el("probe-status").textContent = "";
  el("probe-result").innerHTML = `<div class="card ${r.ok ? "" : "bad"}">
    <strong>${r.ok ? "AUTHORIZED" : "REJECTED - NOT AUTHORIZED"}</strong>
    <div class="meta">code: ${esc(r.code)}</div><p>${esc(r.reason)}</p>
    ${r.ok ? `<div class="meta">normalized: ${esc(r.url)} (host ${esc(r.host)}, port ${esc(r.port)})</div>` : ""}</div>`;
}

/* ---------- wiring ---------- */
document.addEventListener("DOMContentLoaded", () => {
  initTheme(); initTabs();

  el("preflight-run").addEventListener("click", runPreflight);
  el("run-selected").addEventListener("click", () => runTool(el("tool-select").value));
  el("run-all").addEventListener("click", runFullAssessment);
  el("run-refresh").addEventListener("click", refresh);
  el("probe-run").addEventListener("click", probeTarget);
  el("make-report").addEventListener("click", makeReport);
  el("severity-filter").addEventListener("change", renderFindings);
  el("tool-filter").addEventListener("change", renderFindings);
  el("status-filter").addEventListener("change", renderFindings);

  document.addEventListener("click", (event) => {
    const ack = event.target.closest("[data-ack]");
    if (ack) { acknowledge(ack.dataset.ack); return; }
    const gr = event.target.closest("[data-grade]");
    if (gr) { gradeAnswers(gr.dataset.grade); }
  });

  refresh();
  setInterval(() => { if (document.visibilityState === "visible") refresh(); }, 20000);
});
