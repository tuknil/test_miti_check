"use strict";

// Default mitigation scenario with the actual log4j artifacts inlined.
const SCENARIO = {
  contract_id: "mitigation-check@1.0",
  candidate_artifact_id: "candidate:log4shell:waf-rule:1",
  test_basis_id: "test-basis:log4shell:true-positive:1",
  check_profile_id: "mitigation-check-profile:waf-http:1",
  substrate_selector: "substrate:log4j-vulnerable-webserver:container",
  substrate: {
    kind: "container-image",
    image: "ghcr.io/christophetd/log4shell-vulnerable-app:latest",
    digest: "sha256:6f88c941c6f2c3a1d1a3d7f0f7f6c0b6f5b4a3c2d1e0f9a8b7c6d5e4f3a2b1c0d",
    port: 8080,
    vulnerability_id: "CVE-2021-44228",
  },
  candidate: {
    kind: "waf-rule",
    engine: "modsecurity",
    rule_id: "1005440",
    action: "deny",
    rule:
      'SecRule REQUEST_HEADERS|REQUEST_HEADERS_NAMES|REQUEST_URI|ARGS|ARGS_NAMES ' +
      '"@rx (?i)\\$\\{jndi:(?:ldaps?|rmi|dns|nis|iiop|corba|nds|https?):/[^}]*\\}" ' +
      '"id:1005440,phase:2,deny,status:403,t:none,t:urlDecodeUni,' +
      "log,msg:'Log4Shell JNDI lookup attempt (CVE-2021-44228)',tag:'CVE-2021-44228\"",
  },
  test_basis: {
    kind: "http-request-attack",
    proof_basis: "verified-vuln-artifact",
    request: {
      method: "GET",
      path: "/",
      headers: {
        "X-Api-Version":
          "${jndi:ldap://127.0.0.1:1389/Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZA==}",
      },
    },
    expected: { classification: "true-positive", blocked: true, status_code: 403 },
  },
};

const form = document.getElementById("run-form");
const payloadEl = document.getElementById("payload");
const submitBtn = document.getElementById("submit-btn");
const apiBaseInput = document.getElementById("api-base");
const statusEl = document.getElementById("composer-status");
const runListEl = document.getElementById("run-list");
const detailEl = document.getElementById("detail");
const composerEl = document.getElementById("composer");
const execToggle = document.getElementById("exec-toggle");
const execNote = document.getElementById("exec-note");

let selectedRunId = null;
let execMode = "local";

const EXEC_NOTES = {
  local: "Runs the substrate on the host Docker daemon.",
  aci: "Runs the substrate as an Azure Container Instance via DefaultAzureCredential (managed identity on ACA; needs Azure config).",
  "aci-sp": "Azure Container Instance authenticated with a service principal (AZURE_TENANT_ID/CLIENT_ID/CLIENT_SECRET) — works from a laptop or ACA.",
  github: "Dispatches a GitHub Actions workflow that runs the scenario, then stores the retrieved result (needs GitHub config).",
};

execToggle.addEventListener("click", (e) => {
  const btn = e.target.closest(".toggle-opt");
  if (!btn) return;
  execMode = btn.dataset.mode;
  execToggle.querySelectorAll(".toggle-opt").forEach((b) =>
    b.classList.toggle("active", b === btn)
  );
  execNote.textContent = EXEC_NOTES[execMode] || "";
});

// Landing view: only the submit composer is shown.
function showLanding() {
  selectedRunId = null;
  detailEl.hidden = true;
  composerEl.hidden = false;
  loadRuns();
}

// Detail view: only the request + response are shown (no submit option).
function showDetail() {
  composerEl.hidden = true;
  detailEl.hidden = false;
}

const esc = (s) =>
  String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

const apiBase = () => (apiBaseInput.value || "").trim().replace(/\/+$/, "");

const STATE_CLASS = {
  blocked: "ok",
  "not-blocked": "warn",
  "could-not-test": "warn",
  malfunction: "err",
};

function setStatus(state, text) {
  statusEl.className = "response " + state;
  statusEl.textContent = text;
}

// ---- Left run panel ----

async function loadRuns() {
  let runs;
  try {
    const res = await fetch(apiBase() + "/v1/mitigation-check-runs");
    runs = await res.json();
  } catch (err) {
    runListEl.innerHTML = `<li class="run-empty">Cannot reach API.</li>`;
    return;
  }
  if (!Array.isArray(runs) || runs.length === 0) {
    runListEl.innerHTML = `<li class="run-empty">No runs yet.</li>`;
    return;
  }
  runListEl.innerHTML = runs
    .map((r) => {
      const cls = STATE_CLASS[r.terminal_state] || "warn";
      const active = r.run_id === selectedRunId ? " active" : "";
      const time = new Date(r.created_at).toLocaleTimeString();
      const mark = r.match ? "✓" : "✗";
      return `
        <li class="run-item${active}" data-run="${esc(r.run_id)}">
          <div class="run-top">
            <span class="dot dot-${cls}"></span>
            <span class="run-state">${esc(r.terminal_state)}</span>
            <span class="run-match run-match-${r.match ? "ok" : "no"}">${mark}</span>
          </div>
          <div class="run-id">${esc(r.run_id)}</div>
          <div class="run-time">${esc(time)}</div>
        </li>`;
    })
    .join("");
}

runListEl.addEventListener("click", (e) => {
  const li = e.target.closest(".run-item");
  if (li) selectRun(li.dataset.run);
});

document.getElementById("refresh-btn").addEventListener("click", loadRuns);
document.getElementById("new-btn").addEventListener("click", showLanding);

// ---- Run detail: immutable request + response ----

async function selectRun(runId) {
  selectedRunId = runId;
  showDetail();
  loadRuns(); // refresh active highlight
  detailEl.innerHTML = `<p class="detail-empty">Loading ${esc(runId)}…</p>`;
  let rec;
  try {
    const res = await fetch(apiBase() + "/v1/mitigation-check-runs/" + encodeURIComponent(runId));
    if (!res.ok) throw new Error("HTTP " + res.status);
    rec = await res.json();
  } catch (err) {
    detailEl.innerHTML = `<p class="detail-empty">Could not load run: ${esc(err.message)}</p>`;
    return;
  }
  renderDetail(rec);
}

function renderDetail(rec) {
  const o = rec.response || {};
  const time = new Date(rec.created_at).toLocaleString();
  detailEl.innerHTML = `
    <div class="detail-head">
      <span class="run-id-lg">${esc(rec.run_id)}</span>
      <span class="detail-time">${esc(time)}</span>
      <button type="button" id="back-btn" class="back-btn">＋ New run</button>
    </div>

    <h3>Request <em class="immutable">immutable</em></h3>`;

  detailEl.querySelector("#back-btn").addEventListener("click", showLanding);

  detailEl.insertAdjacentHTML("beforeend", `
    <pre class="code">${esc(JSON.stringify(rec.request, null, 2))}</pre>

    <h3>Result</h3>
    ${outcomeHTML(o)}`);
}

function outcomeHTML(o) {
  if (!o || !o.terminal_state) return `<div class="response idle">No result.</div>`;
  const cls = STATE_CLASS[o.terminal_state] || "warn";
  const matchBadge = o.match
    ? '<span class="pill pill-ok">✓ actual matches expected</span>'
    : '<span class="pill pill-err">✗ actual ≠ expected</span>';

  const row = (label, exp, act) => `
    <tr><th>${esc(label)}</th><td>${esc(exp)}</td>
    <td class="${exp === act ? "" : "diff"}">${esc(act)}</td></tr>`;

  const exp = o.expected || {};
  const act = o.actual || {};
  const sub = o.substrate || {};
  const steps = (o.steps || []).map((s) => `<li>${esc(s)}</li>`).join("");

  return `
    <div class="response ${cls}">
      <div class="verdict"><span class="state">${esc(o.terminal_state)}</span>${matchBadge}</div>
      <p class="summary">${esc(o.prose_summary || "")}</p>
      <table class="cmp">
        <thead><tr><th></th><th>expected</th><th>actual</th></tr></thead>
        <tbody>
          ${row("blocked", exp.blocked, act.blocked)}
          ${row("status_code", exp.status_code, act.status_code)}
          ${row("reached app", false, act.reached_app)}
          ${act.matched_rule_id ? `<tr><th>matched rule</th><td>—</td><td>${esc(act.matched_rule_id)}</td></tr>` : ""}
        </tbody>
      </table>
      <p class="detail-line">${esc(act.detail || "")}</p>
      <div class="substrate">substrate: ${esc(sub.image || "?")}${
        sub.runner ? " · runner " + esc(sub.runner) : ""
      }${sub.container_id ? " · " + esc(sub.container_id) : ""}${
        sub.fqdn ? " · " + esc(sub.fqdn) : ""
      }${sub.host_port ? " · :" + esc(sub.host_port) : ""} · ready=${!!sub.ready}</div>
      <details><summary>execution steps</summary><ol>${steps}</ol></details>
    </div>`;
}

// ---- Submit a new run ----

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  let payload;
  try {
    payload = JSON.parse(payloadEl.value);
  } catch (err) {
    setStatus("err", "Payload is not valid JSON: " + err.message);
    return;
  }
  // The toggle is authoritative for where the substrate runs.
  payload.execution_mode = execMode;

  const url = apiBase() + "/v1/mitigation-check-runs";
  submitBtn.disabled = true;
  submitBtn.textContent = "Running scenario…";
  setStatus("idle", "Bringing up the container, applying the WAF rule, running the test… (~20–40s)");

  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = await res.json();
    if (res.ok && body.terminal_state) {
      setStatus("ok", "Run complete: " + body.terminal_state + (body.match ? " (matches expected)" : " (differs from expected)"));
      await loadRuns();
      selectRun(body.run_id);
    } else {
      setStatus("err", "HTTP " + res.status + "\n\n" + JSON.stringify(body, null, 2));
    }
  } catch (err) {
    setStatus("err", "Request failed: " + err.message + "\nIs the API running at " + apiBase() + "?");
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "Submit run · POST";
  }
});

// ---- Init ----
payloadEl.value = JSON.stringify(SCENARIO, null, 2);
loadRuns();
