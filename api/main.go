// Package main implements the mitigation-check private ingress API (LLD §6.1).
//
// Step 1 scope: accept a SubmitMitigationCheckRequest@1 (LLD §10.1), validate it
// against the input contract, and return an accepted run reference (LLD §9.1).
// Downstream queueing, workers, and the verdict engine are out of scope for this step.
package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"crypto/rand"
)

const contractID = "mitigation-check@1.0"

// upstreamContractID is the contract of the incoming defense-generation payload
// that now carries the mitigation rule (primary_candidate.artifact_content).
const upstreamContractID = "defense-generation@1.0"

//go:embed openapi.yaml
var openapiSpec []byte

// maxBodyBytes bounds request payloads at the API edge (LLD §3.4, §13.7).
const maxBodyBytes = 64 * 1024

// SubmitMitigationCheckRequest mirrors the request contract in LLD §10.1, plus
// inline artifact bodies. The reference IDs remain authoritative; the nested
// `substrate` / `candidate` / `test_basis` objects carry the actual artifact
// content (container image, WAF rule, attack test) so a run is self-describing.
type SubmitMitigationCheckRequest struct {
	ContractID          string          `json:"contract_id"`
	CandidateArtifactID string          `json:"candidate_artifact_id"`
	TestBasisID         string          `json:"test_basis_id"`
	SubstrateSelector   string          `json:"substrate_selector,omitempty"`
	CheckProfileID      string          `json:"check_profile_id"`
	Substrate           json.RawMessage `json:"substrate,omitempty"`
	Candidate           json.RawMessage `json:"candidate,omitempty"`
	TestBasis           json.RawMessage `json:"test_basis,omitempty"`
	// ExecutionMode selects the substrate adapter. Defaults to "inmemory" when
	// omitted; other values include "local" (docker), "aci"/"aci-sp", "github",
	// "github-ghcr", and "firewall".
	ExecutionMode string `json:"execution_mode,omitempty"`
	// CorrelationID is echoed into the result envelope (optional).
	CorrelationID string `json:"correlation_id,omitempty"`

	// --- Upstream defense-generation payload (new input contract) ---
	// The mitigation rule is taken from primary_candidate.artifact_content. The
	// remaining envelope fields are accepted (so a full defense-generation result
	// validates) but not yet consumed; upstream_inputs will later carry the test.
	PrimaryCandidateRaw json.RawMessage `json:"primary_candidate,omitempty"`
	AttemptHistory      json.RawMessage `json:"attempt_history,omitempty"`
	OutcomeReason       json.RawMessage `json:"outcome_reason,omitempty"`
	ProofHandoffs       json.RawMessage `json:"proof_handoffs,omitempty"`
	UpstreamInputs      json.RawMessage `json:"upstream_inputs,omitempty"`
	UpstreamResultRef   json.RawMessage `json:"result_ref,omitempty"`
	ProducedAt          string          `json:"produced_at,omitempty"`
	UpstreamProse       string          `json:"prose_summary,omitempty"`
	UpstreamResultID    string          `json:"result_id,omitempty"`
	UpstreamTerminal    string          `json:"terminal_state,omitempty"`
}

// PrimaryCandidate is the upstream defense-generation candidate. artifact_content
// carries the actual mitigation rule (a ModSecurity SecRule).
type PrimaryCandidate struct {
	ArtifactContent      string `json:"artifact_content"`
	ArtifactType         string `json:"artifact_type"`
	CandidateID          string `json:"candidate_id"`
	CandidateKind        string `json:"candidate_kind"`
	Discriminator        string `json:"discriminator"`
	SelectedControlClass string `json:"selected_control_class"`
}

// SubstrateSpec is the inline validation substrate — a bounded, non-production
// container image to host the candidate against (LLD §2.2, §3.4).
type SubstrateSpec struct {
	Kind            string `json:"kind"`
	Image           string `json:"image"`
	Digest          string `json:"digest"`
	Port            int    `json:"port"`
	VulnerabilityID string `json:"vulnerability_id"`
}

// CandidateSpec is the inline candidate mitigation — here, a WAF rule.
type CandidateSpec struct {
	Kind   string `json:"kind"`
	Engine string `json:"engine"`
	RuleID string `json:"rule_id"`
	Rule   string `json:"rule"`
	Action string `json:"action"`
}

// TestBasisSpec is the inline attack/discriminator sample and expected outcome.
type TestBasisSpec struct {
	Kind       string       `json:"kind"`
	ProofBasis string       `json:"proof_basis"`
	Request    TestRequest  `json:"request"`
	Expected   TestExpected `json:"expected"`
}

type TestRequest struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

type TestExpected struct {
	Classification string `json:"classification"`
	Blocked        *bool  `json:"blocked"`
	StatusCode     int    `json:"status_code"`
}

// AcceptedRunResponse is the accepted run reference returned on submit (LLD §9.1).
type AcceptedRunResponse struct {
	RunID    string `json:"run_id"`
	ResultID string `json:"result_id"`
	Status   string `json:"status"`
}

// APIError is the controlled error envelope (LLD §9.5). It never carries stack
// traces, credentials, tokens, or unredacted attack payloads.
type APIError struct {
	Category string   `json:"category"`
	Message  string   `json:"message"`
	Fields   []string `json:"fields,omitempty"`
}

var store *RunStore
var dbx *DatabricksSink

// upstreamInputMode selects the separate upstream executor: the mitigation rule is
// read from a Databricks table referenced by the request's upstream_inputs, instead
// of the inline candidate. On by default; set env MC_INPUT_UPSTREAM=0 to disable.
var upstreamInputMode bool

// dbxReader reads upstream result_json rows from Databricks (upstream mode only).
var dbxReader *DatabricksReader

func main() {
	// CLI mode used by the GitHub Actions workflow: run one scenario locally
	// (docker on the runner) and print the RunOutcome JSON to stdout. No DB.
	if len(os.Args) > 2 && os.Args[1] == "run-scenario" {
		runScenarioCLI(os.Args[2])
		return
	}
	// CLI: convert an http-probe stimulus (file arg or stdin) into a TestBasisSpec.
	if len(os.Args) > 1 && os.Args[1] == "stimulus-to-testbasis" {
		stimulusCLI(os.Args[2:])
		return
	}

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://mc:mc@localhost:5432/mitigation?sslmode=disable"
	}
	s, err := NewRunStore(dsn)
	if err != nil {
		log.Fatalf("could not open run ledger: %v", err)
	}
	store = s

	// Optional secondary sink (Databricks Delta). nil when DATABRICKS_DSN is unset.
	dbx = NewDatabricksSink()

	// Separate upstream executor (rule read from Databricks) — toggled by env, and
	// ON by default; set MC_INPUT_UPSTREAM to 0/false/no to use the legacy executor.
	v := strings.ToLower(strings.TrimSpace(os.Getenv("MC_INPUT_UPSTREAM")))
	if v == "" {
		v = "1"
	}
	if v == "1" || v == "true" || v == "yes" {
		upstreamInputMode = true
		dbxReader = NewDatabricksReader()
		log.Printf("input contract: UPSTREAM mode (rule read from Databricks via upstream_inputs)")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/mitigation-check-runs", withCORS(handleRunsCollection))
	mux.HandleFunc("/v1/mitigation-check-runs/", withCORS(handleRunItem))
	mux.HandleFunc("/healthz", withCORS(handleHealth))
	mux.HandleFunc("/openapi.yaml", withCORS(handleOpenAPI))
	mux.HandleFunc("/docs", withCORS(handleDocs))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8090"
	}
	srv := &http.Server{Addr: ":" + port, Handler: mux}

	// On SIGINT/SIGTERM (docker stop) stop accepting requests, then fall through
	// so main can shut the embedded Postgres down cleanly before exiting.
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		log.Print("shutting down…")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	log.Printf("mitigation-check API listening on %s", srv.Addr)
	err = srv.ListenAndServe()
	store.Close() // synchronous: guarantees postgres stops cleanly before exit
	dbx.Close()
	dbxReader.Close()
	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

// handleOpenAPI serves the embedded OpenAPI 3 spec.
// enrichEnvelope fills the result-envelope fields on the outcome: capability /
// contract, workflow status, the echoed correlation id, evidence refs, and a
// result_ref pointing at the Databricks row (keyed by run_id + result_id, the
// same values written to that table so a consumer can query it).
func enrichEnvelope(out *RunOutcome, correlationID string) {
	out.Capability = "mitigation-check"
	out.ContractID = contractID
	out.CorrelationID = correlationID
	out.EvidenceRefs = []string{}
	if out.TerminalState == stateMalfunction {
		out.Status = "failed"
	} else {
		out.Status = "completed"
	}
	out.ResultRef = &ResultRef{
		System:  "databricks",
		Catalog: os.Getenv("DATABRICKS_CATALOG"),
		Schema:  os.Getenv("DATABRICKS_SCHEMA"),
		Table:   firstNonEmpty(os.Getenv("DATABRICKS_TABLE"), "mitigation_check"),
		Key:     out.ResultID,
	}
}

// runScenarioCLI executes one scenario file and prints the RunOutcome JSON to
// stdout. Used by the GitHub Actions workflow; keeps stdout JSON-only.
func runScenarioCLI(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read scenario: %v", err)
	}
	var req SubmitMitigationCheckRequest
	if err := json.Unmarshal(data, &req); err != nil {
		log.Fatalf("parse scenario: %v", err)
	}
	req.ExecutionMode = execLocal // on the runner, use docker
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	out := executeScenario(ctx, req, "mc-run-"+newID(), resultIDPrefix+newID())
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

func handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(openapiSpec)
}

// handleDocs serves a Swagger UI page pointed at the embedded spec. The Swagger
// UI assets load from a CDN, so viewing /docs needs internet access.
func handleDocs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(swaggerHTML))
}

const swaggerHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>mitigation-check API — Swagger</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"/>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.ui = SwaggerUIBundle({
      url: 'openapi.yaml',
      dom_id: '#swagger-ui',
      deepLinking: true,
      tryItOutEnabled: true
    });
  </script>
</body>
</html>`

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, APIError{Category: "invalid-input", Message: "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleRunsCollection routes the /v1/mitigation-check-runs collection:
// GET lists runs (LLD §9.2), POST submits a new run (LLD §9.1).
func handleRunsCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, store.List())
	case http.MethodPost:
		handleSubmitRun(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, APIError{
			Category: "invalid-input", Message: "method not allowed",
		})
	}
}

// handleRunItem returns one run's immutable request + response (LLD §9.2/§9.3).
func handleRunItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, APIError{
			Category: "invalid-input", Message: "method not allowed",
		})
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v1/mitigation-check-runs/")
	rec, ok := store.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, APIError{
			Category: "invalid-input", Message: "run not found",
		})
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

// handleSubmitRun implements POST /v1/mitigation-check-runs (LLD §9.1).
func handleSubmitRun(w http.ResponseWriter, r *http.Request) {
	req, raw, apiErr := decodeRequest(r)
	if apiErr != nil {
		writeError(w, http.StatusBadRequest, *apiErr)
		return
	}

	if fields := validate(req); len(fields) > 0 {
		writeError(w, http.StatusBadRequest, APIError{
			Category: "invalid-input",
			Message:  "request does not satisfy mitigation-check@1.0 contract",
			Fields:   fields,
		})
		return
	}

	// Execute the scenario synchronously: bring up the substrate container, apply
	// the candidate WAF rule, run the supplied test, and resolve a terminal state
	// (LLD §5, §6.4, §6.5). Bounded by a request-scoped timeout.
	runID := "mc-run-" + newID()
	resultID := resultIDPrefix + newID()

	// GitHub runs dispatch a remote workflow (checkout + build + docker pull +
	// run), which takes longer than a local container bring-up.
	budget := 3 * time.Minute
	switch req.ExecutionMode {
	case execGitHub, execGitHubGHCR:
		budget = 12 * time.Minute
	case execACI, execACISP:
		budget = 10 * time.Minute // ACI provisioning + image pull + app start
	}
	ctx, cancel := context.WithTimeout(r.Context(), budget)
	defer cancel()

	var outcome RunOutcome
	if upstreamInputMode {
		outcome = executeScenarioUpstream(ctx, req, runID, resultID)
	} else {
		outcome = executeScenario(ctx, req, runID, resultID)
	}
	enrichEnvelope(&outcome, req.CorrelationID)

	// Secondary sink: write the result to the Databricks table synchronously so the
	// envelope's status can reflect the write. terminal_state stays the test result;
	// only status degrades to "storage-failed" when the write fails (the run is not
	// a hard failure). A malfunction is already "failed", so a write failure there
	// doesn't change it — but the row is still written for diagnostics.
	if dbx != nil {
		if err := dbx.Write(ctx, outcome); err != nil && outcome.TerminalState != stateMalfunction {
			outcome.Status = "storage-failed"
		}
	}

	// Record the run in the ledger (source of truth) with the exact immutable
	// request bytes and the final envelope (including the resolved status).
	if err := store.Add(&RunRecord{
		RunID:         runID,
		ResultID:      resultID,
		TerminalState: outcome.TerminalState,
		Match:         outcome.Match,
		CreatedAt:     time.Now().UTC(),
		Request:       raw,
		Response:      outcome,
	}); err != nil {
		log.Printf("ledger: failed to persist run %s: %v", runID, err)
	}

	writeJSON(w, http.StatusOK, outcome)
}

// decodeRequest reads and strictly decodes the body, rejecting unknown fields to
// honor the contract's additionalProperties:false (LLD §10.1). It also returns the
// exact raw bytes so the run ledger can store the immutable request.
func decodeRequest(r *http.Request) (SubmitMitigationCheckRequest, json.RawMessage, *APIError) {
	var req SubmitMitigationCheckRequest

	raw, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxBodyBytes))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return req, nil, &APIError{Category: "invalid-input", Message: "request body too large"}
		}
		return req, nil, &APIError{Category: "invalid-input", Message: "could not read request body"}
	}
	if len(raw) == 0 {
		return req, nil, &APIError{Category: "invalid-input", Message: "request body is empty"}
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return req, nil, &APIError{
				Category: "invalid-input",
				Message:  "request contains fields not permitted by the contract",
			}
		}
		return req, nil, &APIError{Category: "invalid-input", Message: "request body is not valid JSON"}
	}

	// Guard against trailing garbage after the JSON object.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return req, nil, &APIError{Category: "invalid-input", Message: "request body must contain a single JSON object"}
	}
	return req, json.RawMessage(raw), nil
}

// validate enforces the SubmitMitigationCheckRequest@1 field rules (LLD §10.1)
// and returns the names of every offending field.
func validate(req SubmitMitigationCheckRequest) []string {
	var bad []string
	// In upstream-input mode the rule is read from Databricks via upstream_inputs, so
	// the legacy reference ids are not required and the upstream contract is accepted.
	if req.ContractID != contractID && !(upstreamInputMode && req.ContractID == upstreamContractID) {
		bad = append(bad, "contract_id")
	}
	if upstreamInputMode {
		if len(req.UpstreamInputs) == 0 {
			bad = append(bad, "upstream_inputs")
		}
	} else {
		if strings.TrimSpace(req.CandidateArtifactID) == "" {
			bad = append(bad, "candidate_artifact_id")
		}
		if strings.TrimSpace(req.TestBasisID) == "" {
			bad = append(bad, "test_basis_id")
		}
		if strings.TrimSpace(req.CheckProfileID) == "" {
			bad = append(bad, "check_profile_id")
		}
	}
	// substrate_selector is optional (LLD §10.1) — no constraint.

	// execution_mode is optional; when set it must be a known adapter.
	if m := req.ExecutionMode; m != "" && m != execLocal && m != execInMemory && m != execACI && m != execACISP && m != execGitHub && m != execGitHubGHCR && m != execFirewall {
		bad = append(bad, "execution_mode")
	}

	// Nested artifact bodies are optional, but validated when present.
	if len(req.Substrate) > 0 {
		var s SubstrateSpec
		if err := json.Unmarshal(req.Substrate, &s); err != nil {
			bad = append(bad, "substrate")
		} else {
			if s.Kind == "" {
				bad = append(bad, "substrate.kind")
			}
			if strings.TrimSpace(s.Image) == "" {
				bad = append(bad, "substrate.image")
			}
		}
	}
	if len(req.Candidate) > 0 {
		var c CandidateSpec
		if err := json.Unmarshal(req.Candidate, &c); err != nil {
			bad = append(bad, "candidate")
		} else {
			if c.Kind == "" {
				bad = append(bad, "candidate.kind")
			}
			if strings.TrimSpace(c.Rule) == "" {
				bad = append(bad, "candidate.rule")
			}
		}
	}
	if len(req.TestBasis) > 0 {
		var t TestBasisSpec
		if err := json.Unmarshal(req.TestBasis, &t); err != nil {
			bad = append(bad, "test_basis")
		} else {
			if t.Kind == "" {
				bad = append(bad, "test_basis.kind")
			}
			// Proof basis must be one of the two admitted values (LLD §7.1).
			if t.ProofBasis != "verified-vuln-artifact" && t.ProofBasis != "mitigation-discriminator" {
				bad = append(bad, "test_basis.proof_basis")
			}
			if t.Expected.Blocked == nil {
				bad = append(bad, "test_basis.expected.blocked")
			}
		}
	}
	return bad
}

func withCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, e APIError) {
	writeJSON(w, status, map[string]APIError{"error": e})
}

// newID returns a short random hex identifier for run/result references.
func newID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}
