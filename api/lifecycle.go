package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	submissionContractID = "mitigation-check-run-submission@1.0"
	statusContractID     = "capability-run-status@1.0"
)

type SubmissionResponse struct {
	Capability    string    `json:"capability"`
	ContractID    string    `json:"contract_id"`
	RequestID     string    `json:"request_id"`
	CorrelationID string    `json:"correlation_id"`
	RunID         string    `json:"run_id"`
	Status        string    `json:"status"`
	StatusURL     string    `json:"status_url"`
	ResultURL     string    `json:"result_url"`
	AcceptedAt    time.Time `json:"accepted_at"`
}

type LifecycleError struct {
	Code      string `json:"code"`
	Detail    string `json:"detail"`
	Retryable bool   `json:"retryable"`
}

func handleRunsCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		handleAsyncSubmit(w, r)
	case http.MethodGet:
		writeJSON(w, http.StatusOK, store.List())
	default:
		writeLifecycleError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed", false)
	}
}

func handleRunItem(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/mitigation-check-runs/"), "/")
	parts := strings.Split(path, "/")
	if path == "" || len(parts) > 2 {
		writeLifecycleError(w, http.StatusNotFound, "run_not_found", "Run not found", false)
		return
	}
	runID := parts[0]
	if len(parts) == 1 && r.Method == http.MethodGet {
		handleRunStatus(w, r, runID)
		return
	}
	if len(parts) == 2 && parts[1] == "result" && r.Method == http.MethodGet {
		handleRunResult(w, r, runID)
		return
	}
	if len(parts) == 2 && parts[1] == "cancel" && r.Method == http.MethodPost {
		handleRunCancel(w, r, runID)
		return
	}
	writeLifecycleError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed", false)
}

func handleAsyncSubmit(w http.ResponseWriter, r *http.Request) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeLifecycleError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json", false)
		return
	}
	requestID := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	correlationID := strings.TrimSpace(r.Header.Get("X-Correlation-ID"))
	if requestID == "" || correlationID == "" {
		writeLifecycleError(w, http.StatusBadRequest, "missing_required_header", "Idempotency-Key and X-Correlation-ID are required", false)
		return
	}
	callback, callbackErr := callbackMetadataFromHeaders(r.Header, callbackAllowedHosts())
	if callbackErr != nil {
		writeLifecycleError(w, http.StatusBadRequest, callbackErr.Code, callbackErr.Detail, callbackErr.Retryable)
		return
	}
	req, _, apiErr := decodeRequest(r)
	if apiErr != nil {
		writeLifecycleError(w, http.StatusBadRequest, "invalid_request", apiErr.Message, false)
		return
	}
	// Migration-safe: request_id may be omitted from the body and is then sourced
	// from Idempotency-Key. If present, every identity must align exactly.
	if req.RequestID == "" {
		req.RequestID = requestID
	}
	if req.CorrelationID == "" {
		req.CorrelationID = correlationID
	}
	if req.RequestID != requestID || req.CorrelationID != correlationID {
		writeLifecycleError(w, http.StatusBadRequest, "request_identity_mismatch", "request_id, Idempotency-Key, correlation_id, and X-Correlation-ID must align", false)
		return
	}
	normalizeRequestDefaults(&req)
	if fields := validate(req); len(fields) > 0 {
		writeLifecycleError(w, http.StatusBadRequest, "invalid_request", "Request does not satisfy mitigation-check@1.0: "+strings.Join(fields, ", "), false)
		return
	}
	if req.Callback != nil {
		writeLifecycleError(w, http.StatusBadRequest, "invalid_callback_location", "Completion callbacks must be supplied with the X-Janus-Callback-* headers", false)
		return
	}
	normalized, digest, err := normalizedRequest(req)
	if err != nil {
		writeLifecycleError(w, http.StatusBadRequest, "invalid_request", "Request could not be normalized", false)
		return
	}
	now := time.Now().UTC()
	resultID := resultIDPrefix + newID()
	run := DurableRun{RunStatus: RunStatus{Capability: "mitigation-check", ContractID: statusContractID,
		RequestID: req.RequestID, CorrelationID: req.CorrelationID, RunID: "mc-run-" + newID(), Status: statusQueued,
		ResultID: &resultID, CreatedAt: now, UpdatedAt: now, Progress: Progress{Phase: "queued", Message: "Awaiting worker"}},
		Request: normalized, RequestDigest: digest}
	if callback.URL != "" {
		run.CallbackURL = callback.URL
		run.CallbackWorkflowID = callback.WorkflowID
		run.CallbackSignal = callback.Signal
		run.CallbackEventID = "mitigation-check:" + run.RunID + ":terminal:v1"
		if strings.TrimSpace(os.Getenv("CAPABILITY_CALLBACK_TOKEN")) == "" {
			log.Printf("callback_configuration_error request_id=%q reason=%q", req.RequestID, "CAPABILITY_CALLBACK_TOKEN is not configured")
		}
	}
	stored, created, err := store.CreateOrGet(r.Context(), run)
	if err != nil {
		logLifecycle("run_submission_failed", run, map[string]any{"error": err.Error()})
		writeLifecycleError(w, http.StatusInternalServerError, "ledger_unavailable", "Could not persist the run", true)
		return
	}
	if stored.RequestDigest != digest {
		writeLifecycleError(w, http.StatusConflict, "idempotency_conflict", "Idempotency-Key was already used with a different normalized request", false)
		return
	}
	if stored.CallbackURL != run.CallbackURL || stored.CallbackWorkflowID != run.CallbackWorkflowID || stored.CallbackSignal != run.CallbackSignal {
		writeLifecycleError(w, http.StatusConflict, "idempotency_callback_conflict", "Idempotency-Key was already used with different callback metadata", false)
		return
	}
	if callback.URL != "" {
		logLifecycle("callback_metadata_accepted", stored, map[string]any{
			"callback_workflow_id": stored.CallbackWorkflowID,
			"callback_signal":      stored.CallbackSignal,
			"callback_token":       "[REDACTED]",
		})
	}
	code := http.StatusAccepted
	if !created && terminalStatus(stored.Status) {
		code = http.StatusOK
	}
	writeJSON(w, code, submissionFrom(stored))
	logLifecycle("run_submitted", stored, map[string]any{"created": created})
}

func normalizeRequestDefaults(req *SubmitMitigationCheckRequest) {
	if req.ExecutionMode == "" {
		req.ExecutionMode = execInMemory
	}
	if len(req.TestBasis) == 0 {
		return
	}
	var basis TestBasisSpec
	if json.Unmarshal(req.TestBasis, &basis) != nil {
		return
	}
	if basis.Request.Method == "" {
		basis.Request.Method = http.MethodGet
	}
	if basis.Request.Path == "" {
		basis.Request.Path = "/"
	}
	if basis.Request.Headers == nil {
		basis.Request.Headers = map[string]string{}
	}
	if normalized, err := json.Marshal(basis); err == nil {
		req.TestBasis = normalized
	}
}

func normalizedRequest(req SubmitMitigationCheckRequest) (json.RawMessage, string, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return nil, "", err
	}
	var value any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err = dec.Decode(&value); err != nil {
		return nil, "", err
	}
	data, err = json.Marshal(value)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(data)
	return data, "sha256:" + hex.EncodeToString(sum[:]), nil
}

func submissionFrom(run DurableRun) SubmissionResponse {
	return SubmissionResponse{Capability: "mitigation-check", ContractID: submissionContractID,
		RequestID: run.RequestID, CorrelationID: run.CorrelationID, RunID: run.RunID, Status: run.Status,
		StatusURL: "/v1/mitigation-check-runs/" + run.RunID, ResultURL: "/v1/mitigation-check-runs/" + run.RunID + "/result", AcceptedAt: run.CreatedAt}
}

func handleRunStatus(w http.ResponseWriter, r *http.Request, id string) {
	status, err := store.GetStatus(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeLifecycleError(w, http.StatusNotFound, "run_not_found", "Run not found", false)
		return
	}
	if err != nil {
		writeLifecycleError(w, http.StatusInternalServerError, "ledger_unavailable", "Could not read run status", true)
		return
	}
	writeJSON(w, http.StatusOK, publicRunStatus(status))
}
func handleRunResult(w http.ResponseWriter, r *http.Request, id string) {
	run, err := store.GetDurable(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeLifecycleError(w, http.StatusNotFound, "run_not_found", "Run not found", false)
		return
	}
	if err != nil {
		writeLifecycleError(w, http.StatusInternalServerError, "ledger_unavailable", "Could not read run result", true)
		return
	}
	if !terminalStatus(run.Status) {
		writeLifecycleError(w, http.StatusConflict, "run_not_terminal", "Run is not terminal", false)
		return
	}
	if run.Status == statusCompleted && run.Result != nil {
		if len(run.ResultPayload) == 0 {
			writeLifecycleError(w, http.StatusInternalServerError, "result_payload_unavailable", "Canonical result payload is unavailable", true)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(run.ResultPayload)
		return
	}
	writeJSON(w, http.StatusOK, publicStatus(run))
}
func handleRunCancel(w http.ResponseWriter, r *http.Request, id string) {
	run, err := store.Cancel(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		writeLifecycleError(w, http.StatusNotFound, "run_not_found", "Run not found", false)
		return
	}
	if err != nil {
		writeLifecycleError(w, http.StatusInternalServerError, "ledger_unavailable", "Could not cancel run", true)
		return
	}
	logLifecycle("cancellation_requested", run, nil)
	writeJSON(w, http.StatusOK, publicStatus(run))
}
func publicStatus(run DurableRun) RunStatus {
	return publicRunStatus(run.RunStatus)
}
func publicRunStatus(status RunStatus) RunStatus {
	if status.Status != statusCompleted {
		status.ResultID = nil
		status.Completion = nil
	}
	return status
}
func terminalStatus(status string) bool {
	return status == statusCompleted || status == statusFailed || status == statusCanceled
}

func writeLifecycleError(w http.ResponseWriter, status int, code, detail string, retryable bool) {
	writeJSON(w, status, LifecycleError{Code: code, Detail: detail, Retryable: retryable})
}

func executionContext(parent context.Context) (context.Context, context.CancelFunc) {
	raw := strings.TrimSpace(os.Getenv("MC_EXECUTION_TIMEOUT"))
	if raw == "" || raw == "0" {
		return context.WithCancel(parent)
	}
	timeout, err := time.ParseDuration(raw)
	if err != nil || timeout <= 0 {
		log.Printf("invalid MC_EXECUTION_TIMEOUT %q; execution timeout disabled", raw)
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, timeout)
}

func executeDurableRun(ctx context.Context, run DurableRun) (RunOutcome, error) {
	var req SubmitMitigationCheckRequest
	if err := json.Unmarshal(run.Request, &req); err != nil {
		return RunOutcome{}, fmt.Errorf("decode persisted request: %w", err)
	}
	ctx, cancel := executionContext(ctx)
	defer cancel()
	out := executeRequestedScenario(ctx, req, run.RunID, *run.ResultID)
	out.RequestID = run.RequestID
	out.RequestSHA256 = run.RequestDigest
	if len(req.UpstreamInputs) > 0 {
		out.UpstreamInputs = append(json.RawMessage(nil), req.UpstreamInputs...)
		out.EvidenceRefs = upstreamEvidenceRefs(req.UpstreamInputs)
	}
	enrichEnvelope(&out, run.CorrelationID)
	out.CreatedAt = time.Now().UTC()
	if err := setCanonicalIntegrity(&out); err != nil {
		return RunOutcome{}, err
	}
	return out, nil
}

func executeRequestedScenario(ctx context.Context, req SubmitMitigationCheckRequest, runID, resultID string) RunOutcome {
	if v2LocatorMode(req) {
		return executeSharedContractV2(ctx, req, runID, resultID)
	}
	if locatorMode(req) {
		return executeScenarioByLocator(ctx, req, runID, resultID)
	}
	if upstreamInputMode && len(req.UpstreamInputs) > 0 {
		return executeScenarioUpstream(ctx, req, runID, resultID)
	}
	return executeScenario(ctx, req, runID, resultID)
}

func setCanonicalIntegrity(out *RunOutcome) error {
	unsigned := *out
	unsigned.ContentSHA256 = ""
	unsigned.SizeBytes = 0
	payload, err := json.Marshal(unsigned)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(payload)
	out.ContentSHA256 = "sha256:" + hex.EncodeToString(sum[:])
	out.SizeBytes = int64(len(payload))
	return nil
}

func upstreamEvidenceRefs(raw json.RawMessage) []string {
	entries, err := parseUpstreamInputs(raw)
	if err != nil {
		return []string{}
	}
	seen := make(map[string]struct{})
	refs := make([]string, 0)
	for _, entry := range entries {
		for _, ref := range entry.EvidenceRefs {
			if ref == "" {
				continue
			}
			if _, exists := seen[ref]; exists {
				continue
			}
			seen[ref] = struct{}{}
			refs = append(refs, ref)
		}
	}
	return refs
}
