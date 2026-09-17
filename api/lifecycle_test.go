package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestExecutionContextDefaultsToUnboundedAndSupportsMultiHourTimeout(t *testing.T) {
	t.Setenv("MC_EXECUTION_TIMEOUT", "")
	ctx, cancel := executionContext(context.Background())
	defer cancel()
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		t.Fatal("default execution context has a deadline")
	}

	t.Setenv("MC_EXECUTION_TIMEOUT", "6h")
	ctx, cancel = executionContext(context.Background())
	defer cancel()
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		t.Fatal("configured execution context has no deadline")
	}
	remaining := time.Until(deadline)
	if remaining < 5*time.Hour+59*time.Minute || remaining > 6*time.Hour {
		t.Fatalf("configured deadline remaining=%s, want approximately 6h", remaining)
	}
}

func TestCanonicalResultIntegrityExcludesIntegrityFields(t *testing.T) {
	outcome := RunOutcome{
		Capability: "mitigation-check", ContractID: contractID, RequestID: "request:integrity",
		RunID: "run:integrity", ResultID: "result:integrity", Status: statusCompleted,
		TerminalState: stateBlocked, EvidenceRefs: []string{}, CreatedAt: time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC),
	}
	if err := setCanonicalIntegrity(&outcome); err != nil {
		t.Fatal(err)
	}
	unsigned := outcome
	unsigned.ContentSHA256 = ""
	unsigned.SizeBytes = 0
	payload, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	wantDigest := "sha256:" + hex.EncodeToString(digest[:])
	if outcome.ContentSHA256 != wantDigest || outcome.SizeBytes != int64(len(payload)) {
		t.Fatalf("integrity=%q/%d, want canonical payload %q/%d", outcome.ContentSHA256, outcome.SizeBytes, wantDigest, len(payload))
	}
	if bytes.Contains(payload, []byte(`"content_sha256"`)) || bytes.Contains(payload, []byte(`"size_bytes"`)) {
		t.Fatalf("canonical payload contains integrity fields: %s", payload)
	}
}

func TestSharedProfileCanonicalResultPayloadUsesRFC8785Integrity(t *testing.T) {
	outcome := RunOutcome{
		Capability: "mitigation-check", ContractID: contractID, RequestID: "request:shared-integrity",
		RunID: "run:shared-integrity", ResultID: "result:shared-integrity", Status: statusCompleted,
		TerminalState: stateBlocked, ProfileID: sharedV2ProfileID, EvidenceRefs: []string{},
		CreatedAt:  time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC),
		Accounting: &CoverageAccounting{RequiredObligationCount: 2, AccountedObligationCount: 2},
	}
	if err := setCanonicalIntegrity(&outcome); err != nil {
		t.Fatal(err)
	}
	payload, err := canonicalResultPayload(outcome)
	if err != nil {
		t.Fatalf("shared-profile canonicalResultPayload: %v", err)
	}
	if err := validateCanonicalResultPayload(outcome, payload); err != nil {
		t.Fatalf("shared-profile payload validation: %v", err)
	}
}

func validLifecycleRequest(id string) SubmitMitigationCheckRequest {
	blocked := true
	testBasis, _ := json.Marshal(TestBasisSpec{Kind: "http-request-attack", ProofBasis: "mitigation-discriminator", Expected: TestExpected{Blocked: &blocked}})
	candidate, _ := json.Marshal(CandidateSpec{Kind: "waf-rule", Rule: `SecRule REQUEST_BODY "@rx attack" "deny,status:403"`})
	return SubmitMitigationCheckRequest{ContractID: contractID, RequestID: id, CorrelationID: "correlation-1",
		CandidateArtifactID: "candidate-1", TestBasisID: "basis-1", CheckProfileID: "profile-1",
		ExecutionMode: execInMemory, Candidate: candidate, TestBasis: testBasis}
}

func TestNormalizedRequestIgnoresJSONFormatting(t *testing.T) {
	req := validLifecycleRequest("request-1")
	_, first, err := normalizedRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.MarshalIndent(req, "", "  ")
	var decoded SubmitMitigationCheckRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	_, second, err := normalizedRequest(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || !strings.HasPrefix(first, "sha256:") || len(first) != 71 {
		t.Fatalf("normalized digests differ: %q %q", first, second)
	}
}

func TestAsyncSubmitRequiresLifecycleHeaders(t *testing.T) {
	body, _ := json.Marshal(validLifecycleRequest("request-1"))
	req := httptest.NewRequest(http.MethodPost, "/v1/mitigation-check-runs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handleAsyncSubmit(response, req)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "missing_required_header") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAsyncSubmitRejectsIdentityMismatchBeforePersistence(t *testing.T) {
	body, _ := json.Marshal(validLifecycleRequest("body-request"))
	req := httptest.NewRequest(http.MethodPost, "/v1/mitigation-check-runs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "header-request")
	req.Header.Set("X-Correlation-ID", "correlation-1")
	response := httptest.NewRecorder()
	handleAsyncSubmit(response, req)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "request_identity_mismatch") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func integrationStore(t *testing.T) *RunStore {
	t.Helper()
	dsn := os.Getenv("MC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("MC_TEST_DATABASE_URL is not configured")
	}
	t.Setenv("DATABASE_URL", dsn)
	s, err := NewRunStore()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func durableFixture(t *testing.T, requestID string) DurableRun {
	t.Helper()
	req := validLifecycleRequest(requestID)
	raw, digest, err := normalizedRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	resultID := resultIDPrefix + newID()
	return DurableRun{RunStatus: RunStatus{RequestID: requestID, CorrelationID: req.CorrelationID,
		RunID: "mc-run-" + newID(), ResultID: &resultID, CreatedAt: now, UpdatedAt: now},
		Request: raw, RequestDigest: digest}
}

func TestPostgresLifecycleIdempotencyLeaseCancellationAndRecovery(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	run := durableFixture(t, "test-"+newID())
	t.Cleanup(func() { _, _ = s.db.Exec(`DELETE FROM mitigation_check_run WHERE request_id=$1`, run.RequestID) })
	created, isNew, err := s.CreateOrGet(ctx, run)
	if err != nil || !isNew {
		t.Fatalf("first create: new=%t err=%v", isNew, err)
	}
	replayed, isNew, err := s.CreateOrGet(ctx, run)
	if err != nil || isNew || replayed.RunID != created.RunID {
		t.Fatalf("replay: new=%t run=%s err=%v", isNew, replayed.RunID, err)
	}
	leased, ok, err := s.LeaseNext(ctx, "worker-1", time.Minute, 3)
	if err != nil || !ok || leased.RunID != run.RunID || leased.Attempt != 1 {
		t.Fatalf("lease: ok=%t run=%+v err=%v", ok, leased, err)
	}
	if _, owned, err := s.Heartbeat(ctx, run.RunID, "worker-1", leased.LeaseToken, time.Minute); err != nil || !owned {
		t.Fatalf("heartbeat: owned=%t err=%v", owned, err)
	}
	canceling, err := s.Cancel(ctx, run.RunID)
	if err != nil || !canceling.CancelRequested {
		t.Fatalf("cancel request: %+v err=%v", canceling, err)
	}
	if written, err := s.MarkCanceled(ctx, run.RunID, "worker-1", leased.LeaseToken); err != nil || !written {
		t.Fatal(err)
	}
	canceled, err := s.Cancel(ctx, run.RunID)
	if err != nil || canceled.Status != statusCanceled {
		t.Fatalf("idempotent cancel: %+v err=%v", canceled, err)
	}

	stale := durableFixture(t, "test-"+newID())
	t.Cleanup(func() { _, _ = s.db.Exec(`DELETE FROM mitigation_check_run WHERE request_id=$1`, stale.RequestID) })
	if _, _, err := s.CreateOrGet(ctx, stale); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE mitigation_check_run SET status='running',attempt=3,lease_expires_at=now()-interval '1 second' WHERE run_id=$1`, stale.RunID); err != nil {
		t.Fatal(err)
	}
	if err := s.FailExhausted(ctx, 3); err != nil {
		t.Fatal(err)
	}
	recovered, err := s.GetDurable(ctx, stale.RunID)
	if err != nil || recovered.Status != statusFailed || recovered.Failure == nil || recovered.Failure.Code != "worker_attempts_exhausted" {
		t.Fatalf("stale recovery: %+v err=%v", recovered, err)
	}
}

func TestAsyncHTTPSubmissionIdempotencyConflictAndQueuedCancellation(t *testing.T) {
	s := integrationStore(t)
	previousStore := store
	store = s
	t.Cleanup(func() { store = previousStore })
	requestID := "test-" + newID()
	t.Cleanup(func() { _, _ = s.db.Exec(`DELETE FROM mitigation_check_run WHERE request_id=$1`, requestID) })

	submit := func(req SubmitMitigationCheckRequest) *httptest.ResponseRecorder {
		body, _ := json.Marshal(req)
		httpRequest := httptest.NewRequest(http.MethodPost, "/v1/mitigation-check-runs", bytes.NewReader(body))
		httpRequest.Header.Set("Content-Type", "application/json")
		httpRequest.Header.Set("Idempotency-Key", requestID)
		httpRequest.Header.Set("X-Correlation-ID", "correlation-1")
		response := httptest.NewRecorder()
		handleAsyncSubmit(response, httpRequest)
		return response
	}

	started := time.Now()
	first := submit(validLifecycleRequest(requestID))
	if first.Code != http.StatusAccepted || time.Since(started) > 2*time.Second {
		t.Fatalf("first submission status=%d elapsed=%s body=%s", first.Code, time.Since(started), first.Body.String())
	}
	var accepted SubmissionResponse
	if err := json.Unmarshal(first.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	second := submit(validLifecycleRequest(requestID))
	var replayed SubmissionResponse
	if err := json.Unmarshal(second.Body.Bytes(), &replayed); err != nil {
		t.Fatal(err)
	}
	if second.Code != http.StatusAccepted || replayed.RunID != accepted.RunID {
		t.Fatalf("replay status=%d first=%s second=%s", second.Code, accepted.RunID, replayed.RunID)
	}
	conflictRequest := validLifecycleRequest(requestID)
	conflictRequest.CandidateArtifactID = "different-candidate"
	conflict := submit(conflictRequest)
	if conflict.Code != http.StatusConflict || !strings.Contains(conflict.Body.String(), "idempotency_conflict") {
		t.Fatalf("conflict status=%d body=%s", conflict.Code, conflict.Body.String())
	}
	resultRequest := httptest.NewRequest(http.MethodGet, "/v1/mitigation-check-runs/"+accepted.RunID+"/result", nil)
	resultResponse := httptest.NewRecorder()
	handleRunResult(resultResponse, resultRequest, accepted.RunID)
	if resultResponse.Code != http.StatusConflict || !strings.Contains(resultResponse.Body.String(), "run_not_terminal") {
		t.Fatalf("pre-terminal result status=%d body=%s", resultResponse.Code, resultResponse.Body.String())
	}
	for i := 0; i < 2; i++ {
		cancelRequest := httptest.NewRequest(http.MethodPost, "/v1/mitigation-check-runs/"+accepted.RunID+"/cancel", nil)
		cancelResponse := httptest.NewRecorder()
		handleRunCancel(cancelResponse, cancelRequest, accepted.RunID)
		if cancelResponse.Code != http.StatusOK || !strings.Contains(cancelResponse.Body.String(), `"status":"canceled"`) {
			t.Fatalf("cancel %d status=%d body=%s", i, cancelResponse.Code, cancelResponse.Body.String())
		}
	}
}

func TestPostgresCompletionIsImmutable(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	run := durableFixture(t, "test-"+newID())
	t.Cleanup(func() { _, _ = s.db.Exec(`DELETE FROM mitigation_check_run WHERE request_id=$1`, run.RequestID) })
	if _, _, err := s.CreateOrGet(ctx, run); err != nil {
		t.Fatal(err)
	}
	leased, ok, err := s.LeaseNext(ctx, "worker-1", time.Minute, 3)
	if err != nil || !ok {
		t.Fatalf("lease ok=%t err=%v", ok, err)
	}
	outcome := RunOutcome{Capability: "mitigation-check", ContractID: contractID, RequestID: run.RequestID,
		RunID: run.RunID, ResultID: *run.ResultID, Status: statusCompleted, TerminalState: stateBlocked,
		CorrelationID: run.CorrelationID, EvidenceRefs: []string{}, CreatedAt: time.Now().UTC()}
	outcome.ResultRef = &ResultRef{System: "databricks", Catalog: "catalog", Schema: "mitigation_check", Table: "results", Key: outcome.ResultID}
	if err := setCanonicalIntegrity(&outcome); err != nil {
		t.Fatal(err)
	}
	payload, err := canonicalResultPayload(outcome)
	if err != nil {
		t.Fatal(err)
	}
	written, err := s.CompletePublished(ctx, run.RunID, "worker-1", leased.LeaseToken, outcome, payload)
	if err != nil || !written {
		t.Fatalf("complete written=%t err=%v", written, err)
	}
	different := outcome
	different.TerminalState = stateNotBlocked
	written, err = s.CompletePublished(ctx, run.RunID, "worker-1", leased.LeaseToken, different, payload)
	if err != nil || written {
		t.Fatalf("terminal result was mutable: written=%t err=%v", written, err)
	}
	reopened, err := NewRunStore() // DATABASE_URL was set by integrationStore
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	status, err := reopened.GetStatus(ctx, run.RunID)
	if err != nil || status.Status != statusCompleted || status.Completion == nil || status.Completion.ResultID != outcome.ResultID {
		t.Fatalf("status did not survive store restart: %+v err=%v", status, err)
	}
}
