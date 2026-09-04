package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNormalizedRequestAppliesExecutionDefaults(t *testing.T) {
	implicit := validLifecycleRequest("request-defaults")
	implicit.ExecutionMode = ""
	explicit := validLifecycleRequest("request-defaults")
	explicit.ExecutionMode = execInMemory
	var basis TestBasisSpec
	if err := json.Unmarshal(explicit.TestBasis, &basis); err != nil {
		t.Fatal(err)
	}
	basis.Request.Method = http.MethodGet
	basis.Request.Path = "/"
	explicit.TestBasis, _ = json.Marshal(basis)
	normalizeRequestDefaults(&implicit)
	normalizeRequestDefaults(&explicit)
	_, first, err := normalizedRequest(implicit)
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := normalizedRequest(explicit)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("default-equivalent requests have different digests: %s != %s", first, second)
	}
}

func TestCanonicalValidationDoesNotDependOnUpstreamMode(t *testing.T) {
	previous := upstreamInputMode
	t.Cleanup(func() { upstreamInputMode = previous })
	for _, enabled := range []bool{false, true} {
		upstreamInputMode = enabled
		req := validLifecycleRequest("request-canonical")
		if fields := validate(req); len(fields) != 0 {
			t.Fatalf("upstream=%t fields=%v", enabled, fields)
		}
	}
	req := validLifecycleRequest("request-noncanonical")
	req.ContractID = upstreamContractID
	if fields := validate(req); !hasField(fields, "contract_id") {
		t.Fatalf("noncanonical contract accepted: %v", fields)
	}
}

func TestCanonicalValidationRejectsNonAuthoritativeUpstreamReference(t *testing.T) {
	req := validLifecycleRequest("request-bad-upstream")
	req.UpstreamInputs = json.RawMessage(`[{
		"capability":"defense-generation","contract_id":"defense-generation@1.0",
		"result_id":"result:one","result_ref":{"system":"databricks","catalog":"catalog","schema":"schema","table":"results","key":"result:other"}
	}]`)
	if fields := validate(req); !hasField(fields, "upstream_inputs[0].result_ref") {
		t.Fatalf("mismatched upstream result identity accepted: %v", fields)
	}
}

func TestUpstreamEvidenceReferencesArePreservedAndDeduplicated(t *testing.T) {
	raw := json.RawMessage(`[
		{"evidence_refs":["evidence:one","evidence:two"]},
		{"evidence_refs":["evidence:two","evidence:three",""]}
	]`)
	refs := upstreamEvidenceRefs(raw)
	want := []string{"evidence:one", "evidence:two", "evidence:three"}
	if strings.Join(refs, ",") != strings.Join(want, ",") {
		t.Fatalf("evidence refs=%v want=%v", refs, want)
	}
}

func TestAsyncSubmitRequiresExactJSONMediaTypeAndRootErrors(t *testing.T) {
	body, _ := json.Marshal(validLifecycleRequest("request-media"))
	for _, mediaType := range []string{"", "text/json", "application/json-patch+json", "application/jsonx"} {
		req := httptest.NewRequest(http.MethodPost, "/v1/mitigation-check-runs", bytes.NewReader(body))
		req.Header.Set("Content-Type", mediaType)
		response := httptest.NewRecorder()
		handleAsyncSubmit(response, req)
		if response.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("content-type=%q status=%d body=%s", mediaType, response.Code, response.Body.String())
		}
		var apiError LifecycleError
		if err := json.Unmarshal(response.Body.Bytes(), &apiError); err != nil || apiError.Code != "unsupported_media_type" {
			t.Fatalf("error is not a root lifecycle envelope: err=%v body=%s", err, response.Body.String())
		}
	}
}

func TestAsyncSubmitRejectsBodyCallbackBeforePersistence(t *testing.T) {
	request := validLifecycleRequest("request-callback")
	request.Callback = &CallbackSpec{URL: "https://callback.invalid/events", EventContractID: "capability-run-event@1.0"}
	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPost, "/v1/mitigation-check-runs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Idempotency-Key", request.RequestID)
	req.Header.Set("X-Correlation-ID", request.CorrelationID)
	response := httptest.NewRecorder()
	handleAsyncSubmit(response, req)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid_callback_location") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestEnrichEnvelopeDoesNotFabricateResultReference(t *testing.T) {
	previous := dbx
	dbx = nil
	t.Cleanup(func() { dbx = previous })
	outcome := RunOutcome{ResultID: resultIDPrefix + "one", TerminalState: stateBlocked}
	enrichEnvelope(&outcome, "correlation-1")
	if outcome.ResultRef != nil {
		t.Fatalf("fabricated result reference: %+v", outcome.ResultRef)
	}
}

func TestImmutableResultMergeNeverUpdates(t *testing.T) {
	statement := immutableResultMergeSQL("`catalog`.`schema`.`results`")
	if !strings.Contains(statement, "MERGE INTO") || !strings.Contains(statement, "WHEN NOT MATCHED THEN INSERT") || strings.Contains(statement, "WHEN MATCHED") || strings.Contains(statement, "UPDATE") {
		t.Fatalf("merge is not insert-only: %s", statement)
	}
}

func TestLeaseFencingAndCanceledOrphanRecovery(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	run := durableFixture(t, "test-fencing-"+newID())
	t.Cleanup(func() { _, _ = s.db.Exec(`DELETE FROM mitigation_check_run WHERE request_id=$1`, run.RequestID) })
	if _, _, err := s.CreateOrGet(ctx, run); err != nil {
		t.Fatal(err)
	}
	first, ok, err := s.LeaseNext(ctx, "worker-old", time.Minute, 3)
	if err != nil || !ok || first.LeaseToken == "" {
		t.Fatalf("first lease: ok=%t run=%+v err=%v", ok, first, err)
	}
	if _, err := s.db.Exec(`UPDATE mitigation_check_run SET lease_expires_at=now()-interval '1 second' WHERE run_id=$1`, run.RunID); err != nil {
		t.Fatal(err)
	}
	second, ok, err := s.LeaseNext(ctx, "worker-new", time.Minute, 3)
	if err != nil || !ok || second.LeaseToken == first.LeaseToken || second.Attempt != 2 {
		t.Fatalf("replacement lease: ok=%t run=%+v err=%v", ok, second, err)
	}
	if _, owned, err := s.Heartbeat(ctx, run.RunID, "worker-old", first.LeaseToken, time.Minute); err != nil || owned {
		t.Fatalf("stale heartbeat owned=%t err=%v", owned, err)
	}
	staleOutcome := lifecycleOutcome(first)
	stalePayload, err := canonicalResultPayload(staleOutcome)
	if err != nil {
		t.Fatal(err)
	}
	if staged, err := s.StageOutcome(ctx, run.RunID, "worker-old", first.LeaseToken, staleOutcome, stalePayload); err != nil || staged {
		t.Fatalf("stale worker staged=%t err=%v", staged, err)
	}
	if _, err := s.Cancel(ctx, run.RunID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE mitigation_check_run SET lease_expires_at=now()-interval '1 second' WHERE run_id=$1`, run.RunID); err != nil {
		t.Fatal(err)
	}
	if err := s.RecoverCanceled(ctx); err != nil {
		t.Fatal(err)
	}
	recovered, err := s.GetDurable(ctx, run.RunID)
	if err != nil || recovered.Status != statusCanceled {
		t.Fatalf("orphan cancellation recovery: %+v err=%v", recovered, err)
	}
}

type recordingPublisher struct {
	attempts int32
	failures int32
}

type durableSuccessCancelingPublisher struct {
	store     *RunStore
	runID     string
	published atomic.Bool
}

func (publisher *durableSuccessCancelingPublisher) Publish(ctx context.Context, _ RunOutcome, _ []byte) error {
	// Model an authoritative sink commit occurring before cancellation reaches
	// the lifecycle ledger. Returning nil means the durable row was verified.
	publisher.published.Store(true)
	_, err := publisher.store.Cancel(ctx, publisher.runID)
	return err
}

type verificationPublisher struct {
	publishes          int32
	verifies           int32
	verificationErrors int32
}

type cancelReconciliationPublisher struct {
	store       *RunStore
	runID       string
	verifyState PublicationVerificationState
	payload     []byte
	publishes   int32
	verifies    int32
}

func (publisher *cancelReconciliationPublisher) Publish(ctx context.Context, _ RunOutcome, payload []byte) error {
	atomic.AddInt32(&publisher.publishes, 1)
	publisher.payload = append([]byte(nil), payload...)
	if _, err := publisher.store.Cancel(ctx, publisher.runID); err != nil {
		return err
	}
	return &PublicationVerificationError{Err: errors.New("MERGE outcome is ambiguous"), State: publicationUnknown}
}

func (publisher *cancelReconciliationPublisher) Verify(_ context.Context, _ RunOutcome, payload []byte) error {
	atomic.AddInt32(&publisher.verifies, 1)
	if !bytes.Equal(payload, publisher.payload) {
		return &PublicationVerificationError{Err: errors.New("reconciliation received different canonical bytes"), State: publicationConflict}
	}
	switch publisher.verifyState {
	case publicationAbsent:
		return &PublicationVerificationError{Err: errors.New("authoritative row is absent"), State: publicationAbsent}
	case publicationConflict:
		return &PublicationVerificationError{Err: errors.New("authoritative row conflicts"), State: publicationConflict}
	default:
		return nil
	}
}

type exactPayloadVerifier struct {
	payload []byte
}

func (publisher *exactPayloadVerifier) Publish(context.Context, RunOutcome, []byte) error {
	return errors.New("recovery must verify without republishing")
}

func (publisher *exactPayloadVerifier) Verify(_ context.Context, _ RunOutcome, payload []byte) error {
	publisher.payload = append([]byte(nil), payload...)
	return nil
}

func (publisher *verificationPublisher) Publish(context.Context, RunOutcome, []byte) error {
	atomic.AddInt32(&publisher.publishes, 1)
	return &PublicationVerificationError{Err: errors.New("readback unavailable after MERGE")}
}

func (publisher *verificationPublisher) Verify(context.Context, RunOutcome, []byte) error {
	atomic.AddInt32(&publisher.verifies, 1)
	if atomic.AddInt32(&publisher.verificationErrors, -1) >= 0 {
		return &PublicationVerificationError{Err: errors.New("readback still unavailable")}
	}
	return nil
}

func (publisher *recordingPublisher) Publish(context.Context, RunOutcome, []byte) error {
	atomic.AddInt32(&publisher.attempts, 1)
	if atomic.AddInt32(&publisher.failures, -1) >= 0 {
		return errors.New("temporary publication failure")
	}
	return nil
}

func TestCancellationAfterPublicationCutoffCannotCancel(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	run := durableFixture(t, "test-publication-cutoff-"+newID())
	t.Cleanup(func() { _, _ = s.db.Exec(`DELETE FROM mitigation_check_run WHERE request_id=$1`, run.RequestID) })
	if _, _, err := s.CreateOrGet(ctx, run); err != nil {
		t.Fatal(err)
	}
	leased, ok, err := s.LeaseNext(ctx, "worker-1", time.Minute, 3)
	if err != nil || !ok {
		t.Fatalf("lease: ok=%t err=%v", ok, err)
	}
	outcome := lifecycleOutcome(leased)
	payload, err := canonicalResultPayload(outcome)
	if err != nil {
		t.Fatal(err)
	}
	if staged, err := s.StageOutcome(ctx, run.RunID, "worker-1", leased.LeaseToken, outcome, payload); err != nil || !staged {
		t.Fatalf("stage: staged=%t err=%v", staged, err)
	}
	if marked, err := s.MarkPublicationPending(ctx, run.RunID, "worker-1", leased.LeaseToken); err != nil || !marked {
		t.Fatalf("cutoff: marked=%t err=%v", marked, err)
	}
	if _, err := s.Cancel(ctx, run.RunID); err != nil {
		t.Fatal(err)
	}
	if canceled, err := s.MarkCanceled(ctx, run.RunID, "worker-1", leased.LeaseToken); err != nil || canceled {
		t.Fatalf("post-cutoff cancellation wrote=%t err=%v", canceled, err)
	}
	if _, err := s.db.Exec(`UPDATE mitigation_check_run SET lease_expires_at=now()-interval '1 second' WHERE run_id=$1`, run.RunID); err != nil {
		t.Fatal(err)
	}
	if err := s.RecoverCanceled(ctx); err != nil {
		t.Fatal(err)
	}
	preserved, err := s.GetDurable(ctx, run.RunID)
	if err != nil || preserved.Status != statusRunning || !preserved.PublicationPending || !preserved.CancelRequested {
		t.Fatalf("publication cutoff was not durable: %+v err=%v", preserved, err)
	}
}

func TestSuccessfulDurablePublicationWinsConcurrentCancellation(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	run := durableFixture(t, "test-publish-success-cancel-"+newID())
	t.Cleanup(func() { _, _ = s.db.Exec(`DELETE FROM mitigation_check_run WHERE request_id=$1`, run.RequestID) })
	if _, _, err := s.CreateOrGet(ctx, run); err != nil {
		t.Fatal(err)
	}
	publisher := &durableSuccessCancelingPublisher{store: s, runID: run.RunID}
	worker := NewRunWorker(s, func(_ context.Context, leased DurableRun) (RunOutcome, error) {
		return lifecycleOutcome(leased), nil
	}, publisher)
	worker.lease = time.Minute
	leased, ok, err := s.LeaseNext(ctx, worker.workerID, worker.lease, worker.maxAttempts)
	if err != nil || !ok {
		t.Fatalf("lease: ok=%t err=%v", ok, err)
	}
	worker.executeOne(ctx, leased)
	completed, err := s.GetDurable(ctx, run.RunID)
	if err != nil || !publisher.published.Load() || completed.Status != statusCompleted || !completed.CancelRequested || completed.Completion == nil || completed.Result == nil || completed.PublicationPending {
		t.Fatalf("durably published result did not win cancellation: %+v err=%v", completed, err)
	}
	if _, ok, err := s.LeaseNext(ctx, "worker-2", time.Minute, worker.maxAttempts); err != nil || ok {
		t.Fatalf("completed publication was requeued: ok=%t err=%v", ok, err)
	}
}

func TestCanceledAmbiguousPublicationReconcilesAuthoritativeRow(t *testing.T) {
	for _, test := range []struct {
		name        string
		state       PublicationVerificationState
		wantStatus  string
		wantFailure string
	}{
		{name: "identical row completes", state: publicationUnknown, wantStatus: statusCompleted},
		{name: "absent row remains pending", state: publicationAbsent, wantStatus: statusQueued},
		{name: "conflicting row fails", state: publicationConflict, wantStatus: statusFailed, wantFailure: "result_publication_conflict"},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := integrationStore(t)
			ctx := context.Background()
			run := durableFixture(t, "test-cancel-reconcile-"+newID())
			t.Cleanup(func() { _, _ = s.db.Exec(`DELETE FROM mitigation_check_run WHERE request_id=$1`, run.RequestID) })
			if _, _, err := s.CreateOrGet(ctx, run); err != nil {
				t.Fatal(err)
			}
			publisher := &cancelReconciliationPublisher{store: s, runID: run.RunID, verifyState: test.state}
			var executions int32
			worker := NewRunWorker(s, func(_ context.Context, leased DurableRun) (RunOutcome, error) {
				atomic.AddInt32(&executions, 1)
				return lifecycleOutcome(leased), nil
			}, publisher)
			worker.lease = time.Minute
			leased, ok, err := s.LeaseNext(ctx, worker.workerID, worker.lease, worker.maxAttempts)
			if err != nil || !ok {
				t.Fatalf("lease: ok=%t err=%v", ok, err)
			}
			worker.executeOne(ctx, leased)
			resolved, err := s.GetDurable(ctx, run.RunID)
			if err != nil || resolved.Status != test.wantStatus || !resolved.CancelRequested {
				t.Fatalf("reconciliation: %+v err=%v", resolved, err)
			}
			if test.wantFailure == "" {
				if resolved.Failure != nil {
					t.Fatalf("unexpected failure: %+v", resolved.Failure)
				}
			} else if resolved.Failure == nil || resolved.Failure.Code != test.wantFailure {
				t.Fatalf("failure=%+v want code=%s", resolved.Failure, test.wantFailure)
			}
			if test.wantStatus == statusCompleted && (resolved.Completion == nil || !bytes.Equal(resolved.ResultPayload, publisher.payload)) {
				t.Fatalf("completed result did not retain published bytes: %+v", resolved)
			}
			if test.state == publicationAbsent {
				if !resolved.PublicationPending || resolved.PublicationRetryAt == nil || !resolved.PublicationRetryAt.After(time.Now()) {
					t.Fatalf("absent readback did not persist a delayed verification retry: %+v", resolved)
				}
				if _, ok, err := s.LeaseNext(ctx, "worker-too-early", time.Minute, worker.maxAttempts); err != nil || ok {
					t.Fatalf("verification retry was immediately leaseable: ok=%t err=%v", ok, err)
				}
				if _, err := s.db.Exec(`UPDATE mitigation_check_run SET publication_retry_at=now()-interval '1 second' WHERE run_id=$1`, run.RunID); err != nil {
					t.Fatal(err)
				}
				publisher.verifyState = publicationUnknown
				retry, ok, err := s.LeaseNext(ctx, worker.workerID, worker.lease, worker.maxAttempts)
				if err != nil || !ok {
					t.Fatalf("late verification lease: ok=%t err=%v", ok, err)
				}
				worker.executeOne(ctx, retry)
				completed, err := s.GetDurable(ctx, run.RunID)
				if err != nil || completed.Status != statusCompleted || completed.Completion == nil {
					t.Fatalf("late authoritative row did not complete: %+v err=%v", completed, err)
				}
				if got := atomic.LoadInt32(&publisher.publishes); got != 1 {
					t.Fatalf("MERGE ran %d times after ambiguous result, want 1", got)
				}
				if got := atomic.LoadInt32(&executions); got != 1 {
					t.Fatalf("executor ran %d times, want 1", got)
				}
			}
		})
	}
}

func TestCanonicalResultBytesSurviveMigrationRecoveryAndResultEndpoint(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	run := durableFixture(t, "test-canonical-recovery-"+newID())
	t.Cleanup(func() { _, _ = s.db.Exec(`DELETE FROM mitigation_check_run WHERE request_id=$1`, run.RequestID) })
	if _, _, err := s.CreateOrGet(ctx, run); err != nil {
		t.Fatal(err)
	}
	leased, ok, err := s.LeaseNext(ctx, "crashed-worker", time.Minute, 3)
	if err != nil || !ok {
		t.Fatalf("lease: ok=%t err=%v", ok, err)
	}
	outcome := lifecycleOutcome(leased)
	outcome.UpstreamInputs = json.RawMessage(`[{"z":2,"a":1}]`)
	if err := setCanonicalIntegrity(&outcome); err != nil {
		t.Fatal(err)
	}
	payload, err := canonicalResultPayload(outcome)
	if err != nil {
		t.Fatal(err)
	}
	if staged, err := s.StageOutcome(ctx, run.RunID, "crashed-worker", leased.LeaseToken, outcome, payload); err != nil || !staged {
		t.Fatalf("stage: staged=%t err=%v", staged, err)
	}
	if marked, err := s.MarkPublicationPending(ctx, run.RunID, "crashed-worker", leased.LeaseToken); err != nil || !marked {
		t.Fatalf("mark publication pending: marked=%t err=%v", marked, err)
	}
	// Simulate an upgrade from the JSONB-only staging schema, then run migration.
	if _, err := s.db.Exec(`UPDATE mitigation_check_run SET result_payload=NULL WHERE run_id=$1`, run.RunID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE mitigation_check_run SET publication_pending=FALSE WHERE run_id=$1`, run.RunID); err != nil {
		t.Fatal(err)
	}
	if err := migrateLifecycle(s.db); err != nil {
		t.Fatal(err)
	}
	recovered, err := s.GetDurable(ctx, run.RunID)
	if err != nil || recovered.Result == nil || validateCanonicalResultPayload(*recovered.Result, recovered.ResultPayload) != nil {
		t.Fatalf("migration did not produce a valid canonical payload: %+v err=%v", recovered, err)
	}
	payload = append([]byte(nil), recovered.ResultPayload...)
	if marked, err := s.MarkPublicationPending(ctx, run.RunID, "crashed-worker", leased.LeaseToken); err != nil || !marked {
		t.Fatalf("restore publication pending: marked=%t err=%v", marked, err)
	}
	if _, err := s.db.Exec(`UPDATE mitigation_check_run SET lease_expires_at=now()-interval '1 second' WHERE run_id=$1`, run.RunID); err != nil {
		t.Fatal(err)
	}
	publisher := &exactPayloadVerifier{}
	worker := NewRunWorker(s, func(context.Context, DurableRun) (RunOutcome, error) {
		t.Fatal("staged recovery re-executed the mitigation check")
		return RunOutcome{}, nil
	}, publisher)
	worker.lease = time.Minute
	recovered, ok, err = s.LeaseNext(ctx, worker.workerID, worker.lease, worker.maxAttempts)
	if err != nil || !ok {
		t.Fatalf("recovery lease: ok=%t err=%v", ok, err)
	}
	worker.executeOne(ctx, recovered)
	if !bytes.Equal(publisher.payload, payload) {
		t.Fatalf("publisher bytes changed across recovery\n got=%s\nwant=%s", publisher.payload, payload)
	}
	previousStore := store
	store = s
	t.Cleanup(func() { store = previousStore })
	request := httptest.NewRequest(http.MethodGet, "/v1/mitigation-check-runs/"+run.RunID+"/result", nil)
	response := httptest.NewRecorder()
	handleRunResult(response, request, run.RunID)
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), payload) {
		t.Fatalf("result endpoint bytes changed: status=%d\n got=%s\nwant=%s", response.Code, response.Body.Bytes(), payload)
	}
}

func TestCancellationBeforePublicationWins(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	run := durableFixture(t, "test-cancel-before-publish-"+newID())
	t.Cleanup(func() { _, _ = s.db.Exec(`DELETE FROM mitigation_check_run WHERE request_id=$1`, run.RequestID) })
	if _, _, err := s.CreateOrGet(ctx, run); err != nil {
		t.Fatal(err)
	}
	publisher := &recordingPublisher{}
	worker := NewRunWorker(s, func(_ context.Context, leased DurableRun) (RunOutcome, error) {
		if _, err := s.Cancel(ctx, leased.RunID); err != nil {
			return RunOutcome{}, err
		}
		return lifecycleOutcome(leased), nil
	}, publisher)
	worker.lease = time.Minute
	leased, ok, err := s.LeaseNext(ctx, worker.workerID, worker.lease, worker.maxAttempts)
	if err != nil || !ok {
		t.Fatalf("lease: ok=%t err=%v", ok, err)
	}
	worker.executeOne(ctx, leased)
	canceled, err := s.GetDurable(ctx, run.RunID)
	if err != nil || canceled.Status != statusCanceled || !canceled.CancelRequested || canceled.Completion != nil {
		t.Fatalf("pre-publication cancellation did not win: %+v err=%v", canceled, err)
	}
	if got := atomic.LoadInt32(&publisher.attempts); got != 0 {
		t.Fatalf("publisher ran %d times after pre-publication cancellation", got)
	}
}

func TestAmbiguousFinalPublicationAttemptRecoversByVerificationOnly(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	run := durableFixture(t, "test-publish-crash-"+newID())
	t.Cleanup(func() { _, _ = s.db.Exec(`DELETE FROM mitigation_check_run WHERE request_id=$1`, run.RequestID) })
	if _, _, err := s.CreateOrGet(ctx, run); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE mitigation_check_run SET attempt=2 WHERE run_id=$1`, run.RunID); err != nil {
		t.Fatal(err)
	}
	var executions int32
	publisher := &verificationPublisher{verificationErrors: 1}
	worker := NewRunWorker(s, func(_ context.Context, leased DurableRun) (RunOutcome, error) {
		atomic.AddInt32(&executions, 1)
		return lifecycleOutcome(leased), nil
	}, publisher)
	worker.lease = time.Minute

	first, ok, err := s.LeaseNext(ctx, worker.workerID, worker.lease, worker.maxAttempts)
	if err != nil || !ok || first.Attempt != worker.maxAttempts {
		t.Fatalf("final execution lease: ok=%t run=%+v err=%v", ok, first, err)
	}
	worker.executeOne(ctx, first)
	pending, err := s.GetDurable(ctx, run.RunID)
	if err != nil || pending.Status != statusQueued || pending.Result == nil || !pending.PublicationPending || pending.PublicationRetryAt == nil {
		t.Fatalf("ambiguous MERGE was not preserved: %+v err=%v", pending, err)
	}

	if _, ok, err := s.LeaseNext(ctx, worker.workerID, worker.lease, worker.maxAttempts); err != nil || ok {
		t.Fatalf("verification retry ignored backoff: ok=%t err=%v", ok, err)
	}
	if _, err := s.db.Exec(`UPDATE mitigation_check_run SET publication_retry_at=now()-interval '1 second' WHERE run_id=$1`, run.RunID); err != nil {
		t.Fatal(err)
	}
	second, ok, err := s.LeaseNext(ctx, worker.workerID, worker.lease, worker.maxAttempts)
	if err != nil || !ok || !second.PublicationPending {
		t.Fatalf("reconciliation lease: ok=%t err=%v", ok, err)
	}
	worker.executeOne(ctx, second)
	completed, err := s.GetDurable(ctx, run.RunID)
	if err != nil || completed.Status != statusCompleted || completed.Completion == nil {
		t.Fatalf("verified canonical result did not complete: %+v err=%v", completed, err)
	}
	if got := atomic.LoadInt32(&executions); got != 1 {
		t.Fatalf("executor ran %d times, want 1", got)
	}
	if got := atomic.LoadInt32(&publisher.publishes); got != 1 {
		t.Fatalf("MERGE ran %d times, want 1", got)
	}
	if got := atomic.LoadInt32(&publisher.verifies); got != 2 {
		t.Fatalf("readback ran %d times, want 2", got)
	}
}

func TestPublicationVerificationRetriesAreBoundedWithBackoff(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	run := durableFixture(t, "test-verification-bounded-"+newID())
	t.Cleanup(func() { _, _ = s.db.Exec(`DELETE FROM mitigation_check_run WHERE request_id=$1`, run.RequestID) })
	if _, _, err := s.CreateOrGet(ctx, run); err != nil {
		t.Fatal(err)
	}
	var executions int32
	publisher := &verificationPublisher{verificationErrors: 10}
	worker := NewRunWorker(s, func(_ context.Context, leased DurableRun) (RunOutcome, error) {
		atomic.AddInt32(&executions, 1)
		return lifecycleOutcome(leased), nil
	}, publisher)
	worker.lease = time.Minute
	worker.maxVerificationAttempts = 2
	worker.verificationBackoff = time.Minute

	first, ok, err := s.LeaseNext(ctx, worker.workerID, worker.lease, worker.maxAttempts)
	if err != nil || !ok {
		t.Fatalf("initial lease: ok=%t err=%v", ok, err)
	}
	worker.executeOne(ctx, first)
	pending, err := s.GetDurable(ctx, run.RunID)
	if err != nil || pending.Status != statusQueued || pending.VerificationAttempt != 1 || pending.PublicationRetryAt == nil {
		t.Fatalf("first verification retry: %+v err=%v", pending, err)
	}
	remaining := time.Until(*pending.PublicationRetryAt)
	if remaining < 50*time.Second || remaining > 70*time.Second {
		t.Fatalf("persisted retry delay=%s, want approximately 1m", remaining)
	}
	if _, ok, err := s.LeaseNext(ctx, "worker-busy-loop", time.Minute, worker.maxAttempts); err != nil || ok {
		t.Fatalf("bounded retry was immediately leaseable: ok=%t err=%v", ok, err)
	}
	if _, err := s.db.Exec(`UPDATE mitigation_check_run SET publication_retry_at=now()-interval '1 second' WHERE run_id=$1`, run.RunID); err != nil {
		t.Fatal(err)
	}
	second, ok, err := s.LeaseNext(ctx, worker.workerID, worker.lease, worker.maxAttempts)
	if err != nil || !ok {
		t.Fatalf("final verification lease: ok=%t err=%v", ok, err)
	}
	worker.executeOne(ctx, second)
	failed, err := s.GetDurable(ctx, run.RunID)
	if err != nil || failed.Status != statusFailed || failed.Failure == nil || failed.Failure.Code != "publication_verification_failed" || failed.Failure.Retryable || failed.PublicationPending || failed.PublicationRetryAt != nil {
		t.Fatalf("bounded verification did not converge stably: %+v err=%v", failed, err)
	}
	if got := atomic.LoadInt32(&executions); got != 1 {
		t.Fatalf("executor ran %d times, want 1", got)
	}
	if got := atomic.LoadInt32(&publisher.publishes); got != 1 {
		t.Fatalf("MERGE ran %d times, want 1", got)
	}
}

func TestCrashAfterMergeBeforeVerificationStateDoesNotFailOrReexecute(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	run := durableFixture(t, "test-post-merge-crash-"+newID())
	t.Cleanup(func() { _, _ = s.db.Exec(`DELETE FROM mitigation_check_run WHERE request_id=$1`, run.RequestID) })
	if _, _, err := s.CreateOrGet(ctx, run); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE mitigation_check_run SET attempt=2 WHERE run_id=$1`, run.RunID); err != nil {
		t.Fatal(err)
	}
	crashed, ok, err := s.LeaseNext(ctx, "crashed-worker", time.Minute, 3)
	if err != nil || !ok || crashed.Attempt != 3 {
		t.Fatalf("final lease: ok=%t run=%+v err=%v", ok, crashed, err)
	}
	outcome := lifecycleOutcome(crashed)
	payload, err := canonicalResultPayload(outcome)
	if err != nil {
		t.Fatal(err)
	}
	if staged, err := s.StageOutcome(ctx, run.RunID, "crashed-worker", crashed.LeaseToken, outcome, payload); err != nil || !staged {
		t.Fatalf("stage before simulated crash: staged=%t err=%v", staged, err)
	}
	if _, err := s.db.Exec(`UPDATE mitigation_check_run SET lease_expires_at=now()-interval '1 second' WHERE run_id=$1`, run.RunID); err != nil {
		t.Fatal(err)
	}
	if err := s.FailExhausted(ctx, 3); err != nil {
		t.Fatal(err)
	}
	preserved, err := s.GetDurable(ctx, run.RunID)
	if err != nil || preserved.Status != statusRunning || preserved.Result == nil {
		t.Fatalf("staged crash window was failed: %+v err=%v", preserved, err)
	}

	var executions int32
	publisher := &recordingPublisher{}
	worker := NewRunWorker(s, func(_ context.Context, leased DurableRun) (RunOutcome, error) {
		atomic.AddInt32(&executions, 1)
		return lifecycleOutcome(leased), nil
	}, publisher)
	worker.lease = time.Minute
	recovered, ok, err := s.LeaseNext(ctx, worker.workerID, worker.lease, worker.maxAttempts)
	if err != nil || !ok || recovered.Result == nil {
		t.Fatalf("staged recovery lease: ok=%t run=%+v err=%v", ok, recovered, err)
	}
	worker.executeOne(ctx, recovered)
	completed, err := s.GetDurable(ctx, run.RunID)
	if err != nil || completed.Status != statusCompleted {
		t.Fatalf("staged recovery did not complete: %+v err=%v", completed, err)
	}
	if got := atomic.LoadInt32(&executions); got != 0 {
		t.Fatalf("executor ran %d times after staged crash, want 0", got)
	}
}

func lifecycleOutcome(run DurableRun) RunOutcome {
	outcome := RunOutcome{
		Capability: "mitigation-check", ContractID: contractID, RequestID: run.RequestID,
		RunID: run.RunID, ResultID: value(run.ResultID), Status: statusCompleted,
		TerminalState: stateBlocked, CorrelationID: run.CorrelationID,
		ResultRef:    &ResultRef{System: "databricks", Catalog: "catalog", Schema: "mitigation_check", Table: "results", Key: value(run.ResultID)},
		EvidenceRefs: []string{}, CreatedAt: time.Now().UTC(),
	}
	if err := setCanonicalIntegrity(&outcome); err != nil {
		panic(err)
	}
	return outcome
}

func hasField(fields []string, wanted string) bool {
	for _, field := range fields {
		if field == wanted {
			return true
		}
	}
	return false
}
