package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCallbackHeaderValidation(t *testing.T) {
	header := http.Header{}
	metadata, apiError := callbackMetadataFromHeaders(header, "orchestration.example")
	if apiError != nil || metadata != (CallbackMetadata{}) {
		t.Fatalf("empty headers metadata=%+v error=%+v", metadata, apiError)
	}

	header.Set(callbackURLHeader, "https://orchestration.example/v1/capability-callbacks")
	if _, apiError := callbackMetadataFromHeaders(header, "orchestration.example"); apiError == nil || apiError.Code != "invalid_callback_headers" {
		t.Fatalf("incomplete callback headers accepted: %+v", apiError)
	}
	header.Set(callbackWorkflowIDHeader, "janus-mitigation-check-abc123")
	header.Set(callbackSignalHeader, callbackSignal)
	metadata, apiError = callbackMetadataFromHeaders(header, "orchestration.example")
	if apiError != nil || metadata.URL != header.Get(callbackURLHeader) || metadata.WorkflowID != header.Get(callbackWorkflowIDHeader) || metadata.Signal != callbackSignal {
		t.Fatalf("valid callback headers metadata=%+v error=%+v", metadata, apiError)
	}

	header.Set(callbackSignalHeader, "wrong")
	if _, apiError := callbackMetadataFromHeaders(header, "orchestration.example"); apiError == nil || apiError.Code != "invalid_callback_signal" {
		t.Fatalf("wrong signal accepted: %+v", apiError)
	}
	header.Set(callbackSignalHeader, callbackSignal)
	header.Set(callbackURLHeader, "http://orchestration.example/v1/capability-callbacks")
	if _, apiError := callbackMetadataFromHeaders(header, "orchestration.example"); apiError == nil || apiError.Code != "invalid_callback_url" {
		t.Fatalf("non-HTTPS callback accepted: %+v", apiError)
	}
	header.Set(callbackURLHeader, "https://other.example/v1/capability-callbacks")
	if _, apiError := callbackMetadataFromHeaders(header, "orchestration.example"); apiError == nil || apiError.Code != "callback_host_not_allowed" {
		t.Fatalf("non-allowlisted callback accepted: %+v", apiError)
	}
}

type callbackStoreFake struct {
	mu                  sync.Mutex
	succeeded           int
	retried             int
	configurationFailed int
	delay               time.Duration
	reason              string
}

func (store *callbackStoreFake) ClaimNextCallback(context.Context, time.Duration) (CallbackDelivery, bool, error) {
	return CallbackDelivery{}, false, nil
}

func (store *callbackStoreFake) CallbackSucceeded(_ context.Context, _, _ string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.succeeded++
	return nil
}

func (store *callbackStoreFake) CallbackFailed(_ context.Context, _, _ string, delay time.Duration, reason string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.retried++
	store.delay = delay
	store.reason = reason
	return nil
}

func (store *callbackStoreFake) CallbackConfigurationFailed(_ context.Context, _, _, reason string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.configurationFailed++
	store.reason = reason
	return nil
}

func callbackDeliveryFixture(callbackURL string) CallbackDelivery {
	runID := "mitigation-run-123"
	return CallbackDelivery{
		Run: DurableRun{
			RunStatus:   RunStatus{RequestID: "mitigation-request-123", CorrelationID: "correlation-123", RunID: runID, Status: statusCompleted},
			CallbackURL: callbackURL, CallbackWorkflowID: "janus-mitigation-check-abc123",
			CallbackSignal: callbackSignal, CallbackEventID: "mitigation-check:" + runID + ":terminal:v1",
		},
		LeaseToken: "lease-1",
	}
}

func TestCallbackPayloadAndAcceptedDelivery(t *testing.T) {
	var received CallbackPayload
	var topLevelFields map[string]json.RawMessage
	var authorization string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		authorization = request.Header.Get("Authorization")
		if request.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content type=%q", request.Header.Get("Content-Type"))
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
		}
		if err := json.Unmarshal(body, &received); err != nil {
			t.Error(err)
		}
		if err := json.Unmarshal(body, &topLevelFields); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"event_id":"mitigation-check:mitigation-run-123:terminal:v1","status":"accepted"}`))
	}))
	defer server.Close()

	store := &callbackStoreFake{}
	dispatcher := NewCallbackDispatcher(store, "shared-secret")
	dispatcher.client = server.Client()
	dispatcher.deliver(context.Background(), callbackDeliveryFixture(server.URL))

	if store.succeeded != 1 || store.retried != 0 || store.configurationFailed != 0 {
		t.Fatalf("delivery state=%+v", store)
	}
	if authorization != "Bearer shared-secret" {
		t.Fatalf("authorization=%q", authorization)
	}
	if len(topLevelFields) != 2 || topLevelFields["workflow_id"] == nil || topLevelFields["wakeup"] == nil {
		t.Fatalf("callback contains unknown or missing top-level fields: %v", topLevelFields)
	}
	if received.WorkflowID != "janus-mitigation-check-abc123" || received.Wakeup.EventID != "mitigation-check:mitigation-run-123:terminal:v1" ||
		received.Wakeup.Capability != "mitigation-check" || received.Wakeup.RequestID != "mitigation-request-123" ||
		received.Wakeup.CorrelationID != "correlation-123" || received.Wakeup.RunID != "mitigation-run-123" {
		t.Fatalf("callback payload=%+v", received)
	}
}

func TestCallbackRetriesReuseEventIDAndBackoff(t *testing.T) {
	var eventIDs []string
	statuses := []int{http.StatusTooManyRequests, http.StatusServiceUnavailable}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		var payload CallbackPayload
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		eventIDs = append(eventIDs, payload.Wakeup.EventID)
		status := statuses[len(eventIDs)-1]
		if status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "20")
		}
		w.WriteHeader(status)
	}))
	defer server.Close()

	store := &callbackStoreFake{}
	dispatcher := NewCallbackDispatcher(store, "shared-secret")
	dispatcher.client = server.Client()
	delivery := callbackDeliveryFixture(server.URL)
	dispatcher.deliver(context.Background(), delivery)
	delivery.Attempt = 1
	delivery.LeaseToken = "lease-2"
	dispatcher.deliver(context.Background(), delivery)

	if store.retried != 2 || store.delay <= 0 {
		t.Fatalf("retry state=%+v", store)
	}
	if len(eventIDs) != 2 || eventIDs[0] != eventIDs[1] {
		t.Fatalf("event IDs changed across retry: %v", eventIDs)
	}
}

func TestCallbackUnauthorizedAlertsWithoutTokenExposure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	store := &callbackStoreFake{}
	dispatcher := NewCallbackDispatcher(store, "do-not-log-this-token")
	dispatcher.client = server.Client()

	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previous) })
	dispatcher.deliver(context.Background(), callbackDeliveryFixture(server.URL))

	if store.configurationFailed != 1 || !strings.Contains(logs.String(), "ALERT callback_configuration_failed") {
		t.Fatalf("configuration failure not alerted: state=%+v logs=%s", store, logs.String())
	}
	if strings.Contains(logs.String(), "do-not-log-this-token") {
		t.Fatalf("token exposed in logs: %s", logs.String())
	}
}

func TestCallbackDuplicateDoesNotMutateCanonicalResult(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	store := &callbackStoreFake{}
	dispatcher := NewCallbackDispatcher(store, "shared-secret")
	dispatcher.client = server.Client()
	delivery := callbackDeliveryFixture(server.URL)
	delivery.Run.ResultPayload = []byte(`{"canonical":"result"}`)
	want := append([]byte(nil), delivery.Run.ResultPayload...)
	dispatcher.deliver(context.Background(), delivery)
	delivery.LeaseToken = "lease-duplicate"
	dispatcher.deliver(context.Background(), delivery)
	if !bytes.Equal(delivery.Run.ResultPayload, want) || store.succeeded != 2 {
		t.Fatalf("duplicate callback changed canonical result or failed: payload=%s state=%+v", delivery.Run.ResultPayload, store)
	}
}

func TestCallbackRetryScheduleContinuesIndefinitely(t *testing.T) {
	for _, attempt := range []int{0, 1, 2, 3, 4, 5, 1000} {
		if delay := callbackRetryDelay(attempt); delay <= 0 {
			t.Fatalf("attempt %d delay=%s", attempt, delay)
		}
	}
}

func TestSubmitPersistsCallbackHeadersAndSupportsPollingOnly(t *testing.T) {
	databaseStore := integrationStore(t)
	previousStore := store
	store = databaseStore
	t.Cleanup(func() { store = previousStore })
	t.Setenv("CAPABILITY_CALLBACK_ALLOWED_HOSTS", "orchestration.example")
	t.Setenv("CAPABILITY_CALLBACK_TOKEN", "shared-secret")

	for _, withCallback := range []bool{true, false} {
		requestID := "test-callback-submit-" + newID()
		requestBody, _ := json.Marshal(validLifecycleRequest(requestID))
		request := httptest.NewRequest(http.MethodPost, "/v1/mitigation-check-runs", bytes.NewReader(requestBody))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", requestID)
		request.Header.Set("X-Correlation-ID", "correlation-1")
		if withCallback {
			request.Header.Set(callbackURLHeader, "https://orchestration.example/v1/capability-callbacks")
			request.Header.Set(callbackWorkflowIDHeader, "janus-mitigation-check-abc123")
			request.Header.Set(callbackSignalHeader, callbackSignal)
		}
		response := httptest.NewRecorder()
		handleAsyncSubmit(response, request)
		if response.Code != http.StatusAccepted {
			t.Fatalf("withCallback=%t status=%d body=%s", withCallback, response.Code, response.Body.String())
		}
		var submission SubmissionResponse
		if err := json.Unmarshal(response.Body.Bytes(), &submission); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = databaseStore.db.Exec(`DELETE FROM mitigation_check_run WHERE request_id=$1`, requestID)
		})
		persisted, err := databaseStore.GetDurable(context.Background(), submission.RunID)
		if err != nil {
			t.Fatal(err)
		}
		if withCallback {
			if persisted.CallbackURL != "https://orchestration.example/v1/capability-callbacks" ||
				persisted.CallbackWorkflowID != "janus-mitigation-check-abc123" || persisted.CallbackSignal != callbackSignal {
				t.Fatalf("callback metadata not persisted: %+v", persisted)
			}
		} else if persisted.CallbackURL != "" || persisted.CallbackWorkflowID != "" || persisted.CallbackSignal != "" {
			t.Fatalf("polling-only run unexpectedly has callback metadata: %+v", persisted)
		}
	}
}

func TestTerminalTransitionCreatesOneCallbackAfterPollingIsAvailable(t *testing.T) {
	databaseStore := integrationStore(t)
	ctx := context.Background()
	run := durableFixture(t, "test-callback-terminal-"+newID())
	run.CallbackURL = "https://orchestration.example/v1/capability-callbacks"
	run.CallbackWorkflowID = "janus-mitigation-check-abc123"
	run.CallbackSignal = callbackSignal
	run.CallbackEventID = "mitigation-check:" + run.RunID + ":terminal:v1"
	t.Cleanup(func() {
		_, _ = databaseStore.db.Exec(`DELETE FROM mitigation_check_run WHERE request_id=$1`, run.RequestID)
	})
	if _, created, err := databaseStore.CreateOrGet(ctx, run); err != nil || !created {
		t.Fatalf("create run: created=%t err=%v", created, err)
	}
	if _, ok, err := databaseStore.ClaimNextCallback(ctx, time.Minute); err != nil || ok {
		t.Fatalf("callback claimed before terminal commit: ok=%t err=%v", ok, err)
	}
	terminal, err := databaseStore.Cancel(ctx, run.RunID)
	if err != nil || terminal.Status != statusCanceled {
		t.Fatalf("terminal cancel=%+v err=%v", terminal, err)
	}
	status, err := databaseStore.GetStatus(ctx, run.RunID)
	if err != nil || status.Status != statusCanceled {
		t.Fatalf("terminal status unavailable before callback: %+v err=%v", status, err)
	}
	result, err := databaseStore.GetDurable(ctx, run.RunID)
	if err != nil || result.Status != statusCanceled {
		t.Fatalf("terminal result unavailable before callback: %+v err=%v", result, err)
	}
	delivery, ok, err := databaseStore.ClaimNextCallback(ctx, time.Minute)
	if err != nil || !ok {
		t.Fatalf("terminal callback not claimable: ok=%t err=%v", ok, err)
	}
	if delivery.Run.CallbackEventID != run.CallbackEventID || delivery.Run.CallbackWorkflowID != run.CallbackWorkflowID {
		t.Fatalf("wrong logical callback event: %+v", delivery)
	}
	if _, second, err := databaseStore.ClaimNextCallback(ctx, time.Minute); err != nil || second {
		t.Fatalf("same logical callback concurrently claimed twice: second=%t err=%v", second, err)
	}
	if err := databaseStore.CallbackFailed(ctx, run.RunID, delivery.LeaseToken, time.Hour, "temporary failure"); err != nil {
		t.Fatal(err)
	}
	status, err = databaseStore.GetStatus(ctx, run.RunID)
	if err != nil || status.Status != statusCanceled {
		t.Fatalf("callback failure made polling unavailable: %+v err=%v", status, err)
	}
}
