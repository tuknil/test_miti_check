package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	callbackURLHeader        = "X-Janus-Callback-URL"
	callbackWorkflowIDHeader = "X-Janus-Callback-Workflow-ID"
	callbackSignalHeader     = "X-Janus-Callback-Signal"
	callbackSignal           = "janus.capability-completion.v1"
)

type CallbackMetadata struct {
	URL        string
	WorkflowID string
	Signal     string
}

type CallbackWakeup struct {
	EventID       string `json:"event_id"`
	Capability    string `json:"capability"`
	RequestID     string `json:"request_id"`
	CorrelationID string `json:"correlation_id"`
	RunID         string `json:"run_id"`
}

type CallbackPayload struct {
	WorkflowID string         `json:"workflow_id"`
	Wakeup     CallbackWakeup `json:"wakeup"`
}

func callbackMetadataFromHeaders(header http.Header, allowedHosts string) (CallbackMetadata, *LifecycleError) {
	metadata := CallbackMetadata{
		URL:        strings.TrimSpace(header.Get(callbackURLHeader)),
		WorkflowID: strings.TrimSpace(header.Get(callbackWorkflowIDHeader)),
		Signal:     strings.TrimSpace(header.Get(callbackSignalHeader)),
	}
	present := 0
	for _, value := range []string{metadata.URL, metadata.WorkflowID, metadata.Signal} {
		if value != "" {
			present++
		}
	}
	if present == 0 {
		return CallbackMetadata{}, nil
	}
	if present != 3 {
		return CallbackMetadata{}, &LifecycleError{Code: "invalid_callback_headers", Detail: "Callback URL, workflow ID, and signal headers must be provided together", Retryable: false}
	}
	parsed, err := url.Parse(metadata.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return CallbackMetadata{}, &LifecycleError{Code: "invalid_callback_url", Detail: "X-Janus-Callback-URL must be an HTTPS URL without user information", Retryable: false}
	}
	if parsed.Fragment != "" {
		return CallbackMetadata{}, &LifecycleError{Code: "invalid_callback_url", Detail: "X-Janus-Callback-URL must not contain a fragment", Retryable: false}
	}
	if !callbackHostAllowed(parsed.Hostname(), allowedHosts) {
		return CallbackMetadata{}, &LifecycleError{Code: "callback_host_not_allowed", Detail: "X-Janus-Callback-URL hostname is not allowlisted", Retryable: false}
	}
	if metadata.Signal != callbackSignal {
		return CallbackMetadata{}, &LifecycleError{Code: "invalid_callback_signal", Detail: "X-Janus-Callback-Signal must equal janus.capability-completion.v1", Retryable: false}
	}
	return metadata, nil
}

func callbackHostAllowed(host, configured string) bool {
	configured = strings.TrimSpace(configured)
	if configured == "" {
		return true
	}
	for _, candidate := range strings.Split(configured, ",") {
		if strings.EqualFold(strings.TrimSpace(candidate), host) {
			return true
		}
	}
	return false
}

type CallbackDispatcher struct {
	store  callbackDeliveryStore
	client *http.Client
	token  string
	poll   time.Duration
	lease  time.Duration
}

type callbackDeliveryStore interface {
	ClaimNextCallback(context.Context, time.Duration) (CallbackDelivery, bool, error)
	CallbackSucceeded(context.Context, string, string) error
	CallbackFailed(context.Context, string, string, time.Duration, string) error
	CallbackConfigurationFailed(context.Context, string, string, string) error
}

func NewCallbackDispatcher(store callbackDeliveryStore, token string) *CallbackDispatcher {
	return &CallbackDispatcher{
		store: store,
		client: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		token: strings.TrimSpace(token),
		poll:  500 * time.Millisecond,
		lease: 30 * time.Second,
	}
}

func (dispatcher *CallbackDispatcher) Run(ctx context.Context) {
	ticker := time.NewTicker(dispatcher.poll)
	defer ticker.Stop()
	for {
		delivery, ok, err := dispatcher.store.ClaimNextCallback(ctx, dispatcher.lease)
		if err != nil && ctx.Err() == nil {
			log.Printf("callback_delivery_claim_failed error=%q", err.Error())
		}
		if ok {
			dispatcher.deliver(ctx, delivery)
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (dispatcher *CallbackDispatcher) deliver(ctx context.Context, delivery CallbackDelivery) {
	if dispatcher.token == "" {
		log.Printf("ALERT callback_configuration_failed run_id=%q reason=%q", delivery.Run.RunID, "CAPABILITY_CALLBACK_TOKEN is not configured")
		if err := dispatcher.store.CallbackConfigurationFailed(ctx, delivery.Run.RunID, delivery.LeaseToken, "callback token is not configured"); err != nil {
			log.Printf("callback_configuration_failure_persist_failed run_id=%q error=%q", delivery.Run.RunID, err.Error())
		}
		return
	}
	payload := CallbackPayload{
		WorkflowID: delivery.Run.CallbackWorkflowID,
		Wakeup: CallbackWakeup{
			EventID: delivery.Run.CallbackEventID, Capability: "mitigation-check",
			RequestID: delivery.Run.RequestID, CorrelationID: delivery.Run.CorrelationID, RunID: delivery.Run.RunID,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		dispatcher.configurationFailed(ctx, delivery, "callback payload could not be encoded")
		return
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, delivery.Run.CallbackURL, bytes.NewReader(body))
	if err != nil {
		dispatcher.configurationFailed(ctx, delivery, "callback URL could not create a request")
		return
	}
	request.Header.Set("Authorization", "Bearer "+dispatcher.token)
	request.Header.Set("Content-Type", "application/json")
	response, err := dispatcher.client.Do(request)
	if err != nil {
		dispatcher.retry(ctx, delivery, 0, err)
		return
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
	if response.StatusCode == http.StatusAccepted {
		if err := dispatcher.store.CallbackSucceeded(ctx, delivery.Run.RunID, delivery.LeaseToken); err != nil {
			log.Printf("callback_delivery_completion_failed run_id=%q error=%q", delivery.Run.RunID, err.Error())
		} else {
			log.Printf("callback_delivery_succeeded run_id=%q event_id=%q http_status=%d", delivery.Run.RunID, delivery.Run.CallbackEventID, response.StatusCode)
		}
		return
	}
	if retryableCallbackStatus(response.StatusCode) {
		dispatcher.retry(ctx, delivery, retryAfter(response.Header.Get("Retry-After"), time.Now()), fmt.Errorf("callback returned HTTP %d", response.StatusCode))
		return
	}
	dispatcher.configurationFailed(ctx, delivery, fmt.Sprintf("callback returned non-retryable HTTP %d", response.StatusCode))
}

func (dispatcher *CallbackDispatcher) retry(ctx context.Context, delivery CallbackDelivery, retryAfterDelay time.Duration, cause error) {
	delay := callbackRetryDelay(delivery.Attempt)
	if retryAfterDelay > delay {
		delay = retryAfterDelay
	}
	if err := dispatcher.store.CallbackFailed(ctx, delivery.Run.RunID, delivery.LeaseToken, delay, cause.Error()); err != nil {
		log.Printf("callback_retry_persist_failed run_id=%q error=%q", delivery.Run.RunID, err.Error())
	} else {
		log.Printf("callback_delivery_retry_scheduled run_id=%q event_id=%q attempt=%d retry_delay_ms=%d", delivery.Run.RunID, delivery.Run.CallbackEventID, delivery.Attempt+1, delay.Milliseconds())
	}
}

func (dispatcher *CallbackDispatcher) configurationFailed(ctx context.Context, delivery CallbackDelivery, reason string) {
	log.Printf("ALERT callback_configuration_failed run_id=%q reason=%q", delivery.Run.RunID, reason)
	if err := dispatcher.store.CallbackConfigurationFailed(ctx, delivery.Run.RunID, delivery.LeaseToken, reason); err != nil {
		log.Printf("callback_configuration_failure_persist_failed run_id=%q error=%q", delivery.Run.RunID, err.Error())
	}
}

func retryableCallbackStatus(status int) bool {
	switch status {
	case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func callbackRetryDelay(attempt int) time.Duration {
	schedule := []time.Duration{5 * time.Second, 15 * time.Second, 30 * time.Second, time.Minute, 5 * time.Minute}
	base := 15 * time.Minute
	if attempt >= 0 && attempt < len(schedule) {
		base = schedule[attempt]
	}
	jitter := 0.8 + rand.Float64()*0.4
	return time.Duration(float64(base) * jitter)
}

func retryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}
	when, err := http.ParseTime(value)
	if err != nil || !when.After(now) {
		return 0
	}
	return when.Sub(now)
}

func callbackAllowedHosts() string {
	return os.Getenv("CAPABILITY_CALLBACK_ALLOWED_HOSTS")
}
