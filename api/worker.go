package main

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"sync/atomic"
	"time"
)

type DurableExecutor func(context.Context, DurableRun) (RunOutcome, error)
type ResultPublisher interface {
	Publish(context.Context, RunOutcome, []byte) error
}

type ResultVerifier interface {
	Verify(context.Context, RunOutcome, []byte) error
}

type RunWorker struct {
	store                   *RunStore
	execute                 DurableExecutor
	publisher               ResultPublisher
	workerID                string
	lease                   time.Duration
	poll                    time.Duration
	maxAttempts             int
	maxVerificationAttempts int
	verificationBackoff     time.Duration
}

func NewRunWorker(store *RunStore, execute DurableExecutor, publisher ResultPublisher) *RunWorker {
	return &RunWorker{store: store, execute: execute, publisher: publisher,
		workerID: "mc-worker-" + hostname() + "-" + newID(), lease: 30 * time.Second, poll: 500 * time.Millisecond, maxAttempts: 3,
		maxVerificationAttempts: 6, verificationBackoff: 5 * time.Second}
}

func (w *RunWorker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.poll)
	defer ticker.Stop()
	for {
		if err := w.store.RecoverCanceled(ctx); err != nil && ctx.Err() == nil {
			logLifecycle("cancellation_recovery_failed", DurableRun{}, map[string]any{"error": err.Error()})
		}
		if err := w.store.FailExhausted(ctx, w.maxAttempts); err != nil && ctx.Err() == nil {
			logLifecycle("lease_recovery_failed", DurableRun{}, map[string]any{"error": err.Error()})
		}
		run, ok, err := w.store.LeaseNext(ctx, w.workerID, w.lease, w.maxAttempts)
		if err != nil && ctx.Err() == nil {
			logLifecycle("lease_claim_failed", DurableRun{}, map[string]any{"worker_id": w.workerID, "error": err.Error()})
		}
		if ok {
			w.executeOne(ctx, run)
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (w *RunWorker) executeOne(parent context.Context, run DurableRun) {
	executionCtx, cancelExecution := context.WithCancel(parent)
	heartbeatCtx, stopHeartbeat := context.WithCancel(parent)
	done := make(chan struct{})
	defer func() {
		cancelExecution()
		stopHeartbeat()
		<-done
	}()
	var leaseLost atomic.Bool
	var cancellationRequested atomic.Bool
	go func() {
		ticker := time.NewTicker(w.lease / 3)
		defer ticker.Stop()
		defer close(done)
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				requested, owned, err := w.store.Heartbeat(parent, run.RunID, w.workerID, run.LeaseToken, w.lease)
				if err != nil {
					leaseLost.Store(true)
					logLifecycle("lease_heartbeat_failed", run, map[string]any{"error": err.Error()})
					cancelExecution()
					return
				}
				if !owned {
					leaseLost.Store(true)
					logLifecycle("lease_lost", run, nil)
					cancelExecution()
					return
				}
				if requested {
					cancellationRequested.Store(true)
					cancelExecution()
				}
			}
		}
	}()
	var outcome RunOutcome
	var payload []byte
	var err error
	if run.Result != nil {
		outcome = *run.Result
		payload = append([]byte(nil), run.ResultPayload...)
		logLifecycle("staged_result_recovered", run, nil)
	} else {
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					err = fmt.Errorf("executor panic: %v", recovered)
					logLifecycle("executor_panic", run, map[string]any{"stack": string(debug.Stack())})
				}
			}()
			outcome, err = w.execute(executionCtx, run)
		}()
	}
	requested, owned, heartbeatErr := w.store.Heartbeat(parent, run.RunID, w.workerID, run.LeaseToken, w.lease)
	if heartbeatErr != nil || !owned {
		leaseLost.Store(true)
	}
	if requested {
		cancellationRequested.Store(true)
	}
	if cancellationRequested.Load() && !run.PublicationPending {
		written, markErr := w.store.MarkCanceled(parent, run.RunID, w.workerID, run.LeaseToken)
		if markErr != nil {
			logLifecycle("run_cancellation_failed", run, map[string]any{"error": markErr.Error()})
		} else if written {
			logLifecycle("run_canceled", run, nil)
		}
		return
	}
	if leaseLost.Load() || parent.Err() != nil {
		logLifecycle("run_abandoned_after_lease_loss", run, nil)
		return
	}
	if err != nil {
		failure := RunFailure{Code: "execution_failed", Detail: "Mitigation check execution failed", Retryable: false}
		written, transitionErr := w.store.Fail(parent, run.RunID, w.workerID, run.LeaseToken, failure)
		logLifecycle("run_failed", run, map[string]any{
			"failure_code": failure.Code, "error": err.Error(), "transition_written": written, "transition_error": errorString(transitionErr),
		})
		return
	}
	if outcome.TerminalState == stateMalfunction {
		failure := RunFailure{Code: "mitigation_check_malfunction", Detail: "Mitigation check reported a malfunction", Retryable: false}
		written, transitionErr := w.store.FailOutcome(parent, run.RunID, w.workerID, run.LeaseToken, outcome, failure)
		logLifecycle("run_failed", run, map[string]any{
			"failure_code": failure.Code, "transition_written": written, "transition_error": errorString(transitionErr),
		})
		return
	}
	if run.Result == nil {
		payload, err = canonicalResultPayload(outcome)
		if err != nil {
			logLifecycle("result_encoding_failed", run, map[string]any{"error": err.Error()})
			return
		}
		staged, stageErr := w.store.StageOutcome(parent, run.RunID, w.workerID, run.LeaseToken, outcome, payload)
		if stageErr != nil || !staged {
			detail := errorString(stageErr)
			if detail == "" {
				detail = "lease no longer owned"
			}
			logLifecycle("result_staging_failed", run, map[string]any{"error": detail})
			return
		}
	}
	if w.publisher == nil || outcome.ResultRef == nil {
		if run.PublicationPending {
			w.retryVerification(parent, run, fmt.Errorf("authoritative Databricks result verifier is unavailable"))
			return
		}
		failure := RunFailure{Code: "result_store_unavailable", Detail: "Authoritative Databricks result publication is unavailable", Retryable: true}
		written, transitionErr := w.store.FailOutcome(parent, run.RunID, w.workerID, run.LeaseToken, outcome, failure)
		logLifecycle("run_failed", run, map[string]any{
			"failure_code": failure.Code, "transition_written": written, "transition_error": errorString(transitionErr),
		})
		return
	}
	// Linearize cancellation immediately before the first publication attempt.
	// Once publication_pending is durable, cancellation must reconcile by
	// result_id before it can become terminal.
	reconcileOnly := run.PublicationPending
	if !run.PublicationPending {
		requested, owned, heartbeatErr := w.store.Heartbeat(parent, run.RunID, w.workerID, run.LeaseToken, w.lease)
		if heartbeatErr != nil || !owned {
			logLifecycle("publication_fence_failed", run, map[string]any{"error": errorString(heartbeatErr)})
			return
		}
		if requested {
			written, markErr := w.store.MarkCanceled(parent, run.RunID, w.workerID, run.LeaseToken)
			logLifecycle("run_canceled_before_publication", run, map[string]any{
				"transition_written": written, "transition_error": errorString(markErr),
			})
			return
		}
		marked, markErr := w.store.MarkPublicationPending(parent, run.RunID, w.workerID, run.LeaseToken)
		if markErr != nil || !marked {
			logLifecycle("result_publication_fence_failed", run, map[string]any{"error": errorString(markErr)})
			return
		}
		run.PublicationPending = true
	}
	if run.PublicationPending {
		verifier, ok := w.publisher.(ResultVerifier)
		if reconcileOnly {
			if !ok {
				w.retryVerification(parent, run, fmt.Errorf("publisher does not support verification"))
				return
			}
			if w.reconcilePublication(parent, run, outcome, payload, verifier) {
				return
			}
		} else if err := w.publisher.Publish(context.WithoutCancel(parent), outcome, payload); err != nil {
			if _, ambiguous := publicationVerificationFailure(err); ambiguous {
				if !ok {
					w.retryVerification(parent, run, err)
					return
				}
				if w.reconcilePublication(parent, run, outcome, payload, verifier) {
					return
				}
			} else {
				w.retryVerification(parent, run, err)
				return
			}
		}
	}
	written, err := w.store.CompletePublished(parent, run.RunID, w.workerID, run.LeaseToken, outcome, payload)
	if err != nil {
		logLifecycle("run_completion_failed", run, map[string]any{"error": err.Error()})
		return
	}
	if written {
		logLifecycle("run_completed", run, map[string]any{"terminal_state": outcome.TerminalState})
		return
	}
	logLifecycle("run_completion_fenced", run, nil)
}

func (w *RunWorker) reconcilePublication(ctx context.Context, run DurableRun, outcome RunOutcome, payload []byte, verifier ResultVerifier) bool {
	verificationErr := verifier.Verify(context.WithoutCancel(ctx), outcome, payload)
	if verificationErr == nil {
		written, transitionErr := w.store.CompletePublished(ctx, run.RunID, w.workerID, run.LeaseToken, outcome, payload)
		logLifecycle("result_publication_reconciled", run, map[string]any{"transition_written": written, "transition_error": errorString(transitionErr)})
		return true
	}
	state, classified := publicationVerificationFailure(verificationErr)
	if classified && state == publicationAbsent {
		w.retryVerification(ctx, run, verificationErr)
		return true
	}
	if classified && state == publicationConflict {
		failure := RunFailure{Code: "result_publication_conflict", Detail: "Authoritative Databricks result conflicts with the staged canonical result", Retryable: false}
		written, transitionErr := w.store.FailPublicationConflict(ctx, run.RunID, w.workerID, run.LeaseToken, failure)
		logLifecycle("result_publication_conflict", run, map[string]any{"transition_written": written, "transition_error": errorString(transitionErr)})
		return true
	}
	w.retryVerification(ctx, run, verificationErr)
	return true
}

func (w *RunWorker) retryVerification(ctx context.Context, run DurableRun, verificationErr error) {
	failure := RunFailure{Code: "publication_verification_failed", Detail: "Immutable Databricks result publication could not be verified within the bounded retry policy", Retryable: false}
	delay := w.verificationDelay(run.VerificationAttempt)
	written, transitionErr := w.store.RetryVerification(ctx, run.RunID, w.workerID, run.LeaseToken, w.maxVerificationAttempts, delay, failure)
	logLifecycle("result_publication_verification_failed", run, map[string]any{
		"failure_code": failure.Code, "error": verificationErr.Error(),
		"verification_attempt": run.VerificationAttempt + 1, "retry_delay_ms": delay.Milliseconds(),
		"transition_written": written, "transition_error": errorString(transitionErr),
	})
}

func (w *RunWorker) verificationDelay(attempt int) time.Duration {
	delay := w.verificationBackoff
	for i := 0; i < attempt && delay < 5*time.Minute; i++ {
		delay *= 2
		if delay > 5*time.Minute {
			return 5 * time.Minute
		}
	}
	return delay
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil || name == "" {
		return "unknown"
	}
	return name
}
func value(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
