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
	"time"
)

const (
	statusQueued    = "queued"
	statusRunning   = "running"
	statusCompleted = "completed"
	statusFailed    = "failed"
	statusCanceled  = "canceled"
)

type Progress struct {
	Phase   string `json:"phase"`
	Percent *int   `json:"percent"`
	Message string `json:"message"`
}

type RunFailure struct {
	Code      string `json:"code"`
	Detail    string `json:"detail"`
	Retryable bool   `json:"retryable"`
}

type Completion struct {
	Capability    string     `json:"capability"`
	ContractID    string     `json:"contract_id"`
	RequestID     string     `json:"request_id"`
	CorrelationID string     `json:"correlation_id"`
	RunID         string     `json:"run_id"`
	ResultID      string     `json:"result_id"`
	Status        string     `json:"status"`
	TerminalState string     `json:"terminal_state"`
	ResultRef     *ResultRef `json:"result_ref"`
	EvidenceRefs  []string   `json:"evidence_refs"`
	ContentSHA256 string     `json:"content_sha256"`
	SizeBytes     int64      `json:"size_bytes"`
	CreatedAt     time.Time  `json:"created_at"`
}

type RunStatus struct {
	Capability    string      `json:"capability"`
	ContractID    string      `json:"contract_id"`
	RequestID     string      `json:"request_id"`
	CorrelationID string      `json:"correlation_id"`
	RunID         string      `json:"run_id"`
	Status        string      `json:"status"`
	TerminalState *string     `json:"terminal_state"`
	ResultID      *string     `json:"result_id"`
	CreatedAt     time.Time   `json:"created_at"`
	StartedAt     *time.Time  `json:"started_at"`
	UpdatedAt     time.Time   `json:"updated_at"`
	CompletedAt   *time.Time  `json:"completed_at"`
	Progress      Progress    `json:"progress"`
	Failure       *RunFailure `json:"failure"`
	Completion    *Completion `json:"completion"`
}

type DurableRun struct {
	RunStatus
	Request             json.RawMessage
	RequestDigest       string
	Result              *RunOutcome
	ResultPayload       []byte
	PublicationPending  bool
	VerificationAttempt int
	PublicationRetryAt  *time.Time
	WorkerID            string
	LeaseToken          string
	Attempt             int
	CancelRequested     bool
	CallbackURL         string
	CallbackWorkflowID  string
	CallbackSignal      string
	CallbackEventID     string
}

func migrateLifecycle(db *sql.DB) error {
	statements := []string{
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS request_id TEXT`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS correlation_id TEXT`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS request_digest TEXT`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS status TEXT`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS progress_phase TEXT`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS progress_message TEXT`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS failure JSONB`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS completion JSONB`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS worker_id TEXT`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS lease_token TEXT`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS attempt INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS last_heartbeat TIMESTAMPTZ`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS cancel_requested BOOLEAN NOT NULL DEFAULT FALSE`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS publication_pending BOOLEAN NOT NULL DEFAULT FALSE`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS result_payload BYTEA`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS verification_attempt INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS publication_retry_at TIMESTAMPTZ`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS callback_url TEXT`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS callback_workflow_id TEXT`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS callback_signal TEXT`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS callback_event_id TEXT`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS callback_state TEXT`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS callback_attempt INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS callback_next_at TIMESTAMPTZ`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS callback_delivered_at TIMESTAMPTZ`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS callback_configuration_failed_at TIMESTAMPTZ`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS callback_last_error TEXT`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS callback_lease_token TEXT`,
		`ALTER TABLE mitigation_check_run ADD COLUMN IF NOT EXISTS callback_lease_expires_at TIMESTAMPTZ`,
		`CREATE UNIQUE INDEX IF NOT EXISTS mitigation_check_run_request_id_uq ON mitigation_check_run(request_id) WHERE request_id IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS mitigation_check_run_worker_idx ON mitigation_check_run(status, lease_expires_at, created_at)`,
		`CREATE INDEX IF NOT EXISTS mitigation_check_run_callback_idx ON mitigation_check_run(callback_state, callback_next_at) WHERE callback_url IS NOT NULL`,
		`UPDATE mitigation_check_run SET status=CASE WHEN terminal_state='malfunction' THEN 'failed' ELSE 'completed' END,
		 updated_at=COALESCE(updated_at,created_at), completed_at=COALESCE(completed_at,created_at),
		 progress_phase=COALESCE(progress_phase,'finished'), progress_message=COALESCE(progress_message,'Legacy run completed') WHERE status IS NULL`,
		`UPDATE mitigation_check_run SET callback_state=CASE
		 WHEN callback_delivered_at IS NOT NULL THEN 'delivered'
		 WHEN callback_configuration_failed_at IS NOT NULL THEN 'configuration_failed'
		 WHEN status IN ('completed','failed','canceled') THEN 'pending'
		 ELSE 'waiting' END,
		 callback_next_at=COALESCE(callback_next_at,updated_at,created_at)
		 WHERE callback_url IS NOT NULL AND callback_state IS NULL`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			return err
		}
	}
	return backfillCanonicalResultPayloads(db)
}

func backfillCanonicalResultPayloads(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.Query(`SELECT run_id,status,publication_pending,response FROM mitigation_check_run
		WHERE request_id IS NOT NULL AND result_payload IS NULL AND response<>'{}'::jsonb FOR UPDATE`)
	if err != nil {
		return err
	}
	type backfill struct {
		id      string
		payload []byte
	}
	var pending []backfill
	for rows.Next() {
		var id string
		var status string
		var publicationPending bool
		var projection []byte
		if err := rows.Scan(&id, &status, &publicationPending, &projection); err != nil {
			_ = rows.Close()
			return err
		}
		if publicationPending || status == statusCompleted {
			_ = rows.Close()
			return fmt.Errorf("cannot infer exact canonical payload for previously published run %s", id)
		}
		var outcome RunOutcome
		if err := json.Unmarshal(projection, &outcome); err != nil {
			_ = rows.Close()
			return fmt.Errorf("decode staged result %s for canonical payload migration: %w", id, err)
		}
		if err := setCanonicalIntegrity(&outcome); err != nil {
			_ = rows.Close()
			return fmt.Errorf("recompute staged result %s integrity for canonical payload migration: %w", id, err)
		}
		payload, err := canonicalResultPayload(outcome)
		if err != nil {
			_ = rows.Close()
			return fmt.Errorf("rebuild staged result %s for canonical payload migration: %w", id, err)
		}
		pending = append(pending, backfill{id: id, payload: payload})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range pending {
		if _, err := tx.Exec(`UPDATE mitigation_check_run SET response=$2::jsonb,result_payload=$3
			WHERE run_id=$1 AND result_payload IS NULL AND publication_pending=FALSE AND status<>'completed'`,
			item.id, string(item.payload), item.payload); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *RunStore) CreateOrGet(ctx context.Context, run DurableRun) (DurableRun, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DurableRun{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `INSERT INTO mitigation_check_run
		(run_id,result_id,terminal_state,match,created_at,request,response,request_id,
		 correlation_id,request_digest,status,updated_at,progress_phase,progress_message,
			 callback_url,callback_workflow_id,callback_signal,callback_event_id,callback_state,callback_next_at)
		VALUES($1,$2,'',FALSE,$3,$4,'{}',$5,$6,$7,'queued',$3,'queued','Awaiting worker',$8,$9,$10,$11,
		       CASE WHEN $8::text IS NULL THEN NULL ELSE 'waiting' END,$3)
		ON CONFLICT (request_id) WHERE request_id IS NOT NULL DO NOTHING`, run.RunID,
		*run.ResultID, run.CreatedAt, []byte(run.Request), run.RequestID, run.CorrelationID,
		run.RequestDigest, nullable(run.CallbackURL), nullable(run.CallbackWorkflowID), nullable(run.CallbackSignal), nullable(run.CallbackEventID))
	if err != nil {
		return DurableRun{}, false, err
	}
	n, _ := res.RowsAffected()
	stored, err := getDurable(ctx, tx, "request_id", run.RequestID)
	if err != nil {
		return DurableRun{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return DurableRun{}, false, err
	}
	return stored, n == 1, nil
}

type rowQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func getDurable(ctx context.Context, q rowQuerier, column, value string) (DurableRun, error) {
	query := `SELECT run_id,request_id,correlation_id,request_digest,status,NULLIF(terminal_state,''),
		NULLIF(result_id,''),created_at,started_at,COALESCE(updated_at,created_at),completed_at,
		COALESCE(progress_phase,''),COALESCE(progress_message,''),failure,request,response,result_payload,
		publication_pending,verification_attempt,publication_retry_at,COALESCE(worker_id,''),COALESCE(lease_token,''),attempt,cancel_requested,COALESCE(callback_url,''),
		COALESCE(callback_workflow_id,''),COALESCE(callback_signal,''),COALESCE(callback_event_id,'') FROM mitigation_check_run WHERE ` + column + `=$1`
	var run DurableRun
	var terminal, resultID sql.NullString
	var failure, request, response, resultPayload []byte
	err := q.QueryRowContext(ctx, query, value).Scan(&run.RunID, &run.RequestID, &run.CorrelationID,
		&run.RequestDigest, &run.Status, &terminal, &resultID, &run.CreatedAt, &run.StartedAt,
		&run.UpdatedAt, &run.CompletedAt, &run.Progress.Phase, &run.Progress.Message, &failure,
		&request, &response, &resultPayload, &run.PublicationPending, &run.VerificationAttempt, &run.PublicationRetryAt, &run.WorkerID, &run.LeaseToken,
		&run.Attempt, &run.CancelRequested, &run.CallbackURL,
		&run.CallbackWorkflowID, &run.CallbackSignal, &run.CallbackEventID)
	if err != nil {
		return run, err
	}
	run.Capability = "mitigation-check"
	run.ContractID = "capability-run-status@1.0"
	run.Request = request
	run.ResultPayload = append([]byte(nil), resultPayload...)
	if terminal.Valid {
		run.TerminalState = &terminal.String
	}
	if resultID.Valid {
		run.ResultID = &resultID.String
	}
	if len(failure) > 0 {
		var f RunFailure
		if json.Unmarshal(failure, &f) == nil {
			run.Failure = &f
		}
	}
	if len(resultPayload) > 0 {
		var result RunOutcome
		if json.Unmarshal(resultPayload, &result) == nil {
			run.Result = &result
		}
	} else if len(response) > 2 {
		var result RunOutcome
		if json.Unmarshal(response, &result) == nil {
			run.Result = &result
		}
	}
	run.setCompletion()
	return run, nil
}

func (r *DurableRun) setCompletion() {
	if r.Status != statusCompleted || r.Result == nil {
		return
	}
	o := r.Result
	r.Completion = &Completion{Capability: "mitigation-check", ContractID: "capability-completion@1.0",
		RequestID: r.RequestID, CorrelationID: r.CorrelationID, RunID: r.RunID, ResultID: o.ResultID,
		Status: statusCompleted, TerminalState: o.TerminalState, ResultRef: o.ResultRef,
		EvidenceRefs: o.EvidenceRefs, ContentSHA256: o.ContentSHA256, SizeBytes: o.SizeBytes, CreatedAt: o.CreatedAt}
}

func (s *RunStore) GetDurable(ctx context.Context, id string) (DurableRun, error) {
	return getDurable(ctx, s.db, "run_id", id)
}

func (s *RunStore) GetStatus(ctx context.Context, id string) (RunStatus, error) {
	var status RunStatus
	var terminal, resultID sql.NullString
	var failure, completion []byte
	err := s.db.QueryRowContext(ctx, `SELECT run_id,request_id,correlation_id,status,
		NULLIF(terminal_state,''),NULLIF(result_id,''),created_at,started_at,
		COALESCE(updated_at,created_at),completed_at,COALESCE(progress_phase,''),
		COALESCE(progress_message,''),failure,completion
		FROM mitigation_check_run WHERE run_id=$1`, id).Scan(&status.RunID, &status.RequestID,
		&status.CorrelationID, &status.Status, &terminal, &resultID, &status.CreatedAt,
		&status.StartedAt, &status.UpdatedAt, &status.CompletedAt, &status.Progress.Phase,
		&status.Progress.Message, &failure, &completion)
	if err != nil {
		return status, err
	}
	status.Capability = "mitigation-check"
	status.ContractID = "capability-run-status@1.0"
	if terminal.Valid {
		status.TerminalState = &terminal.String
	}
	if resultID.Valid {
		status.ResultID = &resultID.String
	}
	if len(failure) > 0 {
		var value RunFailure
		if json.Unmarshal(failure, &value) == nil {
			status.Failure = &value
		}
	}
	if len(completion) > 0 {
		var value Completion
		if json.Unmarshal(completion, &value) == nil {
			status.Completion = &value
		}
	}
	return status, nil
}

func (s *RunStore) LeaseNext(ctx context.Context, workerID string, lease time.Duration, maxAttempts int) (DurableRun, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DurableRun{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	var id string
	err = tx.QueryRowContext(ctx, `SELECT run_id FROM mitigation_check_run WHERE
		(cancel_requested=FALSE OR publication_pending=TRUE) AND (attempt<$1 OR response<>'{}'::jsonb)
		AND COALESCE(publication_retry_at,created_at)<=now()
		AND (status='queued' OR (status='running' AND lease_expires_at<=now()))
		ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1`, maxAttempts).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return DurableRun{}, false, nil
	}
	if err != nil {
		return DurableRun{}, false, err
	}
	leaseToken := "mc-lease-" + newID()
	_, err = tx.ExecContext(ctx, `UPDATE mitigation_check_run SET status='running',started_at=COALESCE(started_at,now()),
		updated_at=now(),worker_id=$2,lease_token=$3,lease_expires_at=now()+$4::interval,last_heartbeat=now(),attempt=attempt+1,
		publication_retry_at=NULL,
		progress_phase=CASE WHEN response='{}'::jsonb THEN 'executing' ELSE 'publishing' END,
		progress_message=CASE WHEN response='{}'::jsonb THEN 'Mitigation check in progress' ELSE 'Publishing immutable result' END
		WHERE run_id=$1 AND (cancel_requested=FALSE OR publication_pending=TRUE)`, id, workerID, leaseToken, interval(lease))
	if err != nil {
		return DurableRun{}, false, err
	}
	run, err := getDurable(ctx, tx, "run_id", id)
	if err != nil {
		return run, false, err
	}
	if err = tx.Commit(); err != nil {
		return run, false, err
	}
	return run, true, nil
}

func (s *RunStore) Heartbeat(ctx context.Context, id, workerID, leaseToken string, lease time.Duration) (bool, bool, error) {
	var cancel bool
	err := s.db.QueryRowContext(ctx, `UPDATE mitigation_check_run SET last_heartbeat=now(),
		lease_expires_at=now()+$4::interval,updated_at=now() WHERE run_id=$1 AND worker_id=$2 AND lease_token=$3
		AND status='running' AND lease_expires_at>now() RETURNING cancel_requested`, id, workerID, leaseToken, interval(lease)).Scan(&cancel)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, nil
	}
	return cancel, err == nil, err
}

// UpdateProgress records diagnostic execution state without extending the
// lease. Worker identity and lease fencing prevent stale attempts from
// overwriting the active attempt's status.
func (s *RunStore) UpdateProgress(ctx context.Context, id, workerID, leaseToken, phase, message string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE mitigation_check_run SET progress_phase=$4,
		progress_message=$5,updated_at=now() WHERE run_id=$1 AND worker_id=$2 AND lease_token=$3
		AND status='running' AND lease_expires_at>now()`, id, workerID, leaseToken, phase, message)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *RunStore) StageOutcome(ctx context.Context, id, workerID, leaseToken string, out RunOutcome, payload []byte) (bool, error) {
	if err := validateCanonicalResultPayload(out, payload); err != nil {
		return false, err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE mitigation_check_run SET response=$4::jsonb,result_payload=$5,match=$6,updated_at=now(),
		progress_phase='publishing',progress_message='Publishing immutable result'
		WHERE run_id=$1 AND worker_id=$2 AND lease_token=$3 AND status='running'
		AND cancel_requested=FALSE AND lease_expires_at>now() AND response='{}'::jsonb`, id, workerID, leaseToken, string(payload), payload, out.Match)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// CompletePublished atomically commits a successfully published or verified
// canonical result. A cancellation racing after authoritative publication is
// retained as a terminal request, but cannot hide the completed result. Worker
// and lease predicates fence stale publishers from completing a run.
func (s *RunStore) CompletePublished(ctx context.Context, id, workerID, leaseToken string, out RunOutcome, payload []byte) (bool, error) {
	if out.ResultRef == nil || out.ResultRef.System != "databricks" || out.ResultRef.Key != out.ResultID {
		return false, fmt.Errorf("completed result lacks an authoritative Databricks reference")
	}
	if err := validateCanonicalResultPayload(out, payload); err != nil {
		return false, err
	}
	completion, err := json.Marshal(Completion{Capability: "mitigation-check", ContractID: "capability-completion@1.0",
		RequestID: out.RequestID, CorrelationID: out.CorrelationID, RunID: out.RunID, ResultID: out.ResultID,
		Status: statusCompleted, TerminalState: out.TerminalState, ResultRef: out.ResultRef, EvidenceRefs: out.EvidenceRefs,
		ContentSHA256: out.ContentSHA256, SizeBytes: out.SizeBytes, CreatedAt: out.CreatedAt})
	if err != nil {
		return false, err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE mitigation_check_run SET
		status='completed',terminal_state=$4,match=$5,response=$6::jsonb,result_payload=$8,completion=$7,completed_at=now(),updated_at=now(),
		progress_phase='finished',progress_message='Mitigation check completed',publication_pending=FALSE,
		publication_retry_at=NULL,callback_state=CASE WHEN callback_url IS NULL THEN callback_state ELSE 'pending' END,
		callback_next_at=CASE WHEN callback_url IS NULL THEN callback_next_at ELSE now() END,
		worker_id=NULL,lease_token=NULL,lease_expires_at=NULL
		WHERE run_id=$1 AND worker_id=$2 AND lease_token=$3 AND status='running'
		AND lease_expires_at>now()`, id, workerID, leaseToken, out.TerminalState, out.Match, string(payload), completion, payload)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *RunStore) Fail(ctx context.Context, id, workerID, leaseToken string, f RunFailure) (bool, error) {
	data, _ := json.Marshal(f)
	res, err := s.db.ExecContext(ctx, `UPDATE mitigation_check_run SET
	status='failed',terminal_state='malfunction',failure=$3,completed_at=now(),updated_at=now(),progress_phase='failed',
	progress_message=$4,callback_state=CASE WHEN callback_url IS NULL THEN callback_state ELSE 'pending' END,
	callback_next_at=CASE WHEN callback_url IS NULL THEN callback_next_at ELSE now() END,
	worker_id=NULL,lease_token=NULL,lease_expires_at=NULL WHERE run_id=$1 AND worker_id=$2
	AND lease_token=$5 AND status='running' AND lease_expires_at>now()`, id, workerID, data, f.Detail, leaseToken)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *RunStore) FailOutcome(ctx context.Context, id, workerID, leaseToken string, out RunOutcome, f RunFailure) (bool, error) {
	result, err := json.Marshal(out)
	if err != nil {
		return false, err
	}
	failure, err := json.Marshal(f)
	if err != nil {
		return false, err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE mitigation_check_run SET status='failed',
		terminal_state='malfunction',match=$4,response=$5,failure=$6,completed_at=now(),updated_at=now(),
		progress_phase='failed',progress_message=$7,
		callback_state=CASE WHEN callback_url IS NULL THEN callback_state ELSE 'pending' END,
		callback_next_at=CASE WHEN callback_url IS NULL THEN callback_next_at ELSE now() END,
		worker_id=NULL,lease_token=NULL,lease_expires_at=NULL
		WHERE run_id=$1 AND worker_id=$2 AND lease_token=$3 AND status='running' AND cancel_requested=FALSE
		AND lease_expires_at>now()`, id, workerID, leaseToken, out.Match, result, failure, f.Detail)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *RunStore) FailExhausted(ctx context.Context, max int) error {
	data, _ := json.Marshal(RunFailure{Code: "worker_attempts_exhausted", Detail: "Worker lease expired and the attempt limit was reached", Retryable: false})
	_, err := s.db.ExecContext(ctx, `UPDATE mitigation_check_run SET status='failed',terminal_state='malfunction',failure=$2,
		completed_at=now(),updated_at=now(),progress_phase='failed',progress_message='Worker attempt limit reached',
		callback_state=CASE WHEN callback_url IS NULL THEN callback_state ELSE 'pending' END,
		callback_next_at=CASE WHEN callback_url IS NULL THEN callback_next_at ELSE now() END,
		worker_id=NULL,lease_token=NULL,lease_expires_at=NULL WHERE status='running' AND cancel_requested=FALSE
		AND response='{}'::jsonb AND lease_expires_at<=now() AND attempt>=$1`, max, data)
	return err
}

func (s *RunStore) RecoverCanceled(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE mitigation_check_run SET status='canceled',terminal_state='canceled',
		completed_at=now(),updated_at=now(),progress_phase='canceled',progress_message='Cancellation recovered after worker lease expiry',
		publication_pending=FALSE,callback_state=CASE WHEN callback_url IS NULL THEN callback_state ELSE 'pending' END,
		callback_next_at=CASE WHEN callback_url IS NULL THEN callback_next_at ELSE now() END,
		worker_id=NULL,lease_token=NULL,lease_expires_at=NULL WHERE status='running' AND cancel_requested=TRUE
		AND publication_pending=FALSE AND lease_expires_at<=now()`)
	return err
}

func (s *RunStore) Cancel(ctx context.Context, id string) (DurableRun, error) {
	_, err := s.db.ExecContext(ctx, `UPDATE mitigation_check_run SET cancel_requested=TRUE,
	status=CASE WHEN status='queued' AND publication_pending=FALSE THEN 'canceled' ELSE status END,
	terminal_state=CASE WHEN status='queued' AND publication_pending=FALSE THEN 'canceled' ELSE terminal_state END,
	completed_at=CASE WHEN status='queued' AND publication_pending=FALSE THEN now() ELSE completed_at END,
	updated_at=CASE WHEN status IN ('queued','running') THEN now() ELSE updated_at END,
	callback_state=CASE WHEN status='queued' AND publication_pending=FALSE AND callback_url IS NOT NULL THEN 'pending' ELSE callback_state END,
	callback_next_at=CASE WHEN status='queued' AND publication_pending=FALSE AND callback_url IS NOT NULL THEN now() ELSE callback_next_at END,
	progress_phase=CASE WHEN status='queued' AND publication_pending=FALSE THEN 'canceled' WHEN publication_pending=TRUE THEN 'verifying' ELSE 'canceling' END,
	progress_message=CASE WHEN status='queued' AND publication_pending=FALSE THEN 'Canceled before execution' WHEN publication_pending=TRUE THEN 'Verifying immutable result publication; cancellation cutoff has passed' ELSE 'Cancellation requested' END
	WHERE run_id=$1 AND status IN ('queued','running')`, id)
	if err != nil {
		return DurableRun{}, err
	}
	return s.GetDurable(ctx, id)
}

func (s *RunStore) MarkCanceled(ctx context.Context, id, workerID, leaseToken string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE mitigation_check_run SET status='canceled',terminal_state='canceled',
		completed_at=now(),updated_at=now(),progress_phase='canceled',progress_message='Cancellation completed',publication_pending=FALSE,
		callback_state=CASE WHEN callback_url IS NULL THEN callback_state ELSE 'pending' END,
		callback_next_at=CASE WHEN callback_url IS NULL THEN callback_next_at ELSE now() END,
		worker_id=NULL,lease_token=NULL,lease_expires_at=NULL WHERE run_id=$1 AND worker_id=$2 AND lease_token=$3
		AND status='running' AND cancel_requested=TRUE AND publication_pending=FALSE`, id, workerID, leaseToken)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *RunStore) MarkPublicationPending(ctx context.Context, id, workerID, leaseToken string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE mitigation_check_run SET publication_pending=TRUE,
		publication_retry_at=NULL,updated_at=now(),progress_phase='publishing',progress_message='Publishing immutable result'
		WHERE run_id=$1 AND worker_id=$2 AND lease_token=$3 AND status='running'
		AND cancel_requested=FALSE AND publication_pending=FALSE AND lease_expires_at>now()`, id, workerID, leaseToken)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *RunStore) RetryVerification(ctx context.Context, id, workerID, leaseToken string, maxAttempts int, delay time.Duration, f RunFailure) (bool, error) {
	failure, _ := json.Marshal(f)
	res, err := s.db.ExecContext(ctx, `UPDATE mitigation_check_run SET
		verification_attempt=verification_attempt+1,
		status=CASE WHEN verification_attempt+1>=$4 THEN 'failed' ELSE 'queued' END,
		terminal_state=CASE WHEN verification_attempt+1>=$4 THEN 'malfunction' ELSE '' END,
		failure=CASE WHEN verification_attempt+1>=$4 THEN $6::jsonb ELSE NULL END,
		completed_at=CASE WHEN verification_attempt+1>=$4 THEN now() ELSE NULL END,updated_at=now(),
		progress_phase=CASE WHEN verification_attempt+1>=$4 THEN 'failed' ELSE 'verifying' END,
		progress_message=CASE WHEN verification_attempt+1>=$4 THEN $7 ELSE 'Waiting to retry immutable result verification' END,
		publication_pending=CASE WHEN verification_attempt+1>=$4 THEN FALSE ELSE TRUE END,
		publication_retry_at=CASE WHEN verification_attempt+1>=$4 THEN NULL ELSE now()+$5::interval END,
		callback_state=CASE WHEN verification_attempt+1>=$4 AND callback_url IS NOT NULL THEN 'pending' ELSE callback_state END,
		callback_next_at=CASE WHEN verification_attempt+1>=$4 AND callback_url IS NOT NULL THEN now() ELSE callback_next_at END,
		worker_id=NULL,lease_token=NULL,lease_expires_at=NULL
		WHERE run_id=$1 AND worker_id=$2 AND lease_token=$3 AND status='running' AND publication_pending=TRUE
		AND lease_expires_at>now()`, id, workerID, leaseToken, maxAttempts, interval(delay), failure, f.Detail)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *RunStore) FailPublicationConflict(ctx context.Context, id, workerID, leaseToken string, f RunFailure) (bool, error) {
	failure, _ := json.Marshal(f)
	res, err := s.db.ExecContext(ctx, `UPDATE mitigation_check_run SET status='failed',terminal_state='malfunction',
		failure=$4,completed_at=now(),updated_at=now(),progress_phase='failed',progress_message=$5,
		publication_pending=FALSE,callback_state=CASE WHEN callback_url IS NULL THEN callback_state ELSE 'pending' END,
		callback_next_at=CASE WHEN callback_url IS NULL THEN callback_next_at ELSE now() END,
		worker_id=NULL,lease_token=NULL,lease_expires_at=NULL
		WHERE run_id=$1 AND worker_id=$2 AND lease_token=$3 AND status='running' AND lease_expires_at>now()`,
		id, workerID, leaseToken, failure, f.Detail)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func canonicalResultPayload(out RunOutcome) ([]byte, error) {
	payload, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	if err := validateCanonicalResultPayload(out, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func validateCanonicalResultPayload(out RunOutcome, payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("canonical result payload is empty")
	}
	var decoded RunOutcome
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return fmt.Errorf("decode canonical result payload: %w", err)
	}
	if decoded.RunID != out.RunID || decoded.ResultID != out.ResultID || decoded.ContentSHA256 != out.ContentSHA256 || decoded.SizeBytes != out.SizeBytes {
		return fmt.Errorf("canonical result payload identity or integrity metadata does not match parsed projection")
	}
	unsigned := decoded
	unsigned.ContentSHA256 = ""
	unsigned.SizeBytes = 0
	canonicalUnsigned, err := json.Marshal(unsigned)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(canonicalUnsigned)
	wantDigest := "sha256:" + hex.EncodeToString(sum[:])
	if decoded.ContentSHA256 != wantDigest || decoded.SizeBytes != int64(len(canonicalUnsigned)) {
		return fmt.Errorf("canonical result integrity metadata is invalid")
	}
	canonicalFull, err := json.Marshal(decoded)
	if err != nil {
		return err
	}
	if !bytes.Equal(canonicalFull, payload) {
		return fmt.Errorf("result payload is not canonical JSON")
	}
	return nil
}

type CallbackDelivery struct {
	Run        DurableRun
	Attempt    int
	LeaseToken string
}

func (s *RunStore) ClaimNextCallback(ctx context.Context, lease time.Duration) (CallbackDelivery, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return CallbackDelivery{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	var id string
	var attempt int
	err = tx.QueryRowContext(ctx, `SELECT run_id,callback_attempt FROM mitigation_check_run
		WHERE status IN ('completed','failed','canceled') AND callback_url IS NOT NULL
		AND callback_state IN ('pending','retry','delivering') AND callback_next_at<=now()
		AND (callback_lease_expires_at IS NULL OR callback_lease_expires_at<=now())
		ORDER BY callback_next_at,created_at FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&id, &attempt)
	if errors.Is(err, sql.ErrNoRows) {
		return CallbackDelivery{}, false, nil
	}
	if err != nil {
		return CallbackDelivery{}, false, err
	}
	leaseToken := newID()
	if _, err := tx.ExecContext(ctx, `UPDATE mitigation_check_run SET callback_state='delivering',
		callback_lease_token=$2,callback_lease_expires_at=now()+$3::interval WHERE run_id=$1`, id, leaseToken, interval(lease)); err != nil {
		return CallbackDelivery{}, false, err
	}
	run, err := getDurable(ctx, tx, "run_id", id)
	if err != nil {
		return CallbackDelivery{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return CallbackDelivery{}, false, err
	}
	return CallbackDelivery{Run: run, Attempt: attempt, LeaseToken: leaseToken}, true, nil
}

func (s *RunStore) CallbackSucceeded(ctx context.Context, id, leaseToken string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE mitigation_check_run SET callback_state='delivered',callback_delivered_at=now(),
		callback_attempt=callback_attempt+1,callback_last_error=NULL,callback_lease_token=NULL,callback_lease_expires_at=NULL
		WHERE run_id=$1 AND callback_state='delivering' AND callback_lease_token=$2`, id, leaseToken)
	return requireCallbackUpdate(res, err)
}

func (s *RunStore) CallbackFailed(ctx context.Context, id, leaseToken string, delay time.Duration, reason string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE mitigation_check_run SET callback_state='retry',callback_attempt=callback_attempt+1,
		callback_next_at=now()+$3::interval,callback_last_error=$4,callback_lease_token=NULL,callback_lease_expires_at=NULL
		WHERE run_id=$1 AND callback_state='delivering' AND callback_lease_token=$2`, id, leaseToken, interval(delay), reason)
	return requireCallbackUpdate(res, err)
}

func (s *RunStore) CallbackConfigurationFailed(ctx context.Context, id, leaseToken, reason string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE mitigation_check_run SET callback_state='configuration_failed',
		callback_attempt=callback_attempt+1,callback_configuration_failed_at=now(),callback_last_error=$3,
		callback_lease_token=NULL,callback_lease_expires_at=NULL
		WHERE run_id=$1 AND callback_state='delivering' AND callback_lease_token=$2`, id, leaseToken, reason)
	return requireCallbackUpdate(res, err)
}

func requireCallbackUpdate(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated != 1 {
		return fmt.Errorf("callback delivery lease is no longer owned")
	}
	return nil
}

func nullable(v string) any {
	if v == "" {
		return nil
	}
	return v
}
func interval(v time.Duration) string { return fmt.Sprintf("%f seconds", v.Seconds()) }
