package main

// databricks.go publishes canonical results after they have been staged in the
// PostgreSQL lifecycle ledger. Publication is insert-only and idempotent. A
// completed async run is exposed only after exact read-back verification.
//
// Env:
//   DATABRICKS_DSN      token:<PAT>@<host>[:443]/sql/1.0/warehouses/<id>
//   DATABRICKS_CATALOG  e.g. 36889_janus_dev
//   DATABRICKS_SCHEMA   e.g. mitigation-check
//   DATABRICKS_TABLE    e.g. mitigation_check
//
// Table:
//   create table mitigation_check(run_id string, result_id string,
//     result_json STRING, constraint run_pk primary key(run_id, result_id)) using delta

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	_ "github.com/databricks/databricks-sql-go"
)

type DatabricksSink struct {
	db      *sql.DB
	table   string // fully-qualified `catalog`.`schema`.`table`
	catalog string
	schema  string
	name    string
}

type PublicationVerificationError struct {
	Err   error
	State PublicationVerificationState
}

type PublicationVerificationState string

const (
	publicationUnknown  PublicationVerificationState = "unknown"
	publicationAbsent   PublicationVerificationState = "absent"
	publicationConflict PublicationVerificationState = "conflict"
)

func (e *PublicationVerificationError) Error() string { return e.Err.Error() }
func (e *PublicationVerificationError) Unwrap() error { return e.Err }

func publicationVerificationFailure(err error) (PublicationVerificationState, bool) {
	var verificationErr *PublicationVerificationError
	if !errors.As(err, &verificationErr) {
		return "", false
	}
	return verificationErr.State, true
}

// NewDatabricksSink returns nil (disabled) when DATABRICKS_DSN is unset.
func NewDatabricksSink() *DatabricksSink {
	dsn := os.Getenv("DATABRICKS_DSN")
	if strings.TrimSpace(dsn) == "" {
		return nil
	}
	db, err := sql.Open("databricks", normalizeDatabricksDSN(dsn))
	if err != nil {
		log.Printf("databricks: disabled (open failed: %v)", err)
		return nil
	}
	db.SetMaxOpenConns(4)

	catalog := strings.TrimSpace(os.Getenv("DATABRICKS_CATALOG"))
	schema := firstNonEmpty(strings.TrimSpace(os.Getenv("DATABRICKS_SCHEMA")), "mitigation_check")
	name := firstNonEmpty(strings.TrimSpace(os.Getenv("DATABRICKS_TABLE")), "mitigation_check")
	if catalog == "" {
		_ = db.Close()
		log.Printf("databricks: disabled (DATABRICKS_CATALOG is required for authoritative result references)")
		return nil
	}
	qualified := backtick(catalog) + "." + backtick(schema) + "." + backtick(name)
	log.Printf("databricks: enabled -> %s", qualified)
	return &DatabricksSink{db: db, table: qualified, catalog: catalog, schema: schema, name: name}
}

func (s *DatabricksSink) ResultRef(resultID string) *ResultRef {
	if s == nil {
		return nil
	}
	return &ResultRef{System: "databricks", Catalog: s.catalog, Schema: s.schema, Table: s.name, Key: resultID}
}

// Publish creates an immutable result row or verifies that an identical row was
// already created by an earlier lease holder. It never updates existing content.
func (s *DatabricksSink) Publish(ctx context.Context, outcome RunOutcome, payload []byte) error {
	if s == nil || outcome.ResultRef == nil {
		return fmt.Errorf("Databricks result sink is not configured")
	}
	expectedRef := s.ResultRef(outcome.ResultID)
	if *outcome.ResultRef != *expectedRef {
		return fmt.Errorf("result reference does not match configured Databricks destination")
	}
	if err := validateCanonicalResultPayload(outcome, payload); err != nil {
		return fmt.Errorf("invalid canonical result payload: %w", err)
	}
	// result_id is written as-is (the full "mitigation-check-result:<hex>" value) so
	// consumers query WHERE result_id = <value>; result_ref.key reports the same value.
	runID := outcome.RunID
	resultID := outcome.ResultID
	logLifecycle("result_publication_started", outcomeIdentity(outcome), map[string]any{"terminal_state": outcome.TerminalState})

	c, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	start := time.Now()
	q := immutableResultMergeSQL(s.table)
	if _, err := s.db.ExecContext(c, q, runID, resultID, string(payload)); err != nil {
		logLifecycle("result_publication_write_failed", outcomeIdentity(outcome), map[string]any{
			"duration_ms": time.Since(start).Milliseconds(), "error": err.Error(),
		})
		return &PublicationVerificationError{Err: fmt.Errorf("MERGE immutable Databricks result: %w", err)}
	}
	if err := s.verifyPayload(c, outcome, payload); err != nil {
		return err
	}
	logLifecycle("result_publication_succeeded", outcomeIdentity(outcome), map[string]any{"duration_ms": time.Since(start).Milliseconds()})
	return nil
}

// Verify performs readback only. Workers use it after a MERGE may have
// succeeded so recovery cannot execute the mitigation check or rewrite a row.
func (s *DatabricksSink) Verify(ctx context.Context, outcome RunOutcome, payload []byte) error {
	if s == nil || outcome.ResultRef == nil {
		return fmt.Errorf("Databricks result sink is not configured")
	}
	if err := validateCanonicalResultPayload(outcome, payload); err != nil {
		return fmt.Errorf("invalid canonical result payload: %w", err)
	}
	c, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	return s.verifyPayload(c, outcome, payload)
}

func (s *DatabricksSink) verifyPayload(ctx context.Context, outcome RunOutcome, payload []byte) error {
	runID := outcome.RunID
	resultID := outcome.ResultID
	rows, err := s.db.QueryContext(ctx, "SELECT run_id, result_json FROM "+s.table+" WHERE result_id = ?", resultID)
	if err != nil {
		return &PublicationVerificationError{Err: fmt.Errorf("verify immutable Databricks result: %w", err)}
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var storedRunID, storedPayload string
		if err := rows.Scan(&storedRunID, &storedPayload); err != nil {
			return &PublicationVerificationError{Err: fmt.Errorf("scan immutable Databricks result: %w", err)}
		}
		count++
		if storedRunID != runID || storedPayload != string(payload) {
			return &PublicationVerificationError{Err: fmt.Errorf("immutable Databricks result conflict for result_id %s", resultID), State: publicationConflict}
		}
	}
	if err := rows.Err(); err != nil {
		return &PublicationVerificationError{Err: fmt.Errorf("verify immutable Databricks result: %w", err)}
	}
	if count == 0 {
		return &PublicationVerificationError{Err: fmt.Errorf("immutable Databricks result verification found no row for result_id %s", resultID), State: publicationAbsent}
	}
	if count > 1 {
		return &PublicationVerificationError{Err: fmt.Errorf("immutable Databricks result verification found %d rows for result_id %s", count, resultID), State: publicationConflict}
	}
	return nil
}

func outcomeIdentity(outcome RunOutcome) DurableRun {
	resultID := outcome.ResultID
	return DurableRun{RunStatus: RunStatus{
		RequestID: outcome.RequestID, CorrelationID: outcome.CorrelationID, RunID: outcome.RunID,
		ResultID: &resultID, Status: statusRunning,
	}}
}

func immutableResultMergeSQL(table string) string {
	return "MERGE INTO " + table + " AS target USING (SELECT ? AS run_id, ? AS result_id, ? AS result_json) AS source " +
		"ON target.result_id = source.result_id WHEN NOT MATCHED THEN INSERT (run_id, result_id, result_json) " +
		"VALUES (source.run_id, source.result_id, source.result_json)"
}

func (s *DatabricksSink) Close() {
	if s != nil && s.db != nil {
		_ = s.db.Close()
	}
}

// backtick quotes a Databricks SQL identifier (handles leading digits / hyphens).
func backtick(id string) string {
	return "`" + strings.ReplaceAll(id, "`", "``") + "`"
}

// normalizeDatabricksDSN inserts :443 when the host has no explicit port, which
// the databricks-sql-go driver requires.
func normalizeDatabricksDSN(dsn string) string {
	at := strings.Index(dsn, "@")
	if at < 0 {
		return dsn
	}
	creds, rest := dsn[:at+1], dsn[at+1:]
	host, path := rest, ""
	if slash := strings.Index(rest, "/"); slash >= 0 {
		host, path = rest[:slash], rest[slash:]
	}
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	return creds + host + path
}
