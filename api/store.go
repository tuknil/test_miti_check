package main

// store.go is the run ledger (LLD §11.1: mitigation_check_run / _result), backed
// by a PostgreSQL database (run as its own container via docker compose). Data
// durability is a property of the db container's volume, not this process.
//
// The immutable request and the executed response are stored as JSONB columns.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// RunRecord is one ledger entry: the immutable request and its executed result.
type RunRecord struct {
	RunID         string          `json:"run_id"`
	ResultID      string          `json:"result_id"`
	TerminalState string          `json:"terminal_state"`
	Match         bool            `json:"match"`
	CreatedAt     time.Time       `json:"created_at"`
	Request       json.RawMessage `json:"request"` // exact submitted payload, immutable
	Response      RunOutcome      `json:"response"`
}

// RunSummary is the compact form shown in the left run panel.
type RunSummary struct {
	RunID         string    `json:"run_id"`
	ResultID      string    `json:"result_id"`
	TerminalState string    `json:"terminal_state"`
	Match         bool      `json:"match"`
	CorrelationID string    `json:"correlation_id,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

type RunStore struct {
	db *sql.DB
}

// NewRunStore connects to Postgres at dsn, waiting for it to accept connections
// (the db container may still be starting), then ensures the schema exists.
func NewRunStore(dsn string) (*RunStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(8)
	db.SetConnMaxLifetime(30 * time.Minute)

	var pingErr error
	for i := 0; i < 30; i++ {
		if pingErr = db.Ping(); pingErr == nil {
			break
		}
		log.Printf("ledger: waiting for postgres… (%v)", pingErr)
		time.Sleep(2 * time.Second)
	}
	if pingErr != nil {
		_ = db.Close()
		return nil, fmt.Errorf("postgres not reachable: %w", pingErr)
	}

	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS mitigation_check_run (
			run_id         TEXT        PRIMARY KEY,
			result_id      TEXT        NOT NULL,
			terminal_state TEXT        NOT NULL,
			match          BOOLEAN     NOT NULL,
			created_at     TIMESTAMPTZ NOT NULL,
			request        JSONB       NOT NULL,
			response       JSONB       NOT NULL
		)`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}

	s := &RunStore{db: db}
	log.Printf("ledger: connected to postgres (%d run(s))", s.count())
	return s, nil
}

func (s *RunStore) count() int {
	var n int
	_ = s.db.QueryRow(`SELECT count(*) FROM mitigation_check_run`).Scan(&n)
	return n
}

// Close releases the connection pool. The database itself lives in the db
// container and its data persists on that container's volume.
func (s *RunStore) Close() {
	if s.db != nil {
		_ = s.db.Close()
	}
}

// Add durably records a run. request is stored as-is (JSONB); response is stored
// via storedResultJSON (the API body plus the embedded candidate/test_basis).
func (s *RunStore) Add(r *RunRecord) error {
	resp, err := storedResultJSON(r.Response)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
		INSERT INTO mitigation_check_run
			(run_id, result_id, terminal_state, match, created_at, request, response)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		r.RunID, r.ResultID, r.TerminalState, r.Match, r.CreatedAt,
		[]byte(r.Request), resp)
	return err
}

func (s *RunStore) Get(id string) (*RunRecord, bool) {
	var (
		rec      RunRecord
		request  []byte
		response []byte
	)
	err := s.db.QueryRow(`
		SELECT run_id, result_id, terminal_state, match, created_at, request, response
		FROM mitigation_check_run WHERE run_id = $1`, id).
		Scan(&rec.RunID, &rec.ResultID, &rec.TerminalState, &rec.Match,
			&rec.CreatedAt, &request, &response)
	if err != nil {
		return nil, false
	}
	rec.Request = json.RawMessage(request)
	if err := json.Unmarshal(response, &rec.Response); err != nil {
		return nil, false
	}
	return &rec, true
}

// List returns run summaries, newest first. The summary text is read from the
// response JSONB's prose_summary field.
func (s *RunStore) List() []RunSummary {
	rows, err := s.db.Query(`
		SELECT run_id, result_id, terminal_state, match, created_at,
		       COALESCE(response->>'correlation_id', '')
		FROM mitigation_check_run
		ORDER BY created_at DESC`)
	if err != nil {
		log.Printf("ledger: list failed: %v", err)
		return nil
	}
	defer rows.Close()

	out := []RunSummary{}
	for rows.Next() {
		var s RunSummary
		if err := rows.Scan(&s.RunID, &s.ResultID, &s.TerminalState, &s.Match,
			&s.CreatedAt, &s.CorrelationID); err != nil {
			continue
		}
		out = append(out, s)
	}
	return out
}
