package main

// store.go is the run ledger (LLD §11.1: mitigation_check_run / _result), backed
// by an embedded PostgreSQL instance managed in-process. The Postgres data
// cluster lives under MC_DATA_DIR, so it is durable across docker stop / rm when
// that path is a mounted volume.
//
// The immutable request and the executed response are stored as JSONB columns.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
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
	CreatedAt     time.Time `json:"created_at"`
	Summary       string    `json:"summary"`
}

const (
	pgPort     = 5433
	pgUser     = "mc"
	pgPassword = "mc"
	pgDatabase = "mitigation"
)

type RunStore struct {
	pg *embeddedpostgres.EmbeddedPostgres
	db *sql.DB
}

// NewRunStore boots an embedded Postgres whose cluster/binaries live under base,
// connects, and ensures the schema exists. base should be a mounted volume for
// durability. Binaries and runtime are cached under base too, so a recreated
// container does not re-download them.
func NewRunStore(base string) (*RunStore, error) {
	if err := os.MkdirAll(base, 0o755); err != nil {
		return nil, fmt.Errorf("create ledger dir: %w", err)
	}

	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Username(pgUser).
		Password(pgPassword).
		Database(pgDatabase).
		Version(embeddedpostgres.V16).
		Port(pgPort).
		DataPath(filepath.Join(base, "pg-data")).
		RuntimePath(filepath.Join(base, "pg-runtime")).
		BinariesPath(filepath.Join(base, "pg-bin")).
		Logger(os.Stderr).
		StartTimeout(120 * time.Second))

	log.Printf("ledger: starting embedded postgres (data under %s)…", base)
	if err := pg.Start(); err != nil {
		return nil, fmt.Errorf("start embedded postgres: %w", err)
	}

	dsn := fmt.Sprintf("postgres://%s:%s@localhost:%d/%s?sslmode=disable",
		pgUser, pgPassword, pgPort, pgDatabase)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		_ = pg.Stop()
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(8)

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
		_ = pg.Stop()
		return nil, fmt.Errorf("create schema: %w", err)
	}

	s := &RunStore{pg: pg, db: db}
	log.Printf("ledger: embedded postgres ready (%d run(s))", s.count())
	return s, nil
}

func (s *RunStore) count() int {
	var n int
	_ = s.db.QueryRow(`SELECT count(*) FROM mitigation_check_run`).Scan(&n)
	return n
}

// Close stops accepting queries and shuts the embedded Postgres down cleanly.
func (s *RunStore) Close() {
	if s.db != nil {
		_ = s.db.Close()
	}
	if s.pg != nil {
		_ = s.pg.Stop()
	}
}

// Add durably records a run. request is stored as-is (JSONB); response is
// marshaled to JSONB.
func (s *RunStore) Add(r *RunRecord) error {
	resp, err := json.Marshal(r.Response)
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
		       COALESCE(response->>'prose_summary', '')
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
			&s.CreatedAt, &s.Summary); err != nil {
			continue
		}
		out = append(out, s)
	}
	return out
}
