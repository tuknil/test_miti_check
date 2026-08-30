package main

// databricks.go is an OPTIONAL secondary sink: besides the Postgres ledger, each
// run's result is also written to a Databricks Delta table. The write is
// synchronous so the result envelope's status can reflect it: a failure never
// changes terminal_state (still the test result) or fails the run, but degrades
// status to "storage-failed". Disabled entirely when DATABRICKS_DSN is unset.
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
	"encoding/json"
	"log"
	"os"
	"strings"
	"time"

	_ "github.com/databricks/databricks-sql-go"
)

type DatabricksSink struct {
	db    *sql.DB
	table string // fully-qualified `catalog`.`schema`.`table`
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

	qualified := backtick(firstNonEmpty(os.Getenv("DATABRICKS_TABLE"), "mitigation_check"))
	if s := os.Getenv("DATABRICKS_SCHEMA"); s != "" {
		qualified = backtick(s) + "." + qualified
	}
	if c := os.Getenv("DATABRICKS_CATALOG"); c != "" {
		qualified = backtick(c) + "." + qualified
	}
	log.Printf("databricks: enabled -> %s", qualified)
	return &DatabricksSink{db: db, table: qualified}
}

// Write inserts one row (run_id, result_id, result_json), keyed by the run's real
// run_id/result_id (the same values the result envelope reports) so another
// service can query it. Returns the write error so the caller can reflect a
// failure in the result envelope's status; the row itself is never a hard failure.
func (s *DatabricksSink) Write(ctx context.Context, outcome RunOutcome) error {
	if s == nil {
		return nil
	}
	payload, err := json.Marshal(outcome)
	if err != nil {
		log.Printf("databricks: WRITE FAILED (run %s): marshal: %v", outcome.RunID, err)
		return err
	}
	// result_id is written as-is (the full "mitigation-check-result:<hex>" value) so
	// consumers query WHERE result_id = <value>; result_ref.key reports the same value.
	runID := outcome.RunID
	resultID := outcome.ResultID
	log.Printf("databricks: writing row (run_id=%s, result_id=%s, %s) -> %s",
		runID, resultID, outcome.TerminalState, s.table)

	c, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	start := time.Now()
	q := "INSERT INTO " + s.table + " (run_id, result_id, result_json) VALUES (?, ?, ?)"
	if _, err := s.db.ExecContext(c, q, runID, resultID, string(payload)); err != nil {
		log.Printf("databricks: WRITE FAILED (run_id=%s) after %s: %v",
			runID, time.Since(start).Round(time.Millisecond), err)
		return err
	}
	log.Printf("databricks: WRITE OK (run_id=%s, result_id=%s) in %s",
		runID, resultID, time.Since(start).Round(time.Millisecond))
	return nil
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
