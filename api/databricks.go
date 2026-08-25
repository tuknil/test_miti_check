package main

// databricks.go is an OPTIONAL secondary sink: besides the Postgres ledger, each
// run's result is also written to a Databricks Delta table. It is best-effort —
// failures are logged and never affect the Postgres write or the API response.
// Disabled entirely when DATABRICKS_DSN is unset.
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

// Write inserts one row (run_id, result_id, result_json). A fresh random string
// is used for BOTH run_id and result_id (as requested); result_json is the run
// outcome. Best-effort: logs and returns on any error.
func (s *DatabricksSink) Write(ctx context.Context, outcome RunOutcome) {
	if s == nil {
		return
	}
	payload, err := json.Marshal(outcome)
	if err != nil {
		log.Printf("databricks: marshal failed: %v", err)
		return
	}
	id := newID()
	c, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	q := "INSERT INTO " + s.table + " (run_id, result_id, result_json) VALUES (?, ?, ?)"
	if _, err := s.db.ExecContext(c, q, id, id, string(payload)); err != nil {
		log.Printf("databricks: insert failed (id %s): %v", id, err)
		return
	}
	log.Printf("databricks: wrote row %s", id)
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
