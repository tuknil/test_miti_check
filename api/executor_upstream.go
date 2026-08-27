package main

// executor_upstream.go is a SEPARATE executor selected by the env condition
// variable MC_INPUT_UPSTREAM (truthy). It serves the same POST endpoint but takes
// the new input contract: instead of an inline candidate rule, the request carries
// upstream_inputs whose result_ref points at a Databricks row. The mitigation rule
// is read from that row's result_json (primary_candidate.artifact_content). The
// test still comes explicitly in the request (test_basis), as before.
//
// Once the rule is resolved it is fed to the shared executor via the inline
// candidate slot, so bring-up / WAF / verdict logic is reused unchanged.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// upstreamRef is the result_ref inside an upstream_inputs entry.
type upstreamRef struct {
	System  string `json:"system"`
	Catalog string `json:"catalog"`
	Schema  string `json:"schema"`
	Table   string `json:"table"`
	Key     string `json:"key"`
}

// qualified is the backtick-quoted `catalog`.`schema`.`table` for SQL.
func (r upstreamRef) qualified() string {
	q := backtick(r.Table)
	if r.Schema != "" {
		q = backtick(r.Schema) + "." + q
	}
	if r.Catalog != "" {
		q = backtick(r.Catalog) + "." + q
	}
	return q
}

type upstreamInput struct {
	Capability string      `json:"capability"`
	ContractID string      `json:"contract_id"`
	ResultID   string      `json:"result_id"`
	ResultRef  upstreamRef `json:"result_ref"`
}

// executeScenarioUpstream resolves the rule from Databricks and delegates the run
// to the shared executor. Any resolution failure is a could-not-test (never a
// fabricated verdict).
func executeScenarioUpstream(ctx context.Context, req SubmitMitigationCheckRequest, runID, resultID string) RunOutcome {
	base := RunOutcome{RunID: runID, ResultID: resultID}

	ref, err := ruleRefFromUpstream(req.UpstreamInputs)
	if err != nil {
		return couldNotTest(base, "upstream_inputs: "+err.Error())
	}
	if dbxReader == nil {
		return couldNotTest(base, "Databricks reader not configured (DATABRICKS_DSN unset)")
	}
	rule, err := dbxReader.ReadRule(ctx, ref)
	if err != nil {
		return couldNotTest(base, "could not read rule from Databricks "+ref.qualified()+
			" where result_id="+ref.Key+": "+err.Error())
	}

	// Feed the resolved rule to the shared executor through the inline candidate slot.
	cand := CandidateSpec{Kind: "waf-rule", Engine: "modsecurity", Rule: rule, Action: "deny"}
	if b, e := json.Marshal(cand); e == nil {
		req.Candidate = b
	}
	out := executeScenario(ctx, req, runID, resultID)
	out.Steps = append([]string{
		"read rule from Databricks " + ref.qualified() + " where result_id=" + ref.Key,
	}, out.Steps...)
	return out
}

// ruleRefFromUpstream returns the result_ref of the rule entry. Only the rule entry
// is used for now: the first Databricks-backed entry (else the first entry).
func ruleRefFromUpstream(raw json.RawMessage) (upstreamRef, error) {
	if len(raw) == 0 {
		return upstreamRef{}, fmt.Errorf("no upstream_inputs provided")
	}
	var entries []upstreamInput
	if err := json.Unmarshal(raw, &entries); err != nil {
		return upstreamRef{}, fmt.Errorf("not a valid array: %w", err)
	}
	if len(entries) == 0 {
		return upstreamRef{}, fmt.Errorf("array is empty")
	}
	for _, e := range entries {
		if strings.EqualFold(e.ResultRef.System, "databricks") && e.ResultRef.Key != "" {
			return e.ResultRef, nil
		}
	}
	if entries[0].ResultRef.Key == "" {
		return upstreamRef{}, fmt.Errorf("first entry has no result_ref.key")
	}
	return entries[0].ResultRef, nil
}

// DatabricksReader reads upstream result_json rows from Databricks.
type DatabricksReader struct {
	db *sql.DB
}

// NewDatabricksReader returns nil when DATABRICKS_DSN is unset.
func NewDatabricksReader() *DatabricksReader {
	dsn := os.Getenv("DATABRICKS_DSN")
	if strings.TrimSpace(dsn) == "" {
		log.Printf("databricks reader: disabled (DATABRICKS_DSN unset)")
		return nil
	}
	db, err := sql.Open("databricks", normalizeDatabricksDSN(dsn))
	if err != nil {
		log.Printf("databricks reader: disabled (open failed: %v)", err)
		return nil
	}
	db.SetMaxOpenConns(4)
	log.Printf("databricks reader: enabled")
	return &DatabricksReader{db: db}
}

// ReadRule reads result_json for ref.Key from the referenced table and returns
// primary_candidate.artifact_content (the mitigation rule).
func (r *DatabricksReader) ReadRule(ctx context.Context, ref upstreamRef) (string, error) {
	if r == nil || r.db == nil {
		return "", fmt.Errorf("reader not configured")
	}
	q := "SELECT result_json FROM " + ref.qualified() + " WHERE result_id = ? LIMIT 1"
	c, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	start := time.Now()

	var js string
	if err := r.db.QueryRowContext(c, q, ref.Key).Scan(&js); err != nil {
		log.Printf("databricks reader: READ FAILED (result_id=%s) after %s: %v",
			ref.Key, time.Since(start).Round(time.Millisecond), err)
		return "", err
	}

	var res struct {
		PrimaryCandidate PrimaryCandidate `json:"primary_candidate"`
	}
	if err := json.Unmarshal([]byte(js), &res); err != nil {
		return "", fmt.Errorf("result_json parse: %w", err)
	}
	rule := strings.TrimSpace(res.PrimaryCandidate.ArtifactContent)
	if rule == "" {
		return "", fmt.Errorf("primary_candidate.artifact_content is empty")
	}
	log.Printf("databricks reader: READ OK (result_id=%s) in %s",
		ref.Key, time.Since(start).Round(time.Millisecond))
	return rule, nil
}

func (r *DatabricksReader) Close() {
	if r != nil && r.db != nil {
		_ = r.db.Close()
	}
}
