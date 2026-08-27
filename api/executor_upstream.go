package main

// executor_upstream.go is a SEPARATE executor selected by the env condition
// variable MC_INPUT_UPSTREAM (truthy). It serves the same POST endpoint but takes
// the new input contract: instead of inline artifacts, the request carries
// upstream_inputs whose result_refs point at Databricks rows. Entries are selected
// by capability:
//   - "defense-generation": the mitigation rule is read from result_json
//     (primary_candidate.artifact_content);
//   - "check-generation": the test is derived from result_json.run_result via the
//     standalone stimulus converter (parseStimulus -> TestBasisFromStimulus).
//
// An inline test_basis in the request wins over the check-generation entry. The
// resolved rule/test are fed to the shared executor via the inline candidate /
// test_basis slots, so bring-up / WAF / verdict logic is reused unchanged.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	capDefenseGeneration = "defense-generation"
	capCheckGeneration   = "check-generation"
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

// executeScenarioUpstream resolves the rule (and, when needed, the test) from
// Databricks and delegates the run to the shared executor. Any resolution failure
// is a could-not-test (never a fabricated verdict).
func executeScenarioUpstream(ctx context.Context, req SubmitMitigationCheckRequest, runID, resultID string) RunOutcome {
	base := RunOutcome{RunID: runID, ResultID: resultID}

	entries, err := parseUpstreamInputs(req.UpstreamInputs)
	if err != nil {
		return couldNotTest(base, "upstream_inputs: "+err.Error())
	}
	if dbxReader == nil {
		return couldNotTest(base, "Databricks reader not configured (DATABRICKS_DSN unset)")
	}

	// Rule comes from the defense-generation entry.
	ruleEntry := selectByCapability(entries, capDefenseGeneration)
	if ruleEntry == nil {
		return couldNotTest(base, "no defense-generation entry in upstream_inputs (need the rule)")
	}
	pc, err := dbxReader.ReadCandidate(ctx, ruleEntry.ResultRef)
	if err != nil {
		return couldNotTest(base, "could not read rule from Databricks "+ruleEntry.ResultRef.qualified()+
			" where result_id="+ruleEntry.ResultRef.Key+": "+err.Error())
	}
	rule := strings.TrimSpace(pc.ArtifactContent)
	cand := CandidateSpec{
		Kind:   candidateKind(pc, rule),
		Engine: candidateEngine(pc, rule),
		Rule:   rule,
		Action: deriveRuleAction(rule),
	}
	if b, e := json.Marshal(cand); e == nil {
		req.Candidate = b
	}
	log.Printf("upstream: derived rule (kind=%s engine=%s action=%s candidate_id=%s): %s",
		cand.Kind, cand.Engine, cand.Action, pc.CandidateID, cand.Rule)
	// A firewall candidate runs on the separate firewall evaluator, not the WAF path.
	if cand.Kind == "firewall-rule" && req.ExecutionMode != execFirewall {
		req.ExecutionMode = execFirewall
	}
	steps := []string{
		"read " + cand.Kind + " from Databricks " + ruleEntry.ResultRef.qualified() +
			" where result_id=" + ruleEntry.ResultRef.Key,
	}

	// Test: an inline test_basis wins; otherwise derive it from the check-generation
	// entry's run_result via the standalone stimulus converter.
	if len(req.TestBasis) == 0 {
		if checkEntry := selectByCapability(entries, capCheckGeneration); checkEntry != nil {
			runResult, err := dbxReader.ReadRunResult(ctx, checkEntry.ResultRef)
			if err != nil {
				return couldNotTest(base, "could not read run_result from Databricks "+checkEntry.ResultRef.qualified()+
					" where result_id="+checkEntry.ResultRef.Key+": "+err.Error())
			}
			stim, err := parseStimulus(runResult)
			if err != nil {
				return couldNotTest(base, "check-generation run_result: "+err.Error())
			}
			tb, err := TestBasisFromStimulus(stim)
			if err != nil {
				return couldNotTest(base, "convert stimulus to test_basis: "+err.Error())
			}
			if b, e := json.Marshal(tb); e == nil {
				req.TestBasis = b
				log.Printf("upstream: derived test_basis from check-generation: %s", string(b))
			}
			steps = append(steps, "derived test_basis from check-generation run_result "+
				checkEntry.ResultRef.qualified()+" where result_id="+checkEntry.ResultRef.Key)
		}
	}

	out := executeScenario(ctx, req, runID, resultID)
	out.Steps = append(steps, out.Steps...)
	return out
}

// candidateKind classifies the rule as "waf-rule" or "firewall-rule" from the
// upstream selected_control_class, falling back to the rule string's shape.
func candidateKind(pc PrimaryCandidate, rule string) string {
	switch strings.ToLower(strings.TrimSpace(pc.SelectedControlClass)) {
	case "firewall":
		return "firewall-rule"
	case "waf":
		return "waf-rule"
	}
	if strings.HasPrefix(strings.TrimSpace(rule), "SecRule") || strings.Contains(rule, "@rx") {
		return "waf-rule"
	}
	return "firewall-rule"
}

// candidateEngine derives the engine from artifact_type (e.g. "modsecurity-rule"
// -> "modsecurity", "iptables-rule" -> "iptables"), else infers from the rule.
func candidateEngine(pc PrimaryCandidate, rule string) string {
	if at := strings.ToLower(strings.TrimSpace(pc.ArtifactType)); at != "" {
		return strings.TrimSuffix(at, "-rule")
	}
	switch {
	case strings.HasPrefix(strings.TrimSpace(rule), "SecRule") || strings.Contains(rule, "@rx"):
		return "modsecurity"
	case strings.Contains(rule, "-j ") || strings.Contains(rule, "iptables"):
		return "iptables"
	}
	return ""
}

// reRuleAction matches a disruptive/allow action token as a whole word.
var reRuleAction = regexp.MustCompile(`\b(deny|drop|block|pass|allow|reject|accept)\b`)

// deriveRuleAction extracts the action from the rule string: the iptables target
// (-j DROP/REJECT/ACCEPT), else the SecRule action list (last quoted segment),
// else anywhere in the rule (firewall compact syntax).
func deriveRuleAction(rule string) string {
	low := strings.ToLower(rule)
	if i := strings.Index(low, "-j "); i >= 0 {
		if f := strings.Fields(low[i+3:]); len(f) > 0 {
			switch f[0] {
			case "drop", "reject", "accept":
				return f[0]
			}
		}
	}
	if seg, ok := lastQuoted(rule); ok {
		if m := reRuleAction.FindString(strings.ToLower(seg)); m != "" {
			return m
		}
	}
	if m := reRuleAction.FindString(low); m != "" {
		return m
	}
	return ""
}

// lastQuoted returns the content of the last double-quoted segment.
func lastQuoted(s string) (string, bool) {
	end := strings.LastIndex(s, `"`)
	if end <= 0 {
		return "", false
	}
	start := strings.LastIndex(s[:end], `"`)
	if start < 0 {
		return "", false
	}
	return s[start+1 : end], true
}

// parseUpstreamInputs decodes the upstream_inputs array.
func parseUpstreamInputs(raw json.RawMessage) ([]upstreamInput, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("no upstream_inputs provided")
	}
	var entries []upstreamInput
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("not a valid array: %w", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("array is empty")
	}
	return entries, nil
}

// selectByCapability returns the first entry with the given capability that has a
// usable result_ref key, or nil.
func selectByCapability(entries []upstreamInput, capability string) *upstreamInput {
	for i := range entries {
		if strings.EqualFold(strings.TrimSpace(entries[i].Capability), capability) &&
			strings.TrimSpace(entries[i].ResultRef.Key) != "" {
			return &entries[i]
		}
	}
	return nil
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

// ReadCandidate reads result_json for ref.Key from the referenced table and returns
// its primary_candidate (whose artifact_content is the mitigation rule).
func (r *DatabricksReader) ReadCandidate(ctx context.Context, ref upstreamRef) (PrimaryCandidate, error) {
	if r == nil || r.db == nil {
		return PrimaryCandidate{}, fmt.Errorf("reader not configured")
	}
	q := "SELECT result_json FROM " + ref.qualified() + " WHERE result_id = ? LIMIT 1"
	c, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	start := time.Now()

	var js string
	if err := r.db.QueryRowContext(c, q, ref.Key).Scan(&js); err != nil {
		log.Printf("databricks reader: READ FAILED (result_id=%s) after %s: %v",
			ref.Key, time.Since(start).Round(time.Millisecond), err)
		return PrimaryCandidate{}, err
	}

	var res struct {
		PrimaryCandidate PrimaryCandidate `json:"primary_candidate"`
	}
	if err := json.Unmarshal([]byte(js), &res); err != nil {
		return PrimaryCandidate{}, fmt.Errorf("result_json parse: %w", err)
	}
	if strings.TrimSpace(res.PrimaryCandidate.ArtifactContent) == "" {
		return PrimaryCandidate{}, fmt.Errorf("primary_candidate.artifact_content is empty")
	}
	log.Printf("databricks reader: READ OK (result_id=%s) in %s",
		ref.Key, time.Since(start).Round(time.Millisecond))
	return res.PrimaryCandidate, nil
}

// ReadRunResult reads result_json for ref.Key from the referenced table and returns
// its run_result object — the standalone stimulus converter's input.
func (r *DatabricksReader) ReadRunResult(ctx context.Context, ref upstreamRef) (json.RawMessage, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("reader not configured")
	}
	q := "SELECT result_json FROM " + ref.qualified() + " WHERE result_id = ? LIMIT 1"
	c, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	start := time.Now()

	var js string
	if err := r.db.QueryRowContext(c, q, ref.Key).Scan(&js); err != nil {
		log.Printf("databricks reader: READ FAILED (result_id=%s) after %s: %v",
			ref.Key, time.Since(start).Round(time.Millisecond), err)
		return nil, err
	}
	rr, err := extractRunResult([]byte(js))
	if err != nil {
		return nil, err
	}
	log.Printf("databricks reader: READ OK run_result (result_id=%s) in %s",
		ref.Key, time.Since(start).Round(time.Millisecond))
	return rr, nil
}

// extractRunResult pulls the run_result object out of a result_json document.
func extractRunResult(js []byte) (json.RawMessage, error) {
	var res struct {
		RunResult json.RawMessage `json:"run_result"`
	}
	if err := json.Unmarshal(js, &res); err != nil {
		return nil, fmt.Errorf("result_json parse: %w", err)
	}
	if len(res.RunResult) == 0 || string(bytes.TrimSpace(res.RunResult)) == "null" {
		return nil, fmt.Errorf("result_json.run_result is missing")
	}
	return res.RunResult, nil
}

func (r *DatabricksReader) Close() {
	if r != nil && r.db != nil {
		_ = r.db.Close()
	}
}
