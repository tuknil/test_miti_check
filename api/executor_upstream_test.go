package main

import (
	"encoding/json"
	"testing"
)

// Two upstream_inputs entries: defense-generation (rule) + check-generation (test).
const twoEntryUpstream = `[
  {
    "capability": "defense-generation",
    "contract_id": "defense-generation@1.0",
    "result_id": "defense-generation-result:c3b02e61c65fb24b3fa16aaf",
    "result_ref": {
      "system": "databricks", "catalog": "36889_janus_dev", "schema": "defense_generation",
      "table": "defense_generation_results", "key": "defense-generation-result:c3b02e61c65fb24b3fa16aaf"
    }
  },
  {
    "capability": "check-generation",
    "contract_id": "check-generation@1.0",
    "result_id": "check-generation-run-result:sha256:6f02",
    "result_ref": {
      "system": "databricks", "catalog": "36889_janus_dev", "schema": "check_generation",
      "table": "check_generation_results", "key": "check-generation-run-result:sha256:6f02"
    }
  }
]`

func TestSelectByCapability(t *testing.T) {
	entries, err := parseUpstreamInputs([]byte(twoEntryUpstream))
	if err != nil {
		t.Fatalf("parseUpstreamInputs: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}

	rule := selectByCapability(entries, capDefenseGeneration)
	if rule == nil || rule.ResultRef.Table != "defense_generation_results" ||
		rule.ResultRef.Key != "defense-generation-result:c3b02e61c65fb24b3fa16aaf" {
		t.Errorf("defense-generation selection wrong: %+v", rule)
	}
	check := selectByCapability(entries, capCheckGeneration)
	if check == nil || check.ResultRef.Table != "check_generation_results" {
		t.Errorf("check-generation selection wrong: %+v", check)
	}
	if got := selectByCapability(entries, "vuln-research"); got != nil {
		t.Errorf("absent capability should be nil, got %+v", got)
	}
}

func TestSelectByCapabilitySkipsEmptyKey(t *testing.T) {
	entries := []upstreamInput{
		{Capability: "defense-generation", ResultRef: upstreamRef{Key: ""}}, // no key -> skipped
		{Capability: "defense-generation", ResultRef: upstreamRef{Key: "k2", Table: "t"}},
	}
	got := selectByCapability(entries, capDefenseGeneration)
	if got == nil || got.ResultRef.Key != "k2" {
		t.Errorf("should skip empty-key entry, got %+v", got)
	}
}

func TestParseUpstreamInputsErrors(t *testing.T) {
	for _, in := range []string{"", "[]", "{}", "not json"} {
		if _, err := parseUpstreamInputs([]byte(in)); err == nil {
			t.Errorf("input %q: expected error", in)
		}
	}
}

// End-to-end (minus the DB read): a check-generation result_json.run_result flows
// through the standalone converter into the expected test_basis.
func TestCheckGenerationRunResultToTestBasis(t *testing.T) {
	resultJSON := `{
      "run_result": {
        "artifacts": [
          { "mitigation_check_signal": { "stimulus": {
            "artifact_type": "http-probe",
            "method": "POST",
            "path_key": "mcp_stdio_env_config",
            "headers": { "Content-Type": "application/json" },
            "json_body": { "env": { "node_options": "--require C:\\temp\\flowise-loader.js" } },
            "vulnerable_marker": "node_options"
          } } }
        ]
      }
    }`
	rr, err := extractRunResult([]byte(resultJSON))
	if err != nil {
		t.Fatalf("extractRunResult: %v", err)
	}
	stim, err := parseStimulus(rr)
	if err != nil {
		t.Fatalf("parseStimulus: %v", err)
	}
	tb, err := TestBasisFromStimulus(stim)
	if err != nil {
		t.Fatalf("TestBasisFromStimulus: %v", err)
	}
	if tb.Request.Method != "POST" || tb.Request.Path != "mcp_stdio_env_config" {
		t.Errorf("request wrong: %+v", tb.Request)
	}
	wantBody := `{"env":{"node_options":"--require C:\\temp\\flowise-loader.js"}}`
	if tb.Request.Body != wantBody {
		t.Errorf("body\n got %q\nwant %q", tb.Request.Body, wantBody)
	}
	if tb.Expected.Classification != "true-positive" || tb.Expected.Blocked == nil || !*tb.Expected.Blocked {
		t.Errorf("expected wrong: %+v", tb.Expected)
	}
}

func TestExtractRunResultMissing(t *testing.T) {
	for _, js := range []string{`{}`, `{"run_result":null}`, `not json`} {
		if _, err := extractRunResult([]byte(js)); err == nil {
			t.Errorf("input %q: expected error", js)
		}
	}
	// Ensure a valid run_result marshals back to valid JSON.
	rr, err := extractRunResult([]byte(`{"run_result":{"a":1}}`))
	if err != nil || !json.Valid(rr) {
		t.Errorf("valid run_result failed: %v %s", err, rr)
	}
}
