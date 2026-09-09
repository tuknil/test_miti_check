package main

import (
	"encoding/json"
	"testing"
)

// TestAPIResultViewHidesEmbeddedFields verifies the canonical result keeps the
// embedded rule/test and diagnostics (for Databricks/result_ref consumers) while
// the API view strips them, leaving the envelope + verdict.
func TestAPIResultViewHidesEmbeddedFields(t *testing.T) {
	canonical := []byte(`{
		"capability":"mitigation-check","contract_id":"mitigation-check@1.0",
		"run_id":"mc-run-1","result_id":"r","terminal_state":"blocked","status":"completed",
		"match":true,"expected":{"blocked":true},"actual":{"blocked":true},"substrate":{"image":"x"},
		"candidate":{"rule":"SecRule ..."},"test_basis":{"kind":"http-probe"},
		"steps":["a","b"],"prose_summary":"...","limitations":["l"],
		"content_sha256":"sha256:x","size_bytes":10,"created_at":"2026-01-01T00:00:00Z"
	}`)

	var view map[string]json.RawMessage
	if err := json.Unmarshal(apiResultView(canonical), &view); err != nil {
		t.Fatalf("api view not valid JSON: %v", err)
	}
	for _, k := range apiResultKeysToHide {
		if _, ok := view[k]; ok {
			t.Errorf("API view must not contain %q", k)
		}
	}
	for _, k := range []string{"capability", "run_id", "result_id", "terminal_state", "status", "match", "expected", "actual", "substrate"} {
		if _, ok := view[k]; !ok {
			t.Errorf("API view must keep %q (envelope/verdict)", k)
		}
	}

	// The canonical payload itself is untouched — still carries the hidden fields.
	var canon map[string]json.RawMessage
	_ = json.Unmarshal(canonical, &canon)
	for _, k := range []string{"candidate", "test_basis", "steps"} {
		if _, ok := canon[k]; !ok {
			t.Errorf("canonical result must keep %q for result_ref consumers", k)
		}
	}

	// Malformed input is returned unchanged (never drops the response).
	bad := []byte(`not json`)
	if string(apiResultView(bad)) != string(bad) {
		t.Errorf("malformed payload should pass through unchanged")
	}
}
