package main

import (
	"encoding/json"
	"os"
	"testing"
)

func TestParseStimulusFromArtifacts(t *testing.T) {
	data, err := os.ReadFile("testdata/stimulus-artifacts.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	s, err := parseStimulus(data)
	if err != nil {
		t.Fatalf("parseStimulus: %v", err)
	}
	// The FIRST artifact's stimulus must be used, not the decoy second one.
	if s.PathKey != "mcp_stdio_env_config" {
		t.Errorf("path_key = %q, want mcp_stdio_env_config (took wrong artifact?)", s.PathKey)
	}
	if s.VulnerableMarker != "node_options" {
		t.Errorf("vulnerable_marker = %q, want node_options", s.VulnerableMarker)
	}

	tb, err := TestBasisFromStimulus(s)
	if err != nil {
		t.Fatalf("TestBasisFromStimulus: %v", err)
	}
	wantBody := `{"env":{"node_options":"--require C:\\temp\\flowise-loader.js"}}`
	if tb.Request.Body != wantBody {
		t.Errorf("body\n got %q\nwant %q", tb.Request.Body, wantBody)
	}
}

// The exact example stimulus from the input probe.
const exampleStimulus = `{
  "stimulus": {
    "artifact_type": "http-probe",
    "method": "POST",
    "path_key": "mcp_stdio_env_config",
    "query": {},
    "headers": { "Content-Type": "application/json" },
    "json_body": { "env": { "node_options": "--require C:\\temp\\flowise-loader.js" } },
    "body_text": null,
    "content_type": null,
    "timeout_seconds": 5,
    "vulnerable_predicate": "body-contains",
    "vulnerable_marker": "node_options",
    "baseline_predicate": "body-not-contains"
  }
}`

func TestTestBasisFromStimulus(t *testing.T) {
	s, err := parseStimulus([]byte(exampleStimulus))
	if err != nil {
		t.Fatalf("parseStimulus: %v", err)
	}
	tb, err := TestBasisFromStimulus(s)
	if err != nil {
		t.Fatalf("TestBasisFromStimulus: %v", err)
	}

	if tb.Kind != "http-probe" {
		t.Errorf("kind = %q, want http-probe", tb.Kind)
	}
	if tb.ProofBasis != "verified-vuln-artifact" {
		t.Errorf("proof_basis = %q", tb.ProofBasis)
	}
	if tb.Request.Method != "POST" {
		t.Errorf("method = %q, want POST", tb.Request.Method)
	}
	if tb.Request.Path != "mcp_stdio_env_config" {
		t.Errorf("path = %q", tb.Request.Path)
	}
	if tb.Request.Headers["Content-Type"] != "application/json" {
		t.Errorf("Content-Type header = %q", tb.Request.Headers["Content-Type"])
	}
	wantBody := `{"env":{"node_options":"--require C:\\temp\\flowise-loader.js"}}`
	if tb.Request.Body != wantBody {
		t.Errorf("body\n got %q\nwant %q", tb.Request.Body, wantBody)
	}
	if tb.Expected.Classification != "true-positive" {
		t.Errorf("classification = %q", tb.Expected.Classification)
	}
	if tb.Expected.Blocked == nil || !*tb.Expected.Blocked {
		t.Errorf("expected.blocked = %v, want true", tb.Expected.Blocked)
	}
	if tb.Expected.StatusCode != 403 {
		t.Errorf("status_code = %d, want 403", tb.Expected.StatusCode)
	}

	// The vulnerable marker must survive into the request body so a candidate can
	// match it.
	if !json.Valid([]byte(tb.Request.Body)) {
		t.Errorf("request body is not valid JSON: %s", tb.Request.Body)
	}
}

func TestStimulusBodyText(t *testing.T) {
	txt := "raw=payload"
	s := Stimulus{Method: "get", BodyText: &txt}
	tb, err := TestBasisFromStimulus(s)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if tb.Request.Method != "GET" {
		t.Errorf("method not upper-cased: %q", tb.Request.Method)
	}
	if tb.Request.Body != txt {
		t.Errorf("body = %q, want %q", tb.Request.Body, txt)
	}
}

func TestStimulusQueryAppended(t *testing.T) {
	s := Stimulus{Method: "GET", PathKey: "/probe", Query: map[string]string{"a": "1", "b": "2"}}
	tb, _ := TestBasisFromStimulus(s)
	// url.Values.Encode sorts keys.
	if tb.Request.Path != "/probe?a=1&b=2" {
		t.Errorf("path = %q, want /probe?a=1&b=2", tb.Request.Path)
	}
}

func TestStimulusContentTypeAdded(t *testing.T) {
	ct := "application/json"
	s := Stimulus{Method: "POST", ContentType: &ct}
	tb, _ := TestBasisFromStimulus(s)
	if tb.Request.Headers["Content-Type"] != ct {
		t.Errorf("Content-Type not added: %v", tb.Request.Headers)
	}
}
