package main

import "testing"

// ControlClass classification from the various metadata fields.
func TestControlClassClassification(t *testing.T) {
	cases := []struct {
		name string
		cand Candidate
		want string
	}{
		{"selected_control_class edr", Candidate{SelectedControlClass: "edr", ArtifactContent: "x"}, classEDR},
		{"selected_control_class waf", Candidate{SelectedControlClass: "waf", ArtifactContent: "x"}, classWAF},
		{"kind endpoint-detection-rule", Candidate{CandidateKind: "endpoint-detection-rule", ArtifactContent: "x"}, classEDR},
		{"kind fast-waf-rule", Candidate{CandidateKind: "fast-waf-rule", ArtifactContent: "x"}, classWAF},
		{"artifact wazuh-rule", Candidate{ArtifactType: "wazuh-rule", ArtifactContent: "x"}, classEDR},
		{"artifact modsecurity-rule", Candidate{ArtifactType: "modsecurity-rule", ArtifactContent: "x"}, classWAF},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := c.cand.ControlClass()
			if err != nil || got != c.want {
				t.Fatalf("got %q err %v, want %q", got, err, c.want)
			}
		})
	}
	if _, err := (&Candidate{ArtifactContent: "x"}).ControlClass(); err == nil {
		t.Fatal("expected error when class is undeterminable")
	}
}

// EDR candidate dispatch reuses the Wazuh evaluator (result document form).
func TestEvaluateCandidateEDR(t *testing.T) {
	doc := `{
      "primary_candidate": {
        "candidate_id": "candidate:edr:1",
        "selected_control_class": "edr",
        "candidate_kind": "endpoint-detection-rule",
        "artifact_type": "wazuh-rule",
        "artifact_content": "<group name=\"janus,edr-proof,\">\n<rule id=\"103047\" level=\"12\">\n<field name=\"event.type\" type=\"pcre2\">^Process Creation$</field>\n<field name=\"src.process.cmdline\" type=\"pcre2\">(?i)-EncodedCommand</field>\n</rule>\n</group>",
        "expected_block_behavior": "Matching process activity triggers termination"
      }
    }`
	cand, err := LoadCandidate([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	event := `{"event":{"type":"Process Creation"},"src":{"process":{"cmdline":"powershell.exe -EncodedCommand SQBFAFgA"}}}`
	rep, err := EvaluateCandidate(cand, []byte(event))
	if err != nil {
		t.Fatal(err)
	}
	if rep.ControlClass != classEDR {
		t.Fatalf("control class = %q, want edr", rep.ControlClass)
	}
	if !rep.Matched {
		t.Fatalf("expected EDR candidate to match: %+v", rep.Results)
	}
}

// WAF candidate dispatch reuses the ModSecurity evaluator.
func TestEvaluateCandidateWAF(t *testing.T) {
	doc := `{
      "primary_candidate": {
        "candidate_id": "candidate-1",
        "selected_control_class": "waf",
        "candidate_kind": "fast-waf-rule",
        "artifact_type": "modsecurity-rule",
        "artifact_content": "SecRule REQUEST_BODY \"@rx attack\" \"id:1001,phase:2,deny,status:403\"",
        "expected_block_behavior": "blocked"
      }
    }`
	cand, err := LoadCandidate([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	// Matching request: body contains "attack".
	hit := `{"method":"POST","path":"/login","headers":{"Content-Type":"text/plain"},"body":"this is an attack payload"}`
	rep, err := EvaluateCandidate(cand, []byte(hit))
	if err != nil {
		t.Fatal(err)
	}
	if rep.ControlClass != classWAF {
		t.Fatalf("control class = %q, want waf", rep.ControlClass)
	}
	if !rep.Matched {
		t.Fatalf("expected WAF candidate to match/block: %+v", rep.Results)
	}
	if rep.Results[0].RuleID != "1001" {
		t.Fatalf("rule id = %q, want 1001", rep.Results[0].RuleID)
	}

	// Benign request: no "attack" substring -> allowed.
	miss := `{"method":"POST","path":"/login","body":"normal user input"}`
	rep2, err := EvaluateCandidate(cand, []byte(miss))
	if err != nil {
		t.Fatal(err)
	}
	if rep2.Matched {
		t.Fatalf("expected benign WAF request to be allowed (no match)")
	}
}

// EvaluateWAF directly: ARGS target and URL-decoded matching.
func TestEvaluateWAFArgsAndURLDecode(t *testing.T) {
	rule := `SecRule ARGS:q "@rx select.+from" "id:2001,deny,status:403"`
	// URL-encoded SQLi in a query arg; the evaluator also checks a URL-decoded pass.
	req, err := LoadHTTPRequest([]byte(`{"method":"GET","path":"/search?q=select%20name%20from%20users"}`))
	if err != nil {
		t.Fatal(err)
	}
	res, err := EvaluateWAF(rule, req)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Matched {
		t.Fatalf("expected ARGS:q SQLi to match: %+v", res)
	}
}

func TestLoadCandidateBareObject(t *testing.T) {
	bare := `{"selected_control_class":"waf","artifact_type":"modsecurity-rule","artifact_content":"SecRule REQUEST_URI \"@rx /etc/passwd\" \"id:3001,deny\""}`
	cand, err := LoadCandidate([]byte(bare))
	if err != nil {
		t.Fatal(err)
	}
	req, _ := LoadHTTPRequest([]byte(`{"path":"/download?file=/etc/passwd"}`))
	rep, err := EvaluateCandidate(cand, mustJSON(t, req))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Matched {
		t.Fatalf("expected path traversal to match")
	}
}

func mustJSON(t *testing.T, req *HTTPRequest) []byte {
	t.Helper()
	return []byte(`{"path":"` + req.Path + `"}`)
}
