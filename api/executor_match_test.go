package main

import (
	"context"
	"encoding/json"
	"testing"
)

// TestMatchRequiresActualBlock verifies that match is true only when the request
// was actually blocked; a not-blocked result is never a match, regardless of the
// expected outcome.
func TestMatchRequiresActualBlock(t *testing.T) {
	run := func(pattern, body string, expectBlocked bool) RunOutcome {
		cand, _ := json.Marshal(CandidateSpec{
			Kind: "waf-rule", Engine: "modsecurity", Action: "deny",
			Rule: `SecRule ARGS|REQUEST_BODY "@rx ` + pattern + `" "id:1,phase:2,deny,status:403"`,
		})
		b := expectBlocked
		tb, _ := json.Marshal(TestBasisSpec{
			Kind: "http-probe", ProofBasis: "verified-vuln-artifact",
			Request:  TestRequest{Method: "POST", Path: "/x", Body: body},
			Expected: TestExpected{Blocked: &b, StatusCode: 403},
		})
		req := SubmitMitigationCheckRequest{
			ContractID: "mitigation-check@1.0", ExecutionMode: "inmemory",
			Candidate: cand, TestBasis: tb,
		}
		return executeScenario(context.Background(), req, "run", "res")
	}

	cases := []struct {
		name, pattern, body string
		expectBlocked       bool
		wantBlocked         bool
		wantMatch           bool
	}{
		{"TP: blocked, expected blocked", "node_options", "node_options=1", true, true, true},
		{"FP: blocked, expected not-blocked", "node_options", "node_options=1", false, true, false},
		{"TN: not-blocked, expected not-blocked", "WILL_NOT_MATCH", "benign=1", false, false, false}, // key: never a match
		{"FN: not-blocked, expected blocked", "WILL_NOT_MATCH", "benign=1", true, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := run(c.pattern, c.body, c.expectBlocked)
			if out.TerminalState == stateCouldNotTest || out.TerminalState == stateMalfunction {
				t.Fatalf("unexpected %s: %s", out.TerminalState, out.Actual.Detail)
			}
			if out.Actual.Blocked != c.wantBlocked {
				t.Fatalf("actual.blocked = %v, want %v", out.Actual.Blocked, c.wantBlocked)
			}
			if out.Match != c.wantMatch {
				t.Errorf("match = %v, want %v (a not-blocked result must never match)", out.Match, c.wantMatch)
			}
		})
	}
}
