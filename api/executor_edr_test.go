package main

import (
	"context"
	"encoding/json"
	"testing"
)

const edrWazuhRule = `<group name="janus,edr-proof,">
  <rule id="103047" level="12">
    <field name="event.type" type="pcre2">^Process Creation$</field>
    <field name="src.process.cmdline" type="pcre2">(?i)-EncodedCommand</field>
    <description>EDR proof</description>
  </rule>
</group>`

func edrRequest(t *testing.T, telemetry string, blocked bool) SubmitMitigationCheckRequest {
	t.Helper()
	cand, _ := json.Marshal(CandidateSpec{Kind: "endpoint-detection-rule", Engine: "wazuh", RuleID: "103047", Rule: edrWazuhRule, Action: "kill-process"})
	tb, _ := json.Marshal(TestBasisSpec{Kind: "edr-telemetry", ProofBasis: "mitigation-discriminator",
		Telemetry: json.RawMessage(telemetry), Expected: TestExpected{Blocked: &blocked}})
	return SubmitMitigationCheckRequest{ContractID: contractID, RequestID: "edr-1", CorrelationID: "correlation-1",
		Candidate: cand, TestBasis: tb}
}

// EDR candidate + matching telemetry -> detected/blocked, match agrees with expected.
func TestEDRExecutionMatchBlocks(t *testing.T) {
	telemetry := `{"event":{"type":"Process Creation"},"src":{"process":{"cmdline":"powershell.exe -EncodedCommand SQBF"}}}`
	req := edrRequest(t, telemetry, true)
	out := executeScenario(context.Background(), req, "run-1", "result-1")
	if out.TerminalState != stateBlocked {
		t.Fatalf("terminal_state=%s want %s (detail=%s)", out.TerminalState, stateBlocked, out.Actual.Detail)
	}
	if !out.Actual.Blocked || out.Actual.MatchedRuleID != "103047" {
		t.Fatalf("actual=%+v", out.Actual)
	}
	if !out.Match {
		t.Fatalf("expected match=true when detected and expected blocked")
	}
}

// EDR dispatch by candidate kind even when execution_mode is unset (defaults).
func TestEDRDispatchByCandidateKind(t *testing.T) {
	telemetry := `{"event":{"type":"Process Creation"},"src":{"process":{"cmdline":"powershell.exe -EncodedCommand X"}}}`
	req := edrRequest(t, telemetry, true)
	req.ExecutionMode = "" // no explicit mode; isEDRCandidate must still route to EDR
	out := executeScenario(context.Background(), req, "run-2", "result-2")
	if out.Substrate.Image != "endpoint telemetry (in-memory Wazuh)" {
		t.Fatalf("did not route to EDR evaluator: image=%q", out.Substrate.Image)
	}
	if out.TerminalState != stateBlocked {
		t.Fatalf("terminal_state=%s want blocked", out.TerminalState)
	}
}

// EDR candidate + benign telemetry -> not detected; a not-blocked result never matches.
func TestEDRExecutionNoMatchAllows(t *testing.T) {
	telemetry := `{"event":{"type":"Process Creation"},"src":{"process":{"cmdline":"powershell.exe -File backup.ps1"}}}`
	req := edrRequest(t, telemetry, true)
	out := executeScenario(context.Background(), req, "run-3", "result-3")
	if out.TerminalState != stateNotBlocked {
		t.Fatalf("terminal_state=%s want %s", out.TerminalState, stateNotBlocked)
	}
	if out.Actual.Blocked || out.Match {
		t.Fatalf("benign telemetry must be not-blocked and not a match: %+v", out.Actual)
	}
}

// Missing telemetry -> could-not-test (never a fabricated verdict).
func TestEDRMissingTelemetryCouldNotTest(t *testing.T) {
	cand, _ := json.Marshal(CandidateSpec{Engine: "wazuh", Rule: edrWazuhRule})
	blocked := true
	tb, _ := json.Marshal(TestBasisSpec{Kind: "edr-telemetry", Expected: TestExpected{Blocked: &blocked}})
	req := SubmitMitigationCheckRequest{ContractID: contractID, RequestID: "edr-x", Candidate: cand, TestBasis: tb}
	out := executeScenario(context.Background(), req, "run-4", "result-4")
	if out.TerminalState != stateCouldNotTest {
		t.Fatalf("terminal_state=%s want %s", out.TerminalState, stateCouldNotTest)
	}
}

// The locator accepts a wazuh-rule defense candidate and yields a wazuh engine.
func TestVerifyDefenseRowAcceptsWazuh(t *testing.T) {
	if candidateKind(PrimaryCandidate{SelectedControlClass: "edr", ArtifactType: "wazuh-rule"}, edrWazuhRule) != "endpoint-detection-rule" {
		t.Fatal("candidateKind should classify a wazuh candidate as endpoint-detection-rule")
	}
	if candidateEngine(PrimaryCandidate{ArtifactType: "wazuh-rule"}, edrWazuhRule) != "wazuh" {
		t.Fatal("candidateEngine should map wazuh-rule to wazuh")
	}
}

// selectEDRTelemetryTestBasis extracts a telemetry signal from a check run_result.
func TestSelectEDRTelemetryTestBasis(t *testing.T) {
	runResult := json.RawMessage(`{"artifacts":[{"artifact_id":"sig-1","artifact_kind":"mitigation-checkable-signal","mitigation_checkable_signal":{"candidate_family":"edr-telemetry","telemetry":{"event":{"type":"Process Creation"},"src":{"process":{"cmdline":"x -EncodedCommand y"}}}}}]}`)
	id, basis, err := selectEDRTelemetryTestBasis(runResult, "")
	if err != nil {
		t.Fatal(err)
	}
	if id != "sig-1" || len(basis.Telemetry) == 0 || basis.Expected.Blocked == nil || !*basis.Expected.Blocked {
		t.Fatalf("unexpected basis: id=%s telemetry=%s expected=%+v", id, basis.Telemetry, basis.Expected)
	}
}
