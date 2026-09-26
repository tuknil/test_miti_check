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

func edrRequest(t *testing.T, telemetry, action string, blocked bool) SubmitMitigationCheckRequest {
	t.Helper()
	t.Setenv("WAZUH_SYNTHETIC", "true") // exercise the synthetic (no-agent) flow
	cand, _ := json.Marshal(CandidateSpec{Kind: "endpoint-detection-rule", Engine: "wazuh", RuleID: "103047", Rule: edrWazuhRule, Action: action})
	tb, _ := json.Marshal(TestBasisSpec{Kind: "edr-telemetry", ProofBasis: "mitigation-discriminator",
		Telemetry: json.RawMessage(telemetry), Expected: TestExpected{Blocked: &blocked}})
	return SubmitMitigationCheckRequest{ContractID: contractID, RequestID: "edr-1", CorrelationID: "correlation-1",
		Candidate: cand, TestBasis: tb}
}

// edrCommandRequest builds an EDR request whose test basis is a command (the
// telemetry is synthesized from it). It selects the synthetic flow.
func edrCommandRequest(t *testing.T, rule, command, action string, blocked bool) SubmitMitigationCheckRequest {
	t.Helper()
	t.Setenv("WAZUH_SYNTHETIC", "true")
	cand, _ := json.Marshal(CandidateSpec{Kind: "endpoint-detection-rule", Engine: "wazuh", Rule: rule, Action: action})
	tb, _ := json.Marshal(TestBasisSpec{Kind: "edr-command", ProofBasis: "mitigation-discriminator",
		Command: command, Expected: TestExpected{Blocked: &blocked}})
	return SubmitMitigationCheckRequest{ContractID: contractID, RequestID: "edr-cmd", CorrelationID: "correlation-1",
		Candidate: cand, TestBasis: tb}
}

// WAZUH_SYNTHETIC=false selects inject-and-observe, which needs the EDR_* agent
// configuration; without it the run is could-not-test.
func TestEDRInjectObserveWhenDisabled(t *testing.T) {
	t.Setenv("WAZUH_SYNTHETIC", "false")
	t.Setenv("EDR_INDEXER_URL", "") // ensure config is absent
	cand, _ := json.Marshal(CandidateSpec{Kind: "endpoint-detection-rule", Engine: "wazuh", Rule: edrAuditExecRule})
	blocked := true
	tb, _ := json.Marshal(TestBasisSpec{Kind: "edr-command", Command: "adduser eve", Expected: TestExpected{Blocked: &blocked}})
	req := SubmitMitigationCheckRequest{ContractID: contractID, RequestID: "edr-io", Candidate: cand, TestBasis: tb}
	out := executeScenario(context.Background(), req, "run-io", "result-io")
	if out.Substrate.Image != "wazuh agent (inject-and-observe)" {
		t.Fatalf("default EDR did not route to inject-and-observe: image=%q", out.Substrate.Image)
	}
	if out.TerminalState != stateCouldNotTest {
		t.Fatalf("expected could-not-test without EDR_* config, got %s (%s)", out.TerminalState, out.Actual.Detail)
	}
}

const edrAuditExecRule = `<group name="audit,">
  <rule id="80785" level="8">
    <decoded_as>auditd</decoded_as>
    <field name="audit.execve.a0">^adduser$</field>
    <description>User account creation via adduser</description>
  </rule>
</group>`

const edrAuditFIMRule = `<group name="syscheck,">
  <rule id="80790" level="7">
    <field name="syscheck.path">^/etc/passwd$</field>
    <field name="syscheck.event">modified</field>
    <description>/etc/passwd modified</description>
  </rule>
</group>`

// MC31-002 regression: the synthetic (in-memory) path must not report detection
// as prevention. A preventive candidate whose rule matches yields DETECTION only
// (could-not-test for prevention); a monitor candidate yields not-blocked. Neither
// ever reports blocked/match from synthesized telemetry.
func TestEDRSyntheticDetectionIsNotPrevention(t *testing.T) {
	telemetry := `{"event":{"type":"Process Creation"},"src":{"process":{"cmdline":"powershell.exe -EncodedCommand SQBF"}}}`

	// Preventive action (kill-process): detection confirmed, prevention unverified.
	prevent := executeScenario(context.Background(), edrRequest(t, telemetry, "kill-process", true), "run-p", "result-p")
	if prevent.Actual.Blocked || prevent.Match {
		t.Fatalf("synthetic preventive match must NOT report blocked/match: blocked=%v match=%v", prevent.Actual.Blocked, prevent.Match)
	}
	if prevent.TerminalState != stateCouldNotTest {
		t.Fatalf("preventive+detected want could-not-test, got %s (%s)", prevent.TerminalState, prevent.Actual.Detail)
	}
	if prevent.Actual.MatchedRuleID != "103047" {
		t.Fatalf("detection should be recorded (MatchedRuleID), got %q", prevent.Actual.MatchedRuleID)
	}

	// Monitor action (non-preventive): detection, but definitively not a block.
	monitor := executeScenario(context.Background(), edrRequest(t, telemetry, "monitor", true), "run-m", "result-m")
	if monitor.Actual.Blocked || monitor.Match {
		t.Fatalf("monitor match must NOT report blocked/match: blocked=%v match=%v", monitor.Actual.Blocked, monitor.Match)
	}
	if monitor.TerminalState != stateNotBlocked {
		t.Fatalf("monitor+detected want not-blocked, got %s (%s)", monitor.TerminalState, monitor.Actual.Detail)
	}

	// The two actions must produce distinct honest outcomes.
	if prevent.TerminalState == monitor.TerminalState {
		t.Fatalf("monitor vs block should differ; both were %s", prevent.TerminalState)
	}
}

// EDR command test basis: synthesized telemetry DETECTS via the execve event
// (preventive candidate → detection-only / could-not-test, never blocked).
func TestEDRCommandDetectsExecve(t *testing.T) {
	out := executeScenario(context.Background(), edrCommandRequest(t, edrAuditExecRule, "adduser eve", "kill-process", true), "run-c1", "result-c1")
	if out.TerminalState != stateCouldNotTest || out.Actual.MatchedRuleID != "80785" {
		t.Fatalf("expected detection-only (could-not-test) for adduser, got %s rule=%q (%s)", out.TerminalState, out.Actual.MatchedRuleID, out.Actual.Detail)
	}
	if out.Actual.Blocked || out.Match {
		t.Fatalf("synthetic detection must not be reported as prevention: %+v", out.Actual)
	}
}

// EDR command test basis: detection can come from a FIM event in the synthesized
// footprint (not just the execve).
func TestEDRCommandDetectsFIMEvent(t *testing.T) {
	out := executeScenario(context.Background(), edrCommandRequest(t, edrAuditFIMRule, "adduser eve", "kill-process", true), "run-c2", "result-c2")
	if out.TerminalState != stateCouldNotTest || out.Actual.MatchedRuleID != "80790" {
		t.Fatalf("expected FIM /etc/passwd detection from adduser footprint, got %s rule=%q (%s)", out.TerminalState, out.Actual.MatchedRuleID, out.Actual.Detail)
	}
	if out.Actual.Blocked {
		t.Fatalf("synthetic FIM detection must not be reported as blocked")
	}
}

// EDR command test basis: an unrelated command is not detected.
func TestEDRCommandNoMatch(t *testing.T) {
	out := executeScenario(context.Background(), edrCommandRequest(t, edrAuditExecRule, "ls -la /tmp", "kill-process", true), "run-c3", "result-c3")
	if out.TerminalState != stateNotBlocked || out.Actual.Blocked || out.Match {
		t.Fatalf("expected not-detected for benign command, got %s match=%v", out.TerminalState, out.Match)
	}
}

// EDR dispatch by candidate kind even when execution_mode is unset (defaults).
func TestEDRDispatchByCandidateKind(t *testing.T) {
	telemetry := `{"event":{"type":"Process Creation"},"src":{"process":{"cmdline":"powershell.exe -EncodedCommand X"}}}`
	req := edrRequest(t, telemetry, "kill-process", true)
	req.ExecutionMode = "" // no explicit mode; isEDRCandidate must still route to EDR
	out := executeScenario(context.Background(), req, "run-2", "result-2")
	if out.Substrate.Image != "endpoint telemetry (in-memory Wazuh, synthetic)" {
		t.Fatalf("did not route to EDR evaluator: image=%q", out.Substrate.Image)
	}
	if out.Actual.MatchedRuleID != "103047" {
		t.Fatalf("expected detection to be recorded, got rule=%q", out.Actual.MatchedRuleID)
	}
}

// EDR candidate + benign telemetry -> not detected; a not-blocked result never matches.
func TestEDRExecutionNoMatchAllows(t *testing.T) {
	telemetry := `{"event":{"type":"Process Creation"},"src":{"process":{"cmdline":"powershell.exe -File backup.ps1"}}}`
	req := edrRequest(t, telemetry, "kill-process", true)
	out := executeScenario(context.Background(), req, "run-3", "result-3")
	if out.TerminalState != stateNotBlocked {
		t.Fatalf("terminal_state=%s want %s", out.TerminalState, stateNotBlocked)
	}
	if out.Actual.Blocked || out.Match {
		t.Fatalf("benign telemetry must be not-blocked and not a match: %+v", out.Actual)
	}
}

// Missing telemetry AND command (synthetic flow) -> could-not-test.
func TestEDRMissingTelemetryCouldNotTest(t *testing.T) {
	t.Setenv("WAZUH_SYNTHETIC", "true")
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

// selectEDRTestBasis extracts a telemetry signal from a check run_result.
func TestSelectEDRTelemetryTestBasis(t *testing.T) {
	runResult := json.RawMessage(`{"artifacts":[{"artifact_id":"sig-1","artifact_kind":"mitigation-checkable-signal","mitigation_checkable_signal":{"candidate_family":"edr-telemetry","telemetry":{"event":{"type":"Process Creation"},"src":{"process":{"cmdline":"x -EncodedCommand y"}}}}}]}`)
	id, basis, err := selectEDRTestBasis(runResult, "")
	if err != nil {
		t.Fatal(err)
	}
	if id != "sig-1" || len(basis.Telemetry) == 0 || basis.Expected.Blocked == nil || !*basis.Expected.Blocked {
		t.Fatalf("unexpected basis: id=%s telemetry=%s expected=%+v", id, basis.Telemetry, basis.Expected)
	}
}

// selectEDRTestBasis extracts a command signal (the upstream/check-generation EDR
// path) and produces a command test basis.
func TestSelectEDRCommandTestBasis(t *testing.T) {
	runResult := json.RawMessage(`{"artifacts":[{"artifact_id":"sig-c","artifact_kind":"mitigation-checkable-signal","mitigation_checkable_signal":{"candidate_family":"edr-command","command":"adduser eve","command_user":"root"}}]}`)
	id, basis, err := selectEDRTestBasis(runResult, "")
	if err != nil {
		t.Fatal(err)
	}
	if id != "sig-c" || basis.Command != "adduser eve" || basis.CommandUser != "root" || basis.Kind != "edr-command" {
		t.Fatalf("unexpected command basis: %+v", basis)
	}
	if basis.Expected.Blocked == nil || !*basis.Expected.Blocked {
		t.Fatalf("expected default blocked=true, got %+v", basis.Expected)
	}
}
