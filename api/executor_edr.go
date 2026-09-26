package main

// executor_edr.go is a SEPARATE, in-memory execution mode ("edr") for evaluating
// endpoint-detection (EDR) candidates — a Wazuh rule against a decoded telemetry
// event. Like the firewall mode, there is no substrate/container/WAF: it parses
// the candidate Wazuh rule and the telemetry test basis and decides
// detected/prevented (block) vs not entirely in-process.
//
// It REUSES the Wazuh rule evaluator in package wazuh (api/wazuh), which is the
// same evaluator shipped as the standalone wazuh-eval tool. Selection between the
// WAF, firewall, and EDR evaluators is by candidate kind (see candidateKind /
// isEDRCandidate); the surrounding lifecycle — durable staging, Databricks
// publication, and Postgres completion — is identical to every other mode.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/janus/mitigation-check-api/wazuh"
	wazuh_ssh "github.com/janus/mitigation-check-api/wazuh-ssh"
)

// isEDRCandidate reports whether the request's candidate is an endpoint-detection
// (Wazuh) rule, by engine/kind or the rule's XML shape.
func isEDRCandidate(raw json.RawMessage) bool {
	var c CandidateSpec
	if err := json.Unmarshal(nonNil(raw), &c); err != nil {
		return false
	}
	if strings.EqualFold(c.Engine, "wazuh") || c.Kind == "endpoint-detection-rule" {
		return true
	}
	r := c.Rule
	return strings.Contains(r, "<rule ") || strings.Contains(r, "<group") || strings.Contains(r, "decoded_as")
}

// runEDRInMemory evaluates a Wazuh rule candidate against a decoded telemetry
// event and resolves a block/pass verdict, mirroring runFirewallInMemory.
func runEDRInMemory(ctx context.Context, req SubmitMitigationCheckRequest, out RunOutcome) RunOutcome {
	var cand CandidateSpec
	if err := json.Unmarshal(nonNil(req.Candidate), &cand); err != nil || strings.TrimSpace(cand.Rule) == "" {
		return couldNotTest(out, "Wazuh EDR rule not provided in request body (candidate.rule)")
	}
	out.Candidate = &cand // embed the rule so the result is self-contained

	var test TestBasisSpec
	if err := json.Unmarshal(nonNil(req.TestBasis), &test); err != nil || test.Expected.Blocked == nil {
		return couldNotTest(out, "telemetry test basis / expected outcome not provided in request body")
	}
	out.Expected = Expected{
		Classification: test.Expected.Classification,
		Blocked:        *test.Expected.Blocked,
		StatusCode:     test.Expected.StatusCode,
	}
	out.TestBasis = &test

	// Telemetry source selector. Default (WAZUH_SYNTHETIC unset/true): the synthetic
	// command→telemetry flow below, which evaluates the candidate rule in-process
	// without an agent. WAZUH_SYNTHETIC=false injects the activity on a real Wazuh
	// agent and observes the actual alerts it raises.
	if !getEnvBool("WAZUH_SYNTHETIC", true) {
		return runEDRInjectObserve(ctx, out, cand, test)
	}

	out.Substrate.Image = "endpoint telemetry (in-memory Wazuh, synthetic)"

	// Resolve the telemetry to evaluate the rule against: for an EDR test basis a
	// command is synthesized into the Wazuh telemetry it would generate (the full
	// footprint: execve + child processes + FIM); otherwise a decoded telemetry
	// event is supplied directly.
	type edrItem struct {
		summary string
		event   *wazuh.Event
	}
	var items []edrItem
	switch {
	case strings.TrimSpace(test.Command) != "":
		footprint, ferr := wazuh.CommandTelemetryFootprint(wazuh.CommandInput{
			Command: test.Command,
			User:    firstNonEmpty(test.CommandUser, "root"),
			Host:    firstNonEmpty(test.CommandHost, "linux-host"),
		})
		if ferr != nil {
			return couldNotTest(out, "could not synthesize telemetry from command: "+ferr.Error())
		}
		for _, e := range footprint {
			items = append(items, edrItem{summary: e.Summary, event: wazuh.LoadEvent(e.Event)})
		}
		out.Steps = append(out.Steps, fmt.Sprintf("synthesized %d telemetry event(s) from command %q", len(items), test.Command))
	case len(test.Telemetry) > 0:
		items = append(items, edrItem{summary: "supplied telemetry", event: wazuh.LoadEvent(test.Telemetry)})
	default:
		return couldNotTest(out, "EDR test basis must provide a command (test_basis.command) or decoded telemetry (test_basis.telemetry)")
	}

	rules, err := wazuh.ParseRules([]byte(cand.Rule))
	if err != nil {
		return couldNotTest(out, "could not parse Wazuh rule: "+err.Error())
	}
	if cand.RuleID == "" && len(rules) > 0 {
		cand.RuleID = rules[0].ID
	}
	out.Steps = append(out.Steps, fmt.Sprintf("parsed Wazuh ruleset (%d rule(s)); native action %q", len(rules), firstNonEmpty(cand.Action, "detect")))

	// The rule fires if any rule matches any of the synthesized telemetry events.
	matched := false
	matchedRuleID := ""
	matchedConds := 0
	matchedOn := ""
	for _, r := range rules {
		for _, it := range items {
			res := wazuh.Evaluate(r, it.event)
			if res.Matched {
				matched = true
				matchedRuleID = res.RuleID
				matchedOn = it.summary
				for _, c := range res.Conditions {
					if c.Matched {
						matchedConds++
					}
				}
				break
			}
		}
		if matched {
			break
		}
	}

	// This path evaluates synthesized telemetry in-process: a rule match proves the
	// rule would DETECT the activity, but it neither installs the rule in the
	// configured Wazuh manager nor observes an active-response/prevention action.
	// So it never reports prevention (Blocked=true) — that would be false mitigation
	// evidence. It emits an honest detection-only / non-prevention outcome, and
	// distinguishes a preventive candidate (kill/quarantine/…) from a monitor one.
	out.Actual.MatchedRuleID = matchedRuleID
	out.Actual.ReachedApp = true // the activity occurred; the endpoint did not block it here
	preventive := isPreventiveAction(cand.Action)
	switch {
	case matched && preventive:
		out.Actual.Blocked = false
		out.Actual.Detail = fmt.Sprintf("synthetic preflight: rule %s matched telemetry [%s] (%d condition(s)) — DETECTION confirmed; prevention (action=%q) was NOT exercised against the Wazuh manager", matchedRuleID, matchedOn, matchedConds, cand.Action)
		out.TerminalState = stateCouldNotTest // prevention is unverified in a preflight
		out.Steps = append(out.Steps, "synthetic preflight detected the activity; prevention not verified")
		out.Limitations = append(out.Limitations, "synthetic in-memory evaluation proves DETECTION only; set WAZUH_SYNTHETIC=false to observe monitor/block behavior on the configured Wazuh manager")
		out.ProseSummary = fmt.Sprintf("Synthetic preflight: Wazuh rule %s DETECTED the activity; prevention not verified (detection-only).", matchedRuleID)
	case matched && !preventive:
		out.Actual.Blocked = false
		out.Actual.Detail = fmt.Sprintf("rule %s matched telemetry [%s] (%d condition(s)) — DETECTION; candidate action=%q is non-preventive (monitor), so the activity is not blocked", matchedRuleID, matchedOn, matchedConds, firstNonEmpty(cand.Action, "detect"))
		out.TerminalState = stateNotBlocked
		out.Steps = append(out.Steps, "detection-only (monitor) control matched; not a preventive mitigation")
		out.Limitations = append(out.Limitations, "candidate is a detection/monitor control: it detects but does not prevent")
		out.ProseSummary = fmt.Sprintf("Wazuh rule %s DETECTED the activity; candidate action is non-preventive (monitor), so no mitigation/block occurs.", matchedRuleID)
	default: // not detected
		out.Actual.Blocked = false
		out.Actual.Detail = "no Wazuh rule matched the telemetry; activity was not detected"
		out.TerminalState = stateNotBlocked
		out.Steps = append(out.Steps, "no Wazuh rule matched telemetry -> not detected")
		out.ProseSummary = "No Wazuh rule matched the synthesized telemetry; not detected."
	}

	// The synthetic path never observes a prevention/block, so it never reports a
	// mitigation match. Authoritative block/monitor evidence comes from the
	// inject-and-observe path against the configured Wazuh manager.
	out.Match = out.Actual.Blocked && (out.Actual.Blocked == out.Expected.Blocked)
	return out
}

// isPreventiveAction reports whether a candidate's native action actually blocks
// or prevents the activity (versus a detection/monitor/log-only action).
func isPreventiveAction(action string) bool {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "kill-process", "kill", "terminate", "quarantine", "isolate", "block",
		"prevent", "deny", "drop", "remove", "delete", "active-response":
		return true
	default:
		return false
	}
}

// runEDRInjectObserve is the real (non-synthetic) EDR path: it injects the test
// basis command on a live Wazuh agent and observes the actual alerts the manager
// raises, rather than synthesizing telemetry in-process. Configuration comes from
// the EDR_* environment (see wazuh_ssh.LoadConfig). The candidate rule is assumed
// already deployed on the manager.
func runEDRInjectObserve(ctx context.Context, out RunOutcome, cand CandidateSpec, test TestBasisSpec) RunOutcome {
	out.Substrate.Image = "wazuh agent (inject-and-observe)"

	command := strings.TrimSpace(test.Command)
	if command == "" {
		return couldNotTest(out, "inject-and-observe EDR requires a command test basis (or set WAZUH_SYNTHETIC=true for the synthetic telemetry flow)")
	}
	cfg, err := wazuh_ssh.LoadConfig()
	if err != nil {
		return couldNotTest(out, "inject-and-observe configuration: "+err.Error())
	}

	token := newID()
	out.Steps = append(out.Steps, fmt.Sprintf("injecting command on Wazuh agent %s (%s) and observing alerts", cfg.AgentID, cfg.ExecutionMode))
	res, err := cfg.Execute(ctx, command, token, firstNonEmpty(test.CommandHost, cfg.SSHHost))
	if err != nil {
		return couldNotTest(out, "inject-and-observe execution: "+err.Error())
	}
	if !res.EDRObservation.Request.Injected {
		return couldNotTest(out, "inject-and-observe: command injection failed: "+firstNonEmpty(res.EDRObservation.Request.InjectionDetail, "unknown error"))
	}

	// Report the manager's OBSERVED behavior. Only a decision of "blocked" is
	// prevention (Blocked=true); "logged-only" is detection without prevention
	// (a monitor control) and must not be reported as a block; "allowed"/none is
	// neither. This keeps EDR evidence honest about monitor vs block.
	detectedIDs := res.EDRObservation.Response.DetectedRuleIDs
	ids := strings.Join(detectedIDs, ",")
	switch strings.ToLower(strings.TrimSpace(res.Control.ControlDecision)) {
	case "blocked":
		out.Actual = Actual{
			Blocked: true, ReachedApp: false, MatchedRuleID: ids,
			Detail: fmt.Sprintf("Wazuh observed prevention for the injected activity (rules %s); control decision blocked", ids),
		}
		out.TerminalState = stateBlocked
		out.Steps = append(out.Steps, "observed prevention (blocked): rules "+ids)
	case "logged-only":
		out.Actual = Actual{
			Blocked: false, ReachedApp: true, MatchedRuleID: ids,
			Detail: fmt.Sprintf("Wazuh DETECTED but did not prevent the injected activity (rules %s); control decision logged-only (monitor)", ids),
		}
		out.TerminalState = stateNotBlocked
		out.Steps = append(out.Steps, "observed detection without prevention (logged-only): rules "+ids)
		out.Limitations = append(out.Limitations, "candidate detected the activity but did not block it (monitor); not a prevention")
	default: // allowed / no-decision / unknown
		out.Actual = Actual{
			Blocked: false, ReachedApp: true, MatchedRuleID: ids,
			Detail: "Wazuh neither detected nor prevented the injected activity",
		}
		out.TerminalState = stateNotBlocked
		out.Steps = append(out.Steps, "observed no detection or prevention for the injected activity")
	}

	out.Match = out.Actual.Blocked && (out.Actual.Blocked == out.Expected.Blocked)
	agree := "matches"
	if !out.Match {
		agree = "does NOT match"
	}
	out.ProseSummary = fmt.Sprintf("Wazuh EDR candidate observed decision %q on a live agent; actual %s expected.", res.Control.ControlDecision, agree)
	if test.ProofBasis == "mitigation-discriminator" && out.TerminalState == stateBlocked {
		out.Limitations = append(out.Limitations, "indirect proof: only discriminator activity was proven blocked (LLD §7.3)")
	}
	return out
}

// ---- EDR test-basis selection (upstream + locator) ----

// edrCheckProjection is the (tolerant) EDR view of a Check Generation run_result:
// a mitigation-checkable endpoint signal carrying either a command (synthesized
// into telemetry) or a decoded event, plus the expected outcome. NOTE: the EDR
// check-generation contract is not yet fixtured here, so this reads a superset
// shape (command | telemetry|event|decoded_event) and defaults the expected
// outcome to detected when the producer omits it.
type edrCheckProjection struct {
	Artifacts []struct {
		ArtifactID   string `json:"artifact_id"`
		ArtifactKind string `json:"artifact_kind"`
		Signal       *struct {
			CandidateFamily string          `json:"candidate_family"`
			Command         string          `json:"command"`
			CommandUser     string          `json:"command_user"`
			CommandHost     string          `json:"command_host"`
			Telemetry       json.RawMessage `json:"telemetry"`
			Event           json.RawMessage `json:"event"`
			DecodedEvent    json.RawMessage `json:"decoded_event"`
			Expected        TestExpected    `json:"expected"`
		} `json:"mitigation_checkable_signal"`
	} `json:"artifacts"`
}

// selectEDRTestBasis picks an endpoint mitigation signal from a Check Generation
// run_result and builds the EDR test basis — a command (preferred) or a decoded
// telemetry event. Mirrors selectRegisteredHTTPTestBasis for the WAF path.
func selectEDRTestBasis(runResult json.RawMessage, selectedID string) (string, TestBasisSpec, error) {
	var projection edrCheckProjection
	if err := json.Unmarshal(runResult, &projection); err != nil {
		return "", TestBasisSpec{}, fmt.Errorf("decode Check Generation run_result: %w", err)
	}
	for _, artifact := range projection.Artifacts {
		if selectedID != "" && artifact.ArtifactID != selectedID {
			continue
		}
		if artifact.ArtifactKind != "mitigation-checkable-signal" || artifact.Signal == nil || strings.TrimSpace(artifact.ArtifactID) == "" {
			continue
		}
		fam := strings.ToLower(strings.TrimSpace(artifact.Signal.CandidateFamily))
		if fam != "edr-command" && fam != "edr-telemetry" && fam != "endpoint-signal" && fam != "endpoint-telemetry" {
			continue
		}
		command := strings.TrimSpace(artifact.Signal.Command)
		telemetry := firstNonEmptyRaw(artifact.Signal.Telemetry, artifact.Signal.Event, artifact.Signal.DecodedEvent)
		if command == "" && len(telemetry) == 0 {
			continue
		}
		expected := artifact.Signal.Expected
		if expected.Blocked == nil {
			detected := true // an EDR proof's discriminator activity is expected to be detected
			expected.Blocked = &detected
		}
		tb := TestBasisSpec{ProofBasis: "mitigation-discriminator", Expected: expected}
		if command != "" {
			tb.Kind, tb.Command, tb.CommandUser, tb.CommandHost = "edr-command", command, artifact.Signal.CommandUser, artifact.Signal.CommandHost
		} else {
			tb.Kind, tb.Telemetry = "edr-telemetry", telemetry
		}
		return artifact.ArtifactID, tb, nil
	}
	if selectedID != "" {
		return "", TestBasisSpec{}, fmt.Errorf("selected test_basis_id %q is not an eligible EDR mitigation artifact", selectedID)
	}
	return "", TestBasisSpec{}, fmt.Errorf("Check Generation produced no supported EDR test basis (command or telemetry)")
}

func firstNonEmptyRaw(raws ...json.RawMessage) json.RawMessage {
	for _, r := range raws {
		if len(r) > 0 && strings.TrimSpace(string(r)) != "null" {
			return r
		}
	}
	return nil
}
