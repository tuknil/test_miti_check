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
	out.Substrate.Image = "endpoint telemetry (in-memory Wazuh)"

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

	if matched {
		out.Actual = Actual{
			Blocked:       true,
			ReachedApp:    false,
			MatchedRuleID: matchedRuleID,
			Detail:        fmt.Sprintf("Wazuh rule %s matched telemetry [%s] (%d condition(s)); endpoint action %q would fire", matchedRuleID, matchedOn, matchedConds, firstNonEmpty(cand.Action, "detect")),
		}
		out.TerminalState = stateBlocked
		out.Steps = append(out.Steps, "Wazuh rule "+matchedRuleID+" matched telemetry -> detected/prevented")
	} else {
		out.Actual = Actual{
			Blocked:    false,
			ReachedApp: true,
			Detail:     "no Wazuh rule matched the telemetry; activity was not detected/prevented",
		}
		out.TerminalState = stateNotBlocked
		out.Steps = append(out.Steps, "no Wazuh rule matched telemetry -> not detected")
	}

	// A match requires an actual block: not-detected never counts as a match; when
	// detected it must still agree with the expected outcome.
	out.Match = out.Actual.Blocked && (out.Actual.Blocked == out.Expected.Blocked)
	verdict := "DETECTED"
	if !out.Actual.Blocked {
		verdict = "NOT DETECTED"
	}
	agree := "matches"
	if !out.Match {
		agree = "does NOT match"
	}
	out.ProseSummary = fmt.Sprintf("Wazuh EDR candidate %s the telemetry sample; actual %s expected.", verdict, agree)
	if test.ProofBasis == "mitigation-discriminator" && out.TerminalState == stateBlocked {
		out.Limitations = append(out.Limitations, "indirect proof: only discriminator telemetry was proven detected (LLD §7.3)")
	}
	return out
}

// ---- locator: EDR telemetry test-basis selection ----

// edrCheckProjection is the (tolerant) EDR view of a Check Generation run_result:
// a mitigation-checkable telemetry signal carrying a decoded event and expected
// outcome. NOTE: the EDR check-generation contract is not yet fixtured here, so
// this reads a superset shape (telemetry|event|decoded_event) and defaults the
// expected outcome to detected when the producer omits it.
type edrCheckProjection struct {
	Artifacts []struct {
		ArtifactID   string `json:"artifact_id"`
		ArtifactKind string `json:"artifact_kind"`
		Signal       *struct {
			CandidateFamily string          `json:"candidate_family"`
			Telemetry       json.RawMessage `json:"telemetry"`
			Event           json.RawMessage `json:"event"`
			DecodedEvent    json.RawMessage `json:"decoded_event"`
			Expected        TestExpected    `json:"expected"`
		} `json:"mitigation_checkable_signal"`
	} `json:"artifacts"`
}

// selectEDRTelemetryTestBasis picks a telemetry mitigation signal from a Check
// Generation run_result and builds the EDR test basis. Mirrors
// selectRegisteredHTTPTestBasis for the WAF path.
func selectEDRTelemetryTestBasis(runResult json.RawMessage, selectedID string) (string, TestBasisSpec, error) {
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
		if fam != "edr-telemetry" && fam != "endpoint-signal" && fam != "endpoint-telemetry" {
			continue
		}
		telemetry := firstNonEmptyRaw(artifact.Signal.Telemetry, artifact.Signal.Event, artifact.Signal.DecodedEvent)
		if len(telemetry) == 0 {
			continue
		}
		expected := artifact.Signal.Expected
		if expected.Blocked == nil {
			detected := true // an EDR proof's discriminator telemetry is expected to be detected
			expected.Blocked = &detected
		}
		return artifact.ArtifactID, TestBasisSpec{
			Kind:       "edr-telemetry",
			ProofBasis: "mitigation-discriminator",
			Telemetry:  telemetry,
			Expected:   expected,
		}, nil
	}
	if selectedID != "" {
		return "", TestBasisSpec{}, fmt.Errorf("selected test_basis_id %q is not an eligible EDR telemetry artifact", selectedID)
	}
	return "", TestBasisSpec{}, fmt.Errorf("Check Generation produced no supported EDR telemetry test basis")
}

func firstNonEmptyRaw(raws ...json.RawMessage) json.RawMessage {
	for _, r := range raws {
		if len(r) > 0 && strings.TrimSpace(string(r)) != "null" {
			return r
		}
	}
	return nil
}
