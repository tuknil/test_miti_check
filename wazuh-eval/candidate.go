package main

// candidate.go adapts a Janus defense-generation candidate to the evaluators.
//
// A defense-generation result carries a primary_candidate whose artifact_content
// is the generated control. The candidate's control class / kind / artifact type
// says HOW to evaluate it:
//
//   EDR  (selected_control_class=edr, candidate_kind=endpoint-detection-rule,
//         artifact_type=wazuh-rule)     -> the Wazuh rule evaluator (rule.go/eval.go)
//         evaluated against a decoded telemetry event.
//   WAF  (selected_control_class=waf, candidate_kind=fast-waf-rule,
//         artifact_type=modsecurity-rule) -> the ModSecurity evaluator (waf.go)
//         evaluated against an HTTP request.
//
// EvaluateCandidate reuses the existing EDR evaluator unchanged and routes WAF
// candidates to the ModSecurity evaluator.

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Candidate is the defense-generation primary_candidate (the fields the
// evaluators need). Unknown fields in the source document are ignored.
type Candidate struct {
	CandidateID           string `json:"candidate_id"`
	SelectedControlClass  string `json:"selected_control_class"`
	CandidateKind         string `json:"candidate_kind"`
	ArtifactType          string `json:"artifact_type"`
	ArtifactContent       string `json:"artifact_content"`
	ArtifactHash          string `json:"artifact_hash"`
	MitigationIntent      string `json:"mitigation_intent"`
	ExpectedBlockBehavior string `json:"expected_block_behavior"`
	ExpectedAllowBehavior string `json:"expected_allow_behavior"`
}

// LoadCandidate accepts either a full defense-generation result document (with a
// primary_candidate) or a bare candidate object, and returns the candidate.
func LoadCandidate(data []byte) (*Candidate, error) {
	var doc struct {
		PrimaryCandidate *Candidate `json:"primary_candidate"`
	}
	if err := json.Unmarshal(data, &doc); err == nil && doc.PrimaryCandidate != nil && strings.TrimSpace(doc.PrimaryCandidate.ArtifactContent) != "" {
		return doc.PrimaryCandidate, nil
	}
	var c Candidate
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse candidate JSON: %w", err)
	}
	if strings.TrimSpace(c.ArtifactContent) == "" {
		return nil, fmt.Errorf("candidate has no artifact_content (nor primary_candidate.artifact_content)")
	}
	return &c, nil
}

// ControlClass classifies the candidate as "edr" or "waf" from its metadata,
// preferring selected_control_class, then candidate_kind, then artifact_type.
func (c *Candidate) ControlClass() (string, error) {
	switch strings.ToLower(strings.TrimSpace(c.SelectedControlClass)) {
	case "edr":
		return classEDR, nil
	case "waf":
		return classWAF, nil
	}
	switch strings.ToLower(strings.TrimSpace(c.CandidateKind)) {
	case "endpoint-detection-rule":
		return classEDR, nil
	case "fast-waf-rule":
		return classWAF, nil
	}
	switch strings.ToLower(strings.TrimSpace(c.ArtifactType)) {
	case "wazuh-rule":
		return classEDR, nil
	case "modsecurity-rule":
		return classWAF, nil
	}
	return "", fmt.Errorf("cannot determine control class (selected_control_class=%q candidate_kind=%q artifact_type=%q)",
		c.SelectedControlClass, c.CandidateKind, c.ArtifactType)
}

const (
	classEDR = "edr"
	classWAF = "waf"
)

// CandidateReport is the unified result of evaluating a candidate's artifact.
type CandidateReport struct {
	CandidateID   string   `json:"candidate_id,omitempty"`
	ControlClass  string   `json:"control_class"`
	CandidateKind string   `json:"candidate_kind,omitempty"`
	ArtifactType  string   `json:"artifact_type,omitempty"`
	Matched       bool     `json:"matched"`
	Results       []Result `json:"results"`
	Notes         []string `json:"notes,omitempty"`
}

// EvaluateCandidate routes to the EDR (Wazuh) or WAF (ModSecurity) evaluator by
// control class, evaluating the artifact against the raw event bytes: a decoded
// telemetry event for EDR, an HTTP request for WAF.
func EvaluateCandidate(c *Candidate, eventBytes []byte) (*CandidateReport, error) {
	class, err := c.ControlClass()
	if err != nil {
		return nil, err
	}
	rep := &CandidateReport{
		CandidateID:   c.CandidateID,
		ControlClass:  class,
		CandidateKind: c.CandidateKind,
		ArtifactType:  c.ArtifactType,
	}

	switch class {
	case classEDR:
		rules, err := ParseRules([]byte(c.ArtifactContent))
		if err != nil {
			return nil, fmt.Errorf("edr candidate: %w", err)
		}
		ev := LoadEvent(eventBytes)
		for _, r := range rules {
			res := Evaluate(r, ev) // reuse the existing EDR evaluator unchanged
			rep.Results = append(rep.Results, res)
			if res.Matched {
				rep.Matched = true
			}
		}

	case classWAF:
		req, err := LoadHTTPRequest(eventBytes)
		if err != nil {
			return nil, fmt.Errorf("waf candidate: %w", err)
		}
		res, err := EvaluateWAF(c.ArtifactContent, req) // reuse the in-process WAF evaluator
		if err != nil {
			return nil, fmt.Errorf("waf candidate: %w", err)
		}
		rep.Results = append(rep.Results, res)
		rep.Matched = res.Matched
	}

	// Surface the candidate's declared expectations for context (informational).
	if c.ExpectedBlockBehavior != "" {
		rep.Notes = append(rep.Notes, "expected_block_behavior: "+c.ExpectedBlockBehavior)
	}
	return rep, nil
}
