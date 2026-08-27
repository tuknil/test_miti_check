package main

// stimulus.go is standalone: it converts an upstream "http-probe" stimulus object
// into a TestBasisSpec (the same test contract the executor runs). It is used to
// derive the test for in-memory execution from a probe definition.
//
// It maps the vulnerable/attack request (the true-positive case): a correct
// candidate is expected to block it. The stimulus's response predicates
// (vulnerable_predicate / vulnerable_marker / baseline_predicate) describe how to
// judge a response and have no home in the current TestBasisSpec (which asserts
// blocked/status_code); they are intentionally not emitted here.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strings"
)

// Stimulus is the upstream http-probe stimulus.
type Stimulus struct {
	ArtifactType        string            `json:"artifact_type"`
	Method              string            `json:"method"`
	PathKey             string            `json:"path_key"`
	Query               map[string]string `json:"query"`
	Headers             map[string]string `json:"headers"`
	JSONBody            json.RawMessage   `json:"json_body"`
	BodyText            *string           `json:"body_text"`
	ContentType         *string           `json:"content_type"`
	TimeoutSeconds      int               `json:"timeout_seconds"`
	VulnerablePredicate string            `json:"vulnerable_predicate"`
	VulnerableMarker    string            `json:"vulnerable_marker"`
	BaselinePredicate   string            `json:"baseline_predicate"`
}

// TestBasisFromStimulus builds the true-positive TestBasisSpec from a stimulus:
// the vulnerable/attack request, expected to be blocked (403) by a correct
// candidate.
func TestBasisFromStimulus(s Stimulus) (TestBasisSpec, error) {
	body, err := stimulusBody(s)
	if err != nil {
		return TestBasisSpec{}, err
	}
	blocked := true
	return TestBasisSpec{
		Kind:       firstNonEmpty(s.ArtifactType, "http-probe"),
		ProofBasis: "verified-vuln-artifact",
		Request: TestRequest{
			Method:  strings.ToUpper(strings.TrimSpace(firstNonEmpty(s.Method, "GET"))),
			Path:    stimulusPath(s.PathKey, s.Query),
			Headers: stimulusHeaders(s),
			Body:    body,
		},
		Expected: TestExpected{
			Classification: "true-positive",
			Blocked:        &blocked,
			StatusCode:     403,
		},
	}, nil
}

// stimulusBody prefers json_body (compacted, preserving key order and escaping),
// falling back to body_text; empty when neither is present.
func stimulusBody(s Stimulus) (string, error) {
	if len(s.JSONBody) > 0 && strings.TrimSpace(string(s.JSONBody)) != "null" {
		var buf bytes.Buffer
		if err := json.Compact(&buf, s.JSONBody); err != nil {
			return "", fmt.Errorf("json_body: %w", err)
		}
		return buf.String(), nil
	}
	if s.BodyText != nil {
		return *s.BodyText, nil
	}
	return "", nil
}

// stimulusPath returns path_key verbatim, appending a sorted query string when the
// query map is non-empty.
func stimulusPath(pathKey string, query map[string]string) string {
	p := strings.TrimSpace(pathKey)
	if len(query) == 0 {
		return p
	}
	vals := url.Values{}
	for k, v := range query {
		vals.Set(k, v)
	}
	return p + "?" + vals.Encode()
}

// stimulusHeaders copies the stimulus headers, adding Content-Type from the
// stimulus's content_type when one is provided and not already present.
func stimulusHeaders(s Stimulus) map[string]string {
	if s.ContentType == nil || strings.TrimSpace(*s.ContentType) == "" {
		return s.Headers
	}
	h := make(map[string]string, len(s.Headers)+1)
	hasCT := false
	for k, v := range s.Headers {
		h[k] = v
		if strings.EqualFold(k, "Content-Type") {
			hasCT = true
		}
	}
	if !hasCT {
		h["Content-Type"] = *s.ContentType
	}
	return h
}

// parseStimulus extracts the stimulus from the input JSON. The primary shape is
//
//	{ "artifacts": [ { "mitigation_check_signal": { "stimulus": {...} } }, ... ] }
//
// where only the FIRST artifact is used. It also accepts the plain fallbacks
// {"stimulus": {...}} and a bare stimulus object.
func parseStimulus(data []byte) (Stimulus, error) {
	if t := bytes.TrimSpace(data); len(t) == 0 || string(t) == "null" {
		return Stimulus{}, fmt.Errorf("empty input")
	}

	// Detect the envelope shape by the presence of a non-null "artifacts" field.
	// When present it is authoritative: a malformed envelope errors rather than
	// silently falling through to a plain-object parse.
	var probe struct {
		Artifacts json.RawMessage `json:"artifacts"`
	}
	if err := json.Unmarshal(data, &probe); err == nil &&
		len(probe.Artifacts) > 0 && string(bytes.TrimSpace(probe.Artifacts)) != "null" {
		var env struct {
			Artifacts []struct {
				MitigationCheckSignal struct {
					Stimulus *Stimulus `json:"stimulus"`
				} `json:"mitigation_check_signal"`
			} `json:"artifacts"`
		}
		if err := json.Unmarshal(data, &env); err != nil {
			return Stimulus{}, fmt.Errorf("parse artifacts: %w", err)
		}
		if len(env.Artifacts) == 0 {
			return Stimulus{}, fmt.Errorf("artifacts array is empty")
		}
		if env.Artifacts[0].MitigationCheckSignal.Stimulus == nil {
			return Stimulus{}, fmt.Errorf("artifacts[0].mitigation_check_signal.stimulus is missing")
		}
		return *env.Artifacts[0].MitigationCheckSignal.Stimulus, nil
	}

	// Fallbacks: {"stimulus": {...}} or a bare stimulus object.
	var wrap struct {
		Stimulus *Stimulus `json:"stimulus"`
	}
	if err := json.Unmarshal(data, &wrap); err == nil && wrap.Stimulus != nil {
		return *wrap.Stimulus, nil
	}
	var s Stimulus
	if err := json.Unmarshal(data, &s); err != nil {
		return Stimulus{}, err
	}
	return s, nil
}

// stimulusCLI reads a stimulus JSON (file arg, or stdin when the arg is "-" or
// absent) and prints the derived TestBasisSpec JSON. Wired to the
// "stimulus-to-testbasis" subcommand.
func stimulusCLI(args []string) {
	var (
		data []byte
		err  error
	)
	if len(args) > 0 && args[0] != "-" {
		data, err = os.ReadFile(args[0])
	} else {
		data, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		log.Fatalf("read stimulus: %v", err)
	}
	s, err := parseStimulus(data)
	if err != nil {
		log.Fatalf("parse stimulus: %v", err)
	}
	tb, err := TestBasisFromStimulus(s)
	if err != nil {
		log.Fatalf("convert: %v", err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(tb); err != nil {
		log.Fatalf("encode: %v", err)
	}
}
