package main

// executor.go implements a real local-WAF validation substrate (LLD §6.4) and a
// deterministic verdict (LLD §6.5, §7.2). On submit it:
//   1. brings up the vulnerable container image (the substrate),
//   2. applies the candidate's actual ModSecurity SecRule via an in-process WAF,
//   3. runs the supplied test request through the WAF,
//   4. observes actual behavior and resolves a terminal state,
//   5. tears the substrate down.
//
// The WAF here faithfully enforces the *specific* SecRule shipped in the
// candidate (its @rx pattern, targets, and deny/status action). It is not the
// full ModSecurity engine; swapping in a real ModSecurity container is an
// adapter change behind this same flow.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// RunOutcome is the executed result surfaced to the UI (a pragmatic superset of
// MitigationCheckResult@1, LLD §10.2).
type RunOutcome struct {
	RunID         string   `json:"run_id"`
	ResultID      string   `json:"result_id"`
	TerminalState string   `json:"terminal_state"`
	Match         bool     `json:"match"`
	Expected      Expected `json:"expected"`
	Actual        Actual   `json:"actual"`
	Substrate     SubInfo  `json:"substrate"`
	Steps         []string `json:"steps"`
	ProseSummary  string   `json:"prose_summary"`
	Limitations   []string `json:"limitations,omitempty"`
}

type Expected struct {
	Classification string `json:"classification"`
	Blocked        bool   `json:"blocked"`
	StatusCode     int    `json:"status_code"`
}

type Actual struct {
	Blocked       bool   `json:"blocked"`
	StatusCode    int    `json:"status_code"`
	ReachedApp    bool   `json:"reached_app"`
	MatchedRuleID string `json:"matched_rule_id,omitempty"`
	Detail        string `json:"detail"`
}

type SubInfo struct {
	Image       string `json:"image"`
	ContainerID string `json:"container_id,omitempty"`
	HostPort    int    `json:"host_port,omitempty"`
	Ready       bool   `json:"ready"`
}

const (
	stateBlocked      = "blocked"
	stateNotBlocked   = "not-blocked"
	stateCouldNotTest = "could-not-test"
	stateMalfunction  = "malfunction"
)

// executeScenario runs the full bring-up → apply → test → observe → teardown loop.
// It requires the inline substrate/candidate/test_basis bodies to be present.
func executeScenario(ctx context.Context, req SubmitMitigationCheckRequest, runID, resultID string) RunOutcome {
	out := RunOutcome{RunID: runID, ResultID: resultID}

	var sub SubstrateSpec
	var cand CandidateSpec
	var test TestBasisSpec
	if err := json.Unmarshal(nonNil(req.Substrate), &sub); err != nil || sub.Image == "" {
		return couldNotTest(out, "substrate image not provided in request body")
	}
	if err := json.Unmarshal(nonNil(req.Candidate), &cand); err != nil || cand.Rule == "" {
		return couldNotTest(out, "candidate WAF rule not provided in request body")
	}
	if err := json.Unmarshal(nonNil(req.TestBasis), &test); err != nil || test.Expected.Blocked == nil {
		return couldNotTest(out, "test basis / expected outcome not provided in request body")
	}

	out.Expected = Expected{
		Classification: test.Expected.Classification,
		Blocked:        *test.Expected.Blocked,
		StatusCode:     test.Expected.StatusCode,
	}
	out.Substrate.Image = sub.Image

	// Compile the candidate rule up front; a rule we cannot parse means we cannot
	// faithfully apply the candidate, so we cannot test.
	waf, err := compileRule(cand)
	if err != nil {
		return couldNotTest(out, "could not parse candidate SecRule: "+err.Error())
	}
	out.Steps = append(out.Steps, "parsed candidate SecRule id="+waf.ruleID+" (deny→"+strconv.Itoa(waf.status)+")")

	// 1. Bring up the substrate container.
	port, err := freePort()
	if err != nil {
		return couldNotTest(out, "no free host port for substrate")
	}
	out.Substrate.HostPort = port

	if err := dockerAvailable(ctx); err != nil {
		return couldNotTest(out, "docker not available: "+err.Error())
	}
	out.Steps = append(out.Steps, "docker available")

	cid, err := startContainer(ctx, sub.Image, port)
	if err != nil {
		return couldNotTest(out, "could not start substrate container: "+trimErr(err))
	}
	out.Substrate.ContainerID = shortID(cid)
	out.Steps = append(out.Steps, "started container "+shortID(cid)+" from "+sub.Image+" on 127.0.0.1:"+strconv.Itoa(port))
	defer func() { _ = stopContainer(cid) }()

	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	if err := waitReady(ctx, base, 90*time.Second); err != nil {
		return couldNotTest(out, "substrate did not become ready: "+err.Error())
	}
	out.Substrate.Ready = true
	out.Steps = append(out.Steps, "substrate ready (app responding on "+base+")")

	// 2 + 3. Apply the WAF rule to the supplied test request.
	matched, decoded := waf.evaluate(test.Request)
	if matched {
		// Rule fired: request is denied at the WAF and never reaches the app.
		out.Actual = Actual{
			Blocked:       true,
			StatusCode:    waf.status,
			ReachedApp:    false,
			MatchedRuleID: waf.ruleID,
			Detail:        "WAF rule " + waf.ruleID + " matched; request denied with " + strconv.Itoa(waf.status),
		}
		out.Steps = append(out.Steps, "WAF matched rule "+waf.ruleID+" on: "+truncate(decoded, 120))
		out.TerminalState = stateBlocked
	} else {
		// Rule did not fire: forward the request to the real vulnerable app.
		status, snippet, ferr := forward(ctx, base, test.Request)
		if ferr != nil {
			return couldNotTest(out, "could not observe app response: "+ferr.Error())
		}
		out.Actual = Actual{
			Blocked:    false,
			StatusCode: status,
			ReachedApp: true,
			Detail:     "WAF did not match; request reached app (status " + strconv.Itoa(status) + "): " + truncate(snippet, 120),
		}
		out.Steps = append(out.Steps, "WAF did not match; request forwarded to app, status "+strconv.Itoa(status))
		out.TerminalState = stateNotBlocked
	}

	// 4. Actual vs expected.
	out.Match = out.Actual.Blocked == out.Expected.Blocked
	out.ProseSummary = summarize(out)
	if test.ProofBasis == "mitigation-discriminator" && out.TerminalState == stateBlocked {
		out.Limitations = append(out.Limitations, "indirect proof: only discriminator behavior was proven blocked (LLD §7.3)")
	}
	return out
}

func couldNotTest(out RunOutcome, reason string) RunOutcome {
	out.TerminalState = stateCouldNotTest
	out.Actual.Detail = reason
	out.Steps = append(out.Steps, "could-not-test: "+reason)
	out.ProseSummary = "Could not produce a trustworthy block/pass verdict: " + reason
	return out
}

func summarize(o RunOutcome) string {
	verdict := "BLOCKED"
	if !o.Actual.Blocked {
		verdict = "NOT BLOCKED"
	}
	agree := "matches"
	if !o.Match {
		agree = "does NOT match"
	}
	exp := "blocked"
	if !o.Expected.Blocked {
		exp = "not-blocked"
	}
	return fmt.Sprintf("Candidate %s the supplied sample in %s; actual %s expected (%s).",
		verdict, o.Substrate.Image, agree, exp)
}

// ---- WAF: faithful enforcement of the specific candidate SecRule ----

type wafRule struct {
	ruleID string
	status int
	re     *regexp.Regexp
	// targets left implicit: URI + header values + body (covers
	// REQUEST_URI | REQUEST_HEADERS | ARGS | REQUEST_BODY).
}

var (
	reRuleID = regexp.MustCompile(`\bid:(\d+)`)
	reStatus = regexp.MustCompile(`\bstatus:(\d+)`)
)

func compileRule(c CandidateSpec) (*wafRule, error) {
	pattern, ok := extractRx(c.Rule)
	if !ok {
		return nil, fmt.Errorf("no @rx operator found")
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	r := &wafRule{re: re, ruleID: c.RuleID, status: 403}
	if m := reRuleID.FindStringSubmatch(c.Rule); m != nil && r.ruleID == "" {
		r.ruleID = m[1]
	}
	if m := reStatus.FindStringSubmatch(c.Rule); m != nil {
		if s, err := strconv.Atoi(m[1]); err == nil {
			r.status = s
		}
	}
	return r, nil
}

// extractRx pulls the regex out of the first quoted operator argument of a SecRule.
func extractRx(rule string) (string, bool) {
	i := strings.Index(rule, `"`)
	if i < 0 {
		return "", false
	}
	rest := rule[i+1:]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return "", false
	}
	op := strings.TrimSpace(rest[:j])
	if strings.HasPrefix(op, "@rx") {
		return strings.TrimSpace(strings.TrimPrefix(op, "@rx")), true
	}
	return "", false
}

// evaluate applies the rule to the request, mirroring t:urlDecodeUni by matching
// against both raw and URL-decoded forms of the URI, header values, and body.
func (w *wafRule) evaluate(req TestRequest) (bool, string) {
	candidates := []string{req.Path, req.Body}
	for _, v := range req.Headers {
		candidates = append(candidates, v)
	}
	for _, raw := range candidates {
		for _, s := range []string{raw, urlDecode(raw)} {
			if s != "" && w.re.MatchString(s) {
				return true, s
			}
		}
	}
	return false, ""
}

func urlDecode(s string) string {
	if d, err := url.QueryUnescape(s); err == nil {
		return d
	}
	return s
}

// ---- Docker substrate lifecycle ----

func dockerAvailable(ctx context.Context) error {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return exec.CommandContext(c, "docker", "version", "--format", "{{.Server.Version}}").Run()
}

func startContainer(ctx context.Context, image string, hostPort int) (string, error) {
	c, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	args := []string{"run", "-d", "--rm",
		"-p", fmt.Sprintf("127.0.0.1:%d:8080", hostPort),
		image}
	cmd := exec.CommandContext(c, "docker", args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s", strings.TrimSpace(errb.String()+" "+err.Error()))
	}
	return strings.TrimSpace(out.String()), nil
}

func stopContainer(id string) error {
	if id == "" {
		return nil
	}
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return exec.CommandContext(c, "docker", "rm", "-f", id).Run()
}

func waitReady(ctx context.Context, base string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 3 * time.Second}
	var last string
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		resp, err := client.Get(base + "/")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return nil
			}
			last = "status " + strconv.Itoa(resp.StatusCode)
		} else {
			last = err.Error()
		}
		time.Sleep(1 * time.Second)
	}
	if last == "" {
		last = "timeout"
	}
	return fmt.Errorf("%s", last)
}

// forward sends the (non-blocked) test request to the real app and reports status.
func forward(ctx context.Context, base string, req TestRequest) (int, string, error) {
	c, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	method := req.Method
	if method == "" {
		method = "GET"
	}
	path := req.Path
	if path == "" {
		path = "/"
	}
	httpReq, err := http.NewRequestWithContext(c, method, base+path, strings.NewReader(req.Body))
	if err != nil {
		return 0, "", err
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(httpReq)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return resp.StatusCode, strings.TrimSpace(string(body)), nil
}

// ---- small helpers ----

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func nonNil(r json.RawMessage) json.RawMessage {
	if len(r) == 0 {
		return json.RawMessage("null")
	}
	return r
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func trimErr(err error) string {
	s := err.Error()
	return truncate(s, 300)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
