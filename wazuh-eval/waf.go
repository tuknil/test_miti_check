package main

// waf.go evaluates a WAF candidate: a ModSecurity SecRule against an HTTP
// request. It REUSES the mitigation-check in-process WAF evaluator (api's
// executor.go: wafRule / compileRule / evaluate / targetValues) verbatim, so a
// WAF candidate is judged here exactly as the production in-memory substrate
// judges it — same target set, same @rx extraction, same RE2 quantifier
// clamping, same raw+URL-decoded matching. It only wraps that logic to take the
// rule text directly and to emit the shared Result shape used by the EDR path.
//
// Supported (as in the substrate): a single SecRule with an @rx operator; targets
// REQUEST_BODY, REQUEST_URI, REQUEST_HEADERS, ARGS, ARGS_NAMES, ARGS:<name>;
// id:/status: actions. Each selected value is tested raw and after one URL-decode.

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// HTTPRequest is the decoded HTTP request a WAF rule is evaluated against. Its
// fields mirror the substrate's TestRequest so evaluation is identical.
type HTTPRequest struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// LoadHTTPRequest parses an HTTP request from JSON, accepting a flat object or a
// nested "http"/"request" wrapper and a few field aliases (uri/url → path,
// request_body → body).
func LoadHTTPRequest(data []byte) (*HTTPRequest, error) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse HTTP request JSON: %w", err)
	}
	src := raw
	for _, k := range []string{"http", "request"} {
		if m, ok := raw[k].(map[string]any); ok {
			src = m
			break
		}
	}
	r := &HTTPRequest{Headers: map[string]string{}}
	r.Method = strings.ToUpper(pickString(src, "method", "request_method"))
	r.Path = pickString(src, "path", "uri", "url", "request_uri")
	r.Body = pickString(src, "body", "request_body", "data", "payload")
	for _, key := range []string{"headers", "request_headers"} {
		if h, ok := src[key].(map[string]any); ok {
			for k, v := range h {
				r.Headers[k] = fmt.Sprint(v)
			}
		}
	}
	return r, nil
}

func pickString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok {
				return s
			}
			return fmt.Sprint(v)
		}
	}
	return ""
}

// ---- WAF evaluator (reused from api/executor.go) ---------------------------

type wafRule struct {
	ruleID  string
	status  int
	re      *regexp.Regexp
	targets []string
	clamped bool // a PCRE quantifier bound >1000 was clamped to fit RE2
}

var (
	reRuleID = regexp.MustCompile(`\bid:(\d+)`)
	reStatus = regexp.MustCompile(`\bstatus:(\d+)`)
	reTarget = regexp.MustCompile(`(?m)^\s*SecRule\s+(\S+)\s+`)
	// reQuant matches a bounded quantifier: {n}, {n,}, or {n,m}.
	reQuant = regexp.MustCompile(`\{(\d+)(,(\d*))?\}`)
)

// re2MaxRepeat is Go's RE2 hard limit on quantifier counts (regexp/syntax).
const re2MaxRepeat = 1000

// CompileSecRule compiles a ModSecurity SecRule (the candidate artifact_content)
// into an evaluable WAF rule. Mirrors api/executor.go's compileRule.
func CompileSecRule(rule string) (*wafRule, error) {
	targetMatch := reTarget.FindStringSubmatch(rule)
	if targetMatch == nil {
		return nil, fmt.Errorf("no SecRule target found")
	}
	targets, err := parseTargets(targetMatch[1])
	if err != nil {
		return nil, err
	}
	pattern, ok := extractRx(rule)
	if !ok {
		return nil, fmt.Errorf("no @rx operator found")
	}
	pattern, clamped := clampRE2Repeats(pattern)
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	r := &wafRule{re: re, status: 403, targets: targets, clamped: clamped}
	if m := reRuleID.FindStringSubmatch(rule); m != nil {
		r.ruleID = m[1]
	}
	if m := reStatus.FindStringSubmatch(rule); m != nil {
		if s, err := strconv.Atoi(m[1]); err == nil {
			r.status = s
		}
	}
	return r, nil
}

// clampRE2Repeats caps quantifier bounds above RE2's max (1000) so PCRE-style
// anti-DoS bounds like `.{0,1024}` — which RE2 rejects — compile under Go's
// regexp. RE2 has no backtracking, so the bound is only a length guard.
func clampRE2Repeats(pat string) (string, bool) {
	changed := false
	out := reQuant.ReplaceAllStringFunc(pat, func(m string) string {
		g := reQuant.FindStringSubmatch(m)
		lo, _ := strconv.Atoi(g[1])
		if lo > re2MaxRepeat {
			lo, changed = re2MaxRepeat, true
		}
		if g[2] == "" { // {n}
			return fmt.Sprintf("{%d}", lo)
		}
		if g[3] == "" { // {n,}
			return fmt.Sprintf("{%d,}", lo)
		}
		hi, _ := strconv.Atoi(g[3]) // {n,m}
		if hi > re2MaxRepeat {
			hi, changed = re2MaxRepeat, true
		}
		return fmt.Sprintf("{%d,%d}", lo, hi)
	})
	return out, changed
}

func parseTargets(expression string) ([]string, error) {
	parts := strings.Split(expression, "|")
	if len(parts) > 16 {
		return nil, fmt.Errorf("SecRule target expression exceeds 16 components")
	}
	for _, target := range parts {
		if target == "" || strings.HasPrefix(target, "!") || !supportedTarget(target) {
			return nil, fmt.Errorf("unsupported SecRule target %q", target)
		}
	}
	return parts, nil
}

func supportedTarget(target string) bool {
	if strings.HasPrefix(target, "ARGS:") {
		return strings.TrimPrefix(target, "ARGS:") != ""
	}
	return target == "REQUEST_BODY" || target == "REQUEST_URI" ||
		target == "REQUEST_HEADERS" || target == "ARGS" ||
		target == "ARGS_NAMES"
}

// extractRx pulls the regex out of the first quoted operator argument of a
// SecRule, decoding ModSecurity's backslash/quote escaping while preserving
// regex escapes such as \d.
func extractRx(rule string) (string, bool) {
	i := strings.Index(rule, `"`)
	if i < 0 {
		return "", false
	}
	var quoted strings.Builder
	for j := i + 1; j < len(rule); j++ {
		switch rule[j] {
		case '\\':
			if j+1 < len(rule) && (rule[j+1] == '\\' || rule[j+1] == '"') {
				quoted.WriteByte(rule[j+1])
				j++
				continue
			}
			quoted.WriteByte(rule[j])
		case '"':
			op := strings.TrimSpace(quoted.String())
			if strings.HasPrefix(op, "@rx") {
				return strings.TrimSpace(strings.TrimPrefix(op, "@rx")), true
			}
			return "", false
		default:
			quoted.WriteByte(rule[j])
		}
	}
	return "", false
}

// match applies the rule to the values its target selects, each checked raw and
// after one URL-decoding pass. Mirrors api/executor.go's evaluate, additionally
// reporting which target matched.
func (w *wafRule) match(req *HTTPRequest) (matched bool, target, value string) {
	for _, t := range w.targets {
		for _, raw := range targetValuesForOne(t, req) {
			for _, s := range []string{raw, urlDecode(raw)} {
				if s != "" && w.re.MatchString(s) {
					return true, t, s
				}
			}
		}
	}
	return false, "", ""
}

func targetValuesForOne(target string, req *HTTPRequest) []string {
	switch target {
	case "REQUEST_BODY":
		return []string{req.Body}
	case "REQUEST_URI":
		return []string{req.Path}
	case "REQUEST_HEADERS":
		names := make([]string, 0, len(req.Headers))
		for name := range req.Headers {
			names = append(names, name)
		}
		sort.Strings(names)
		values := make([]string, 0, len(names))
		for _, name := range names {
			values = append(values, req.Headers[name])
		}
		return values
	case "ARGS", "ARGS_NAMES":
		arguments := requestArguments(req)
		names := make([]string, 0, len(arguments))
		for name := range arguments {
			names = append(names, name)
		}
		sort.Strings(names)
		values := make([]string, 0, len(arguments))
		for _, name := range names {
			if target == "ARGS_NAMES" {
				values = append(values, name)
			} else {
				values = append(values, arguments[name]...)
			}
		}
		return values
	default:
		if strings.HasPrefix(target, "ARGS:") {
			return requestArguments(req)[strings.TrimPrefix(target, "ARGS:")]
		}
		return nil
	}
}

func requestArguments(req *HTTPRequest) url.Values {
	arguments := make(url.Values)
	merge := func(values url.Values) {
		for name, entries := range values {
			arguments[name] = append(arguments[name], entries...)
		}
	}
	if values, err := url.ParseQuery(req.Body); err == nil {
		merge(values)
	}
	if parsed, err := url.ParseRequestURI(req.Path); err == nil {
		merge(parsed.Query())
	}
	return arguments
}

func urlDecode(s string) string {
	if d, err := url.QueryUnescape(s); err == nil {
		return d
	}
	return s
}

// EvaluateWAF compiles and evaluates a WAF candidate rule against a request,
// returning the shared Result shape (Matched = the SecRule fired → would block).
func EvaluateWAF(rule string, req *HTTPRequest) (Result, error) {
	w, err := CompileSecRule(rule)
	if err != nil {
		return Result{}, err
	}
	matched, target, value := w.match(req)

	res := Result{RuleID: firstNonEmpty(w.ruleID, "(no id)"), Matched: matched}
	pattern := w.re.String()
	cond := CondResult{
		Kind:    "waf:@rx",
		Pattern: pattern,
		Matched: matched,
		Field:   firstNonEmpty(target, strings.Join(w.targets, "|")),
		Value:   value,
		Present: true,
	}
	if !matched {
		cond.Detail = "no targeted value matched @rx (targets: " + strings.Join(w.targets, ", ") + ")"
	}
	res.Conditions = append(res.Conditions, cond)

	if matched {
		res.Notes = append(res.Notes, fmt.Sprintf("disposition: SecRule fired → request BLOCKED (status %d)", w.status))
	} else {
		res.Notes = append(res.Notes, fmt.Sprintf("disposition: no match → request ALLOWED (would block with status %d on match)", w.status))
	}
	if w.clamped {
		res.Notes = append(res.Notes, "a PCRE quantifier bound >1000 was clamped to fit RE2 (matching differs only for very long inputs).")
	}
	return res, nil
}
