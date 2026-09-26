package wazuh

// eval.go evaluates a Wazuh rule against a single decoded event.
//
// A rule fires only when EVERY condition it declares matches (logical AND).
// Wazuh supports three text-matching engines; we implement stdlib-only
// approximations of each (documented in README.md):
//
//   OS_Match  (<match>, type="osmatch")  — literal substring with optional
//             '|' alternation and '^'/'$' anchors. No regex metacharacters.
//   OS_Regex  (<regex>, <field>, default) — Wazuh's own regex syntax; we
//             translate its escapes (\w \d \s \p \t ...) to Go's RE2.
//   PCRE2     (<pcre2>, type="pcre2")      — approximated by RE2. Lookarounds
//             and backreferences are unsupported and reported as such.
//
// Correlation elements (if_sid, if_group, frequency, same_source_ip, ...) span
// multiple events and cannot be judged from one event; they are reported as
// informational notes and do not, by themselves, fail the match.

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// CondResult is the outcome of one condition within a rule.
type CondResult struct {
	Kind    string `json:"kind"`             // "match", "field:win.eventdata.image", "srcip", ...
	Pattern string `json:"pattern"`          // the rule's pattern/value
	Negate  bool   `json:"negate,omitempty"` // condition inverted with negate="yes"
	Matched bool   `json:"matched"`          // did this condition pass?
	Field   string `json:"field,omitempty"`  // event field consulted
	Value   string `json:"value,omitempty"`  // event value seen (empty if field absent)
	Present bool   `json:"present"`          // was the consulted field present?
	Detail  string `json:"detail,omitempty"` // engine notes / approximation warnings
}

// Result is the full evaluation of one rule against one event.
type Result struct {
	RuleID      string       `json:"rule_id"`
	Level       string       `json:"level,omitempty"`
	Description string       `json:"description,omitempty"`
	Matched     bool         `json:"matched"`
	Conditions  []CondResult `json:"conditions"`
	Notes       []string     `json:"notes,omitempty"` // correlation elements & caveats
}

// Evaluate runs every condition of the rule against the event and AND-s them.
func Evaluate(r Rule, e *Event) Result {
	res := Result{
		RuleID:      r.ID,
		Level:       r.Level,
		Description: strings.TrimSpace(r.Description),
		Matched:     true,
	}

	add := func(c CondResult) {
		res.Conditions = append(res.Conditions, c)
		if !c.Matched {
			res.Matched = false
		}
	}

	// decoded_as / program_name: match against the decoder name or program_name field.
	for _, m := range r.DecodedAs {
		add(matchField(e, "decoded_as", m, "osmatch", "decoder.name", "decoder", "program_name"))
	}
	for _, m := range r.ProgramName {
		add(matchField(e, "program_name", m, "osmatch", "program_name", "data.program_name"))
	}

	// match / regex / pcre2: run against the full log text.
	for _, m := range r.Match {
		add(matchText(e, "match", m, "osmatch"))
	}
	for _, m := range r.Regex {
		add(matchText(e, "regex", m, "osregex"))
	}
	for _, m := range r.Pcre2 {
		add(matchText(e, "pcre2", m, "pcre2"))
	}

	// field name="...": match a named decoded field (default engine osregex).
	for _, f := range r.Fields {
		add(matchNamedField(e, f))
	}

	// Typed comparators — each addresses a conventional decoded field.
	comparators := []struct {
		kind    string
		matcher []Matcher
		fields  []string
		engine  string
	}{
		{"srcip", r.SrcIP, []string{"srcip", "src_ip", "data.srcip"}, "ip"},
		{"dstip", r.DstIP, []string{"dstip", "dst_ip", "data.dstip"}, "ip"},
		{"srcport", r.SrcPort, []string{"srcport", "data.srcport"}, "osmatch"},
		{"dstport", r.DstPort, []string{"dstport", "data.dstport"}, "osmatch"},
		{"user", r.User, []string{"dstuser", "user", "data.dstuser", "data.user"}, "osregex"},
		{"srcuser", r.SrcUser, []string{"srcuser", "data.srcuser"}, "osregex"},
		{"dstuser", r.DstUser, []string{"dstuser", "data.dstuser"}, "osregex"},
		{"url", r.URL, []string{"url", "data.url"}, "osregex"},
		{"id", r.IDField, []string{"id", "data.id"}, "osmatch"},
		{"status", r.Status, []string{"status", "data.status"}, "osmatch"},
		{"hostname", r.Hostname, []string{"hostname", "data.hostname"}, "osregex"},
		{"extra_data", r.ExtraData, []string{"extra_data", "data.extra_data"}, "osregex"},
		{"system_name", r.SystemName, []string{"system_name", "data.system_name"}, "osregex"},
		{"action", r.Action, []string{"action", "data.action"}, "osregex"},
		{"protocol", r.Protocol, []string{"protocol", "data.protocol"}, "osmatch"},
		{"data", r.Data, []string{"data", "data.data"}, "osregex"},
		{"location", r.Location, []string{"location"}, "osregex"},
	}
	for _, c := range comparators {
		for _, m := range c.matcher {
			if c.engine == "ip" {
				add(matchIP(e, c.kind, m, c.fields...))
			} else {
				add(matchField(e, c.kind, m, c.engine, c.fields...))
			}
		}
	}

	collectNotes(r, &res)
	return res
}

// collectNotes records correlation / multi-event elements that cannot be judged
// from a single event. They do not fail the match; they qualify it.
func collectNotes(r Rule, res *Result) {
	note := func(s string) { res.Notes = append(res.Notes, s) }
	if len(r.IfSid) > 0 {
		note(fmt.Sprintf("if_sid=%s: parent rule(s) must have fired; not checkable from one event (assumed satisfied).", strings.Join(r.IfSid, ",")))
	}
	if len(r.IfGroup) > 0 {
		note(fmt.Sprintf("if_group=%s: a prior rule in this group must have fired; not checkable from one event (assumed satisfied).", strings.Join(r.IfGroup, ",")))
	}
	if len(r.IfMatchedSid) > 0 {
		note(fmt.Sprintf("if_matched_sid=%s: correlation over timeframe; not checkable from one event (assumed satisfied).", strings.Join(r.IfMatchedSid, ",")))
	}
	if len(r.IfMatchedGrp) > 0 {
		note(fmt.Sprintf("if_matched_group=%s: correlation over timeframe; not checkable from one event (assumed satisfied).", strings.Join(r.IfMatchedGrp, ",")))
	}
	if r.Frequency != "" || r.Timeframe != "" {
		note(fmt.Sprintf("frequency=%q timeframe=%q: this rule counts repeated events; a single event cannot satisfy the count.", r.Frequency, r.Timeframe))
	}
	if r.SameSrcIP != nil || r.SameSrcIP2 != nil {
		note("same_source_ip: cross-event correlation; not checkable from one event.")
	}
	if r.SameUser != nil {
		note("same_user: cross-event correlation; not checkable from one event.")
	}
	if r.DifferentURL != nil {
		note("different_url: cross-event correlation; not checkable from one event.")
	}
	if strings.EqualFold(r.Overwrite, "yes") {
		note("overwrite=\"yes\": this rule redefines another by id; evaluated here as a standalone rule.")
	}
}

// ---- field/text resolution -------------------------------------------------

// matchText matches a rule pattern against the event's full log text.
func matchText(e *Event, kind string, m Matcher, defaultEngine string) CondResult {
	text := e.FullLog
	present := text != ""
	c := CondResult{Kind: kind, Pattern: m.Value, Negate: isNegate(m.Negate), Field: "full_log", Value: text, Present: present}
	ok, detail := runEngine(engineFor(m.Type, defaultEngine), m.Value, text)
	c.Detail = detail
	c.Matched = applyNegate(ok, c.Negate)
	return c
}

// matchField matches against the first present field among candidates.
func matchField(e *Event, kind string, m Matcher, defaultEngine string, fields ...string) CondResult {
	val, field, present := resolve(e, fields...)
	c := CondResult{Kind: kind, Pattern: m.Value, Negate: isNegate(m.Negate), Field: field, Value: val, Present: present}
	ok := false
	var detail string
	if present {
		ok, detail = runEngine(engineFor(m.Type, defaultEngine), m.Value, val)
	} else {
		detail = "field not present in event"
	}
	c.Detail = detail
	c.Matched = applyNegate(ok, c.Negate)
	return c
}

// matchNamedField matches a <field name="..."> condition.
func matchNamedField(e *Event, f Field) CondResult {
	val, present := e.get(f.Name)
	c := CondResult{
		Kind:    "field:" + f.Name,
		Pattern: f.Value,
		Negate:  isNegate(f.Negate),
		Field:   f.Name,
		Value:   val,
		Present: present,
	}
	ok := false
	var detail string
	if present {
		ok, detail = runEngine(engineFor(f.Type, "osregex"), f.Value, val)
	} else {
		detail = "field not present in event"
	}
	c.Detail = detail
	c.Matched = applyNegate(ok, c.Negate)
	return c
}

// matchIP matches srcip/dstip as an IP or CIDR (comma/pipe-separated list allowed).
func matchIP(e *Event, kind string, m Matcher, fields ...string) CondResult {
	val, field, present := resolve(e, fields...)
	c := CondResult{Kind: kind, Pattern: m.Value, Negate: isNegate(m.Negate), Field: field, Value: val, Present: present}
	ok := false
	if present {
		ok = ipMatch(m.Value, val)
	} else {
		c.Detail = "field not present in event"
	}
	c.Matched = applyNegate(ok, c.Negate)
	return c
}

// resolve returns the value/field-name of the first present candidate field.
func resolve(e *Event, fields ...string) (val, field string, present bool) {
	for _, f := range fields {
		if v, ok := e.get(f); ok {
			return v, f, true
		}
	}
	if len(fields) > 0 {
		field = fields[0]
	}
	return "", field, false
}

// ---- matching engines ------------------------------------------------------

func engineFor(typeAttr, def string) string {
	switch strings.ToLower(strings.TrimSpace(typeAttr)) {
	case "osmatch":
		return "osmatch"
	case "osregex":
		return "osregex"
	case "pcre2":
		return "pcre2"
	case "":
		return def
	default:
		return def
	}
}

// runEngine dispatches to the requested matching engine, returning whether the
// pattern matched and an optional diagnostic note.
func runEngine(engine, pattern, subject string) (bool, string) {
	switch engine {
	case "osmatch":
		return osMatch(pattern, subject), ""
	case "pcre2":
		return pcre2Match(pattern, subject)
	default: // osregex
		return osRegex(pattern, subject)
	}
}

// osMatch approximates Wazuh OS_Match: a literal string test with optional '|'
// alternation and '^' (prefix) / '$' (suffix) anchors. It is case-sensitive and
// treats every other character literally (no regex metacharacters).
func osMatch(pattern, subject string) bool {
	for _, alt := range strings.Split(pattern, "|") {
		if alt == "" {
			continue
		}
		anchorStart := strings.HasPrefix(alt, "^")
		anchorEnd := strings.HasSuffix(alt, "$")
		lit := strings.TrimSuffix(strings.TrimPrefix(alt, "^"), "$")
		switch {
		case anchorStart && anchorEnd:
			if subject == lit {
				return true
			}
		case anchorStart:
			if strings.HasPrefix(subject, lit) {
				return true
			}
		case anchorEnd:
			if strings.HasSuffix(subject, lit) {
				return true
			}
		default:
			if strings.Contains(subject, lit) {
				return true
			}
		}
	}
	return false
}

// osRegex approximates Wazuh OS_Regex by translating its escape classes to RE2
// and compiling with Go's regexp. Wazuh OS_Regex is not anchored by default.
func osRegex(pattern, subject string) (bool, string) {
	translated := translateOSRegex(pattern)
	re, err := regexp.Compile(translated)
	if err != nil {
		return false, "osregex compile error (approximation): " + err.Error()
	}
	detail := ""
	if translated != pattern {
		detail = "osregex approximated as RE2: " + translated
	}
	return re.MatchString(subject), detail
}

// translateOSRegex maps Wazuh OS_Regex tokens to RE2 equivalents.
// Wazuh classes: \w \d \s \t \p (punctuation) and their negations \W \D \S.
func translateOSRegex(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] == '\\' && i+1 < len(p) {
			n := p[i+1]
			switch n {
			case 'p': // Wazuh: punctuation. RE2 \p means Unicode class, so remap.
				b.WriteString("[[:punct:]]")
			case 'w', 'W', 'd', 'D', 's', 'S', 't', 'n', 'r', '.', '(', ')', '[', ']', '{', '}', '|', '+', '*', '?', '^', '$', '\\', '/':
				b.WriteByte('\\')
				b.WriteByte(n)
			default:
				// Unknown escape: pass the literal char through unescaped-ish.
				b.WriteByte('\\')
				b.WriteByte(n)
			}
			i++
			continue
		}
		b.WriteByte(p[i])
	}
	return b.String()
}

// pcre2Match approximates PCRE2 with RE2. RE2 lacks lookaround/backreferences;
// when the pattern uses them, compilation fails and we report the limitation.
func pcre2Match(pattern, subject string) (bool, string) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		detail := "pcre2 not fully supported by RE2 approximation: " + err.Error()
		if strings.Contains(pattern, "(?=") || strings.Contains(pattern, "(?!") ||
			strings.Contains(pattern, "(?<") || strings.Contains(pattern, "\\1") {
			detail += " (lookaround/backreference cannot be evaluated)"
		}
		return false, detail
	}
	return re.MatchString(subject), ""
}

// ipMatch tests an event IP against a rule pattern that may be a plain IP, a
// CIDR, or a comma/pipe-separated list of either.
func ipMatch(pattern, value string) bool {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return false
	}
	for _, tok := range strings.FieldsFunc(pattern, func(r rune) bool { return r == ',' || r == '|' }) {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if strings.Contains(tok, "/") {
			if _, cidr, err := net.ParseCIDR(tok); err == nil && cidr.Contains(ip) {
				return true
			}
			continue
		}
		if pip := net.ParseIP(tok); pip != nil && pip.Equal(ip) {
			return true
		}
	}
	return false
}

// ---- negate helpers --------------------------------------------------------

func isNegate(attr string) bool {
	return strings.EqualFold(strings.TrimSpace(attr), "yes")
}

func applyNegate(matched, negate bool) bool {
	if negate {
		return !matched
	}
	return matched
}
