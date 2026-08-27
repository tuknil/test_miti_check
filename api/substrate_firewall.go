package main

// substrate_firewall.go is a SEPARATE, in-memory execution mode ("firewall") for
// evaluating network firewall rules (L3/L4) — distinct from the L7 WAF path.
// There is no substrate/container: it parses the candidate firewall rule and a
// supplied network-connection test (5-tuple) and decides block/pass entirely
// in-process. Fits Log4Shell as an egress control: a rule that denies the
// outbound JNDI callback (LDAP/RMI) mitigates exploitation.
//
// Two candidate.rule syntaxes are accepted:
//   1) compact:  <action> <proto> <src> -> <dst>[:<port|lo-hi|*>]
//        deny tcp any -> any:1389
//   2) iptables (candidate.engine "iptables" or a rule with -j):
//        -A OUTPUT -p tcp -d 198.51.100.7 --dport 1389 -j DROP
//        -A OUTPUT -p tcp -m multiport --dports 389,636,1099,1389 -j DROP
// Either way it is evaluated in-memory against the connection 5-tuple.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// FirewallTestBasis is the network-connection test for firewall mode.
type FirewallTestBasis struct {
	Kind       string       `json:"kind"`
	ProofBasis string       `json:"proof_basis"`
	Connection FWConnection `json:"connection"`
	Expected   TestExpected `json:"expected"`
}

type FWConnection struct {
	Protocol string `json:"protocol"`
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	DstPort  int    `json:"dst_port"`
}

func runFirewallInMemory(ctx context.Context, req SubmitMitigationCheckRequest, out RunOutcome) RunOutcome {
	var cand CandidateSpec
	if err := json.Unmarshal(nonNil(req.Candidate), &cand); err != nil || strings.TrimSpace(cand.Rule) == "" {
		return couldNotTest(out, "firewall rule not provided in request body (candidate.rule)")
	}
	out.Candidate = &cand // embed the rule so the result is self-contained
	var test FirewallTestBasis
	if err := json.Unmarshal(nonNil(req.TestBasis), &test); err != nil || test.Expected.Blocked == nil {
		return couldNotTest(out, "network-connection test / expected outcome not provided in request body")
	}

	out.Expected = Expected{
		Classification: test.Expected.Classification,
		Blocked:        *test.Expected.Blocked,
		StatusCode:     test.Expected.StatusCode,
	}
	out.Substrate.Image = "network firewall (in-memory)"

	fw, err := compileFirewallRule(cand)
	if err != nil {
		return couldNotTest(out, "could not parse firewall rule: "+err.Error())
	}
	out.Steps = append(out.Steps, "parsed firewall rule "+fw.ruleID+" ("+fw.action+" "+fw.proto+")")

	conn := test.Connection
	out.Steps = append(out.Steps, fmt.Sprintf("evaluating connection %s %s -> %s:%d",
		conn.Protocol, conn.SrcIP, conn.DstIP, conn.DstPort))

	matched := fw.matches(conn)
	if matched && fw.action == "deny" {
		out.Actual = Actual{
			Blocked:       true,
			ReachedApp:    false,
			MatchedRuleID: fw.ruleID,
			Detail:        "firewall rule " + fw.ruleID + " matched; connection denied",
		}
		out.TerminalState = stateBlocked
		out.Steps = append(out.Steps, "firewall DENY matched -> connection blocked")
	} else {
		out.Actual = Actual{
			Blocked:    false,
			ReachedApp: true,
			Detail:     "no denying firewall rule matched; connection allowed to reach the destination",
		}
		out.TerminalState = stateNotBlocked
		out.Steps = append(out.Steps, "no deny match -> connection allowed")
	}

	out.Match = out.Actual.Blocked == out.Expected.Blocked
	verdict := "BLOCKED"
	if !out.Actual.Blocked {
		verdict = "ALLOWED"
	}
	agree := "matches"
	if !out.Match {
		agree = "does NOT match"
	}
	out.ProseSummary = fmt.Sprintf("Firewall rule %s %s the %s connection to %s:%d; actual %s expected.",
		fw.ruleID, verdict, conn.Protocol, conn.DstIP, conn.DstPort, agree)
	if test.ProofBasis == "mitigation-discriminator" && out.TerminalState == stateBlocked {
		out.Limitations = append(out.Limitations, "indirect proof: only discriminator behavior was proven blocked (LLD §7.3)")
	}
	return out
}

// ---- in-memory firewall rule ----

type fwRule struct {
	ruleID         string
	action         string // "deny" | "allow"
	proto          string // "tcp" | "udp" | "any"
	srcNet, dstNet *net.IPNet
	portLo, portHi int          // range; 0,0 = any
	portSet        map[int]bool // explicit set (iptables multiport); takes precedence
	chain          string       // iptables chain (informational)
}

func compileFirewallRule(c CandidateSpec) (*fwRule, error) {
	if isIptables(c) {
		return compileIptablesRule(c)
	}
	sides := strings.SplitN(c.Rule, "->", 2)
	if len(sides) != 2 {
		return nil, fmt.Errorf("expected '<action> <proto> <src> -> <dst>[:port]'")
	}
	left := strings.Fields(sides[0])
	if len(left) < 3 {
		return nil, fmt.Errorf("left side needs: <action> <proto> <src>")
	}
	r := &fwRule{
		ruleID: firstNonEmpty(c.RuleID, "fw-rule"),
		action: strings.ToLower(firstNonEmpty(c.Action, left[0])),
		proto:  strings.ToLower(left[1]),
	}
	var err error
	if r.srcNet, err = parseHostOrCIDR(left[2]); err != nil {
		return nil, fmt.Errorf("source: %w", err)
	}

	right := strings.TrimSpace(sides[1])
	host, port := right, ""
	if i := strings.LastIndex(right, ":"); i >= 0 {
		host, port = right[:i], right[i+1:]
	}
	if r.dstNet, err = parseHostOrCIDR(host); err != nil {
		return nil, fmt.Errorf("destination: %w", err)
	}
	if r.portLo, r.portHi, err = parsePortRange(port); err != nil {
		return nil, fmt.Errorf("port: %w", err)
	}
	return r, nil
}

func (r *fwRule) matches(c FWConnection) bool {
	if r.proto != "" && r.proto != "any" && !strings.EqualFold(r.proto, c.Protocol) {
		return false
	}
	if r.srcNet != nil {
		if ip := net.ParseIP(c.SrcIP); ip == nil || !r.srcNet.Contains(ip) {
			return false
		}
	}
	if r.dstNet != nil {
		if ip := net.ParseIP(c.DstIP); ip == nil || !r.dstNet.Contains(ip) {
			return false
		}
	}
	if len(r.portSet) > 0 {
		if !r.portSet[c.DstPort] {
			return false
		}
	} else if !(r.portLo == 0 && r.portHi == 0) {
		if c.DstPort < r.portLo || c.DstPort > r.portHi {
			return false
		}
	}
	return true
}

// parseHostOrCIDR: "any"/"*" => nil (match all); CIDR => that net; bare IP => /32/128.
func parseHostOrCIDR(s string) (*net.IPNet, error) {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "any") || s == "*" {
		return nil, nil
	}
	if strings.Contains(s, "/") {
		_, n, err := net.ParseCIDR(s)
		return n, err
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP/CIDR %q", s)
	}
	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
}

// parsePortRange: ""/"*"/"any" => any; "n" => n,n; "lo-hi" => lo,hi.
func parsePortRange(s string) (int, int, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "*" || strings.EqualFold(s, "any") {
		return 0, 0, nil
	}
	if lo, hi, ok := strings.Cut(s, "-"); ok {
		l, err1 := strconv.Atoi(strings.TrimSpace(lo))
		h, err2 := strconv.Atoi(strings.TrimSpace(hi))
		if err1 != nil || err2 != nil {
			return 0, 0, fmt.Errorf("invalid range %q", s)
		}
		return l, h, nil
	}
	p, err := strconv.Atoi(s)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port %q", s)
	}
	return p, p, nil
}

// ---- iptables rule syntax ----

// isIptables reports whether the candidate rule is iptables-style rather than the
// compact "<action> <proto> <src> -> <dst>" form.
func isIptables(c CandidateSpec) bool {
	if strings.EqualFold(c.Engine, "iptables") {
		return true
	}
	rule := strings.TrimSpace(c.Rule)
	return strings.HasPrefix(rule, "iptables") ||
		strings.HasPrefix(rule, "-A ") || strings.HasPrefix(rule, "-I ") ||
		strings.Contains(rule, " -j ")
}

// compileIptablesRule parses a subset of iptables syntax into an fwRule:
//
//	[-A|-I <chain>] [-p <proto>] [-s <src>] [-d <dst>]
//	[-m <mod>] [--dport <port|lo:hi>] [--dports <p,p,lo:hi>] -j <DROP|REJECT|ACCEPT>
//
// e.g.  -A OUTPUT -p tcp -d 198.51.100.7 --dport 1389 -j DROP
func compileIptablesRule(c CandidateSpec) (*fwRule, error) {
	r := &fwRule{ruleID: firstNonEmpty(c.RuleID, "fw-rule"), proto: "any"}
	toks := strings.Fields(c.Rule)
	target := ""
	for i := 0; i < len(toks); i++ {
		arg := toks[i]
		val := ""
		if i+1 < len(toks) {
			val = toks[i+1]
		}
		switch strings.ToLower(arg) {
		case "iptables", "ip6tables", "iptables-legacy":
			// binary name — skip
		case "-a", "--append", "-i", "--insert":
			r.chain = val
			i++
		case "-p", "--protocol":
			r.proto = strings.ToLower(val)
			i++
		case "-s", "--source", "--src":
			n, err := parseHostOrCIDR(val)
			if err != nil {
				return nil, fmt.Errorf("source: %w", err)
			}
			r.srcNet = n
			i++
		case "-d", "--destination", "--dst":
			n, err := parseHostOrCIDR(val)
			if err != nil {
				return nil, fmt.Errorf("destination: %w", err)
			}
			r.dstNet = n
			i++
		case "--dport", "--destination-port":
			lo, hi, err := parseDport(val)
			if err != nil {
				return nil, err
			}
			r.portLo, r.portHi = lo, hi
			i++
		case "--dports":
			set, err := parseDports(val)
			if err != nil {
				return nil, err
			}
			r.portSet = set
			i++
		case "-j", "--jump":
			target = strings.ToUpper(val)
			i++
		case "-m", "--match":
			i++ // skip the module name (tcp, multiport, ...)
		default:
			// ignore unrecognized flags/values
		}
	}
	switch target {
	case "DROP", "REJECT":
		r.action = "deny"
	case "ACCEPT":
		r.action = "allow"
	default:
		r.action = strings.ToLower(firstNonEmpty(c.Action, "deny"))
	}
	if r.proto == "all" {
		r.proto = "any"
	}
	return r, nil
}

// parseDport handles an iptables --dport: single port or a "lo:hi" range.
func parseDport(s string) (int, int, error) {
	if lo, hi, ok := strings.Cut(s, ":"); ok {
		l, e1 := strconv.Atoi(strings.TrimSpace(lo))
		h, e2 := strconv.Atoi(strings.TrimSpace(hi))
		if e1 != nil || e2 != nil {
			return 0, 0, fmt.Errorf("invalid port range %q", s)
		}
		return l, h, nil
	}
	p, err := strconv.Atoi(s)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port %q", s)
	}
	return p, p, nil
}

// parseDports handles an iptables multiport --dports: comma list of ports/ranges.
func parseDports(s string) (map[int]bool, error) {
	set := map[int]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if lo, hi, ok := strings.Cut(part, ":"); ok {
			l, e1 := strconv.Atoi(strings.TrimSpace(lo))
			h, e2 := strconv.Atoi(strings.TrimSpace(hi))
			if e1 != nil || e2 != nil {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			for p := l; p <= h && p-l < 65536; p++ {
				set[p] = true
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q", part)
			}
			set[p] = true
		}
	}
	return set, nil
}
