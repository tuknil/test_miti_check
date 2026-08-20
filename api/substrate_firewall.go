package main

// substrate_firewall.go is a SEPARATE, in-memory execution mode ("firewall") for
// evaluating network firewall rules (L3/L4) — distinct from the L7 WAF path.
// There is no substrate/container: it parses the candidate firewall rule and a
// supplied network-connection test (5-tuple) and decides block/pass entirely
// in-process. Fits Log4Shell as an egress control: a rule that denies the
// outbound JNDI callback (LDAP/RMI) mitigates exploitation.
//
// Rule syntax (candidate.rule):  <action> <proto> <src> -> <dst>[:<port|lo-hi|*>]
//   deny  tcp any        -> any:1389
//   deny  tcp any        -> 10.0.0.0/24:1389-1400
//   allow tcp 10.0.0.0/8 -> any:443

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
	portLo, portHi int // 0,0 = any
}

func compileFirewallRule(c CandidateSpec) (*fwRule, error) {
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
	if !(r.portLo == 0 && r.portHi == 0) {
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
