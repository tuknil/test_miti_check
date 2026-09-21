package main

// rule.go models a Wazuh ruleset rule and parses it from the Wazuh XML format.
//
// A Wazuh rule is a set of conditions that are ALL AND-ed together — the rule
// "matches" an event only when every condition it declares is satisfied. This
// file captures the condition-bearing elements; evaluation lives in eval.go.

import (
	"encoding/xml"
	"fmt"
)

// Matcher is a single condition element with a text pattern and the two common
// attributes: negate ("yes" inverts the test) and type (overrides the matching
// engine, e.g. "pcre2", "osregex", "osmatch").
type Matcher struct {
	Negate string `xml:"negate,attr"`
	Type   string `xml:"type,attr"`
	Value  string `xml:",chardata"`
}

// Field matches a named decoded field (e.g. win.eventdata.image).
type Field struct {
	Name   string `xml:"name,attr"`
	Negate string `xml:"negate,attr"`
	Type   string `xml:"type,attr"`
	Value  string `xml:",chardata"`
}

// Rule is a Wazuh <rule>. Repeatable condition elements are slices; every one
// present must match (logical AND) for the rule to fire.
type Rule struct {
	ID        string `xml:"id,attr"`
	Level     string `xml:"level,attr"`
	Frequency string `xml:"frequency,attr"`
	Timeframe string `xml:"timeframe,attr"`
	Overwrite string `xml:"overwrite,attr"`

	// Correlation / hierarchy — not evaluable from a single event (see notes).
	IfSid        []string `xml:"if_sid"`
	IfGroup      []string `xml:"if_group"`
	IfMatchedSid []string `xml:"if_matched_sid"`
	IfMatchedGrp []string `xml:"if_matched_group"`
	SameSrcIP    *empty   `xml:"same_source_ip"`
	SameSrcIP2   *empty   `xml:"same_srcip"`
	SameUser     *empty   `xml:"same_user"`
	DifferentURL *empty   `xml:"different_url"`

	// Content conditions (evaluated against a single event).
	DecodedAs   []Matcher `xml:"decoded_as"`
	ProgramName []Matcher `xml:"program_name"`
	Match       []Matcher `xml:"match"`
	Regex       []Matcher `xml:"regex"`
	Pcre2       []Matcher `xml:"pcre2"`
	Fields      []Field   `xml:"field"`
	SrcIP       []Matcher `xml:"srcip"`
	DstIP       []Matcher `xml:"dstip"`
	SrcPort     []Matcher `xml:"srcport"`
	DstPort     []Matcher `xml:"dstport"`
	User        []Matcher `xml:"user"`
	SrcUser     []Matcher `xml:"srcuser"`
	DstUser     []Matcher `xml:"dstuser"`
	URL         []Matcher `xml:"url"`
	IDField     []Matcher `xml:"id"`
	Status      []Matcher `xml:"status"`
	Hostname    []Matcher `xml:"hostname"`
	ExtraData   []Matcher `xml:"extra_data"`
	SystemName  []Matcher `xml:"system_name"`
	Action      []Matcher `xml:"action"`
	Location    []Matcher `xml:"location"`
	Data        []Matcher `xml:"data"`
	Protocol    []Matcher `xml:"protocol"`

	// Metadata (not conditions).
	Description string   `xml:"description"`
	Options     []string `xml:"options"`
	Groups      string   `xml:"group"`
}

type empty struct{}

// ruleContainer captures a <group> (which nests rules and further groups) or a
// bare list of <rule>s. The parser wraps the input in a synthetic root so a file
// with a <group> root, a bare <rule>, or several rules all decode uniformly.
type ruleContainer struct {
	Rules  []Rule          `xml:"rule"`
	Groups []ruleContainer `xml:"group"`
}

// ParseRules parses Wazuh rule XML and returns every <rule> found, in order.
func ParseRules(data []byte) ([]Rule, error) {
	wrapped := append([]byte("<__wazuh_rules_root__>"), data...)
	wrapped = append(wrapped, []byte("</__wazuh_rules_root__>")...)

	var root ruleContainer
	if err := xml.Unmarshal(wrapped, &root); err != nil {
		return nil, fmt.Errorf("parse rule XML: %w", err)
	}

	var out []Rule
	var walk func(c ruleContainer)
	walk = func(c ruleContainer) {
		out = append(out, c.Rules...)
		for _, g := range c.Groups {
			walk(g)
		}
	}
	walk(root)
	if len(out) == 0 {
		return nil, fmt.Errorf("no <rule> found in input")
	}
	return out, nil
}
