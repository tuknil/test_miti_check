package main

// wazuh-eval — evaluate a Wazuh EDR rule against a decoded telemetry event and
// report whether the rule's conditions match.
//
// Usage:
//
//	wazuh-eval -rule rules.xml -event event.json
//	wazuh-eval -rule rules.xml -log '<raw log line>'
//	cat event.json | wazuh-eval -rule rules.xml
//	wazuh-eval -rule rules.xml -event event.json -id 100002   # a specific rule
//	wazuh-eval -rule rules.xml -event event.json -json        # machine-readable
//
// Exit status: 0 if at least one evaluated rule matched, 1 if none matched,
// 2 on usage/parse error.

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Stdin))
}

func run(args []string, stdout, stderr io.Writer, stdin io.Reader) int {
	fs := flag.NewFlagSet("wazuh-eval", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		rulePath  = fs.String("rule", "", "path to Wazuh rule XML file (required)")
		eventPath = fs.String("event", "", "path to decoded telemetry JSON file (default: stdin)")
		logLine   = fs.String("log", "", "raw log line to evaluate instead of a JSON event")
		ruleID    = fs.String("id", "", "evaluate only the rule with this id (default: all rules in the file)")
		asJSON    = fs.Bool("json", false, "emit the result as JSON")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "wazuh-eval — evaluate a Wazuh rule against decoded telemetry.")
		fmt.Fprintln(stderr, "\nUsage:")
		fmt.Fprintln(stderr, "  wazuh-eval -rule rules.xml -event event.json")
		fmt.Fprintln(stderr, "  cat event.json | wazuh-eval -rule rules.xml")
		fmt.Fprintln(stderr, "  wazuh-eval -rule rules.xml -log '<raw log line>'")
		fmt.Fprintln(stderr, "\nFlags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *rulePath == "" {
		fmt.Fprintln(stderr, "error: -rule is required")
		fs.Usage()
		return 2
	}

	ruleData, err := os.ReadFile(*rulePath)
	if err != nil {
		fmt.Fprintf(stderr, "error: reading rule file: %v\n", err)
		return 2
	}
	rules, err := ParseRules(ruleData)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	// Load the event: -log wins, else -event file, else stdin.
	var eventBytes []byte
	switch {
	case *logLine != "":
		eventBytes = []byte(*logLine)
	case *eventPath != "":
		eventBytes, err = os.ReadFile(*eventPath)
		if err != nil {
			fmt.Fprintf(stderr, "error: reading event file: %v\n", err)
			return 2
		}
	default:
		eventBytes, err = io.ReadAll(stdin)
		if err != nil {
			fmt.Fprintf(stderr, "error: reading event from stdin: %v\n", err)
			return 2
		}
		if len(strings.TrimSpace(string(eventBytes))) == 0 {
			fmt.Fprintln(stderr, "error: no event provided (use -event, -log, or pipe JSON to stdin)")
			fs.Usage()
			return 2
		}
	}
	event := LoadEvent(eventBytes)

	// Select rules to evaluate.
	var selected []Rule
	for _, r := range rules {
		if *ruleID == "" || r.ID == *ruleID {
			selected = append(selected, r)
		}
	}
	if len(selected) == 0 {
		fmt.Fprintf(stderr, "error: no rule with id %q found in %s\n", *ruleID, *rulePath)
		return 2
	}

	results := make([]Result, 0, len(selected))
	anyMatch := false
	for _, r := range selected {
		res := Evaluate(r, event)
		results = append(results, res)
		if res.Matched {
			anyMatch = true
		}
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		payload := any(results)
		if len(results) == 1 {
			payload = results[0]
		}
		if err := enc.Encode(payload); err != nil {
			fmt.Fprintf(stderr, "error: encoding JSON: %v\n", err)
			return 2
		}
	} else {
		printReport(stdout, results)
	}

	if anyMatch {
		return 0
	}
	return 1
}

// printReport writes a human-readable per-condition breakdown.
func printReport(w io.Writer, results []Result) {
	for i, res := range results {
		if i > 0 {
			fmt.Fprintln(w)
		}
		verdict := "NO MATCH"
		if res.Matched {
			verdict = "MATCH"
		}
		fmt.Fprintf(w, "Rule %s", res.RuleID)
		if res.Level != "" {
			fmt.Fprintf(w, " (level %s)", res.Level)
		}
		fmt.Fprintf(w, ": %s\n", verdict)
		if res.Description != "" {
			fmt.Fprintf(w, "  description: %s\n", res.Description)
		}
		if len(res.Conditions) == 0 {
			fmt.Fprintln(w, "  (no per-event conditions; see notes)")
		}
		for _, c := range res.Conditions {
			mark := "✗"
			if c.Matched {
				mark = "✓"
			}
			neg := ""
			if c.Negate {
				neg = " (negated)"
			}
			fmt.Fprintf(w, "  %s %s%s ~ %q\n", mark, c.Kind, neg, c.Pattern)
			seen := c.Value
			if !c.Present {
				seen = "<field absent>"
			} else if seen == "" {
				seen = "<empty>"
			}
			fmt.Fprintf(w, "      field=%s value=%s\n", nonEmpty(c.Field, "-"), truncate(seen, 200))
			if c.Detail != "" {
				fmt.Fprintf(w, "      note: %s\n", c.Detail)
			}
		}
		for _, n := range res.Notes {
			fmt.Fprintf(w, "  · %s\n", n)
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func nonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
