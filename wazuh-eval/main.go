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
		rulePath      = fs.String("rule", "", "path to a Wazuh rule XML file (EDR-only, direct mode)")
		candidatePath = fs.String("candidate", "", "path to a defense-generation candidate/result JSON; routes to the EDR or WAF evaluator by candidate kind")
		eventPath     = fs.String("event", "", "path to the event JSON: decoded telemetry (EDR) or an HTTP request (WAF); default stdin")
		logLine       = fs.String("log", "", "raw log line to evaluate instead of a JSON event (EDR only)")
		cmdLine       = fs.String("cmd", "", "a Linux command to synthesize Wazuh auditd telemetry for (used as the event)")
		cmdUser       = fs.String("cmd-user", "root", "user for -cmd telemetry (best-effort uid mapping)")
		cmdHost       = fs.String("cmd-host", "linux-host", "agent/host name for -cmd telemetry")
		footprint     = fs.Bool("footprint", false, "with -cmd: print the full list of telemetry the command generates (execve + child processes + FIM)")
		ruleID        = fs.String("id", "", "evaluate only the rule with this id (default: all rules)")
		asJSON        = fs.Bool("json", false, "emit the result as JSON")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "wazuh-eval — evaluate an EDR (Wazuh) or WAF (ModSecurity) rule against an event.")
		fmt.Fprintln(stderr, "\nUsage:")
		fmt.Fprintln(stderr, "  # Candidate mode — auto-routes to EDR or WAF by candidate kind:")
		fmt.Fprintln(stderr, "  wazuh-eval -candidate candidate.json -event event.json")
		fmt.Fprintln(stderr, "  # EDR direct mode (Wazuh rule XML):")
		fmt.Fprintln(stderr, "  wazuh-eval -rule rules.xml -event telemetry.json")
		fmt.Fprintln(stderr, "  cat telemetry.json | wazuh-eval -rule rules.xml")
		fmt.Fprintln(stderr, "  # Synthesize Wazuh telemetry for a command (and optionally evaluate it):")
		fmt.Fprintln(stderr, "  wazuh-eval -cmd 'cat /etc/passwd'")
		fmt.Fprintln(stderr, "  wazuh-eval -rule rules.xml -cmd 'cat /etc/passwd'")
		fmt.Fprintln(stderr, "\nFlags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// -cmd synthesizes Wazuh auditd telemetry for a Linux command. With no rule or
	// candidate it just prints the telemetry (command → telemetry); with one it is
	// used as the event to evaluate (handled in the event-loading switch below).
	if *cmdLine != "" && *rulePath == "" && *candidatePath == "" {
		input := CommandInput{Command: *cmdLine, User: *cmdUser, Host: *cmdHost}
		if *footprint {
			events, terr := CommandTelemetryFootprint(input)
			if terr != nil {
				fmt.Fprintf(stderr, "error: %v\n", terr)
				return 2
			}
			return encodeJSON(stdout, stderr, events)
		}
		telemetry, terr := CommandToWazuhTelemetry(input)
		if terr != nil {
			fmt.Fprintf(stderr, "error: %v\n", terr)
			return 2
		}
		fmt.Fprintln(stdout, string(telemetry))
		return 0
	}
	if (*rulePath == "") == (*candidatePath == "") {
		fmt.Fprintln(stderr, "error: provide exactly one of -rule or -candidate (or -cmd alone to print telemetry)")
		fs.Usage()
		return 2
	}

	// Load the event bytes: -cmd wins, else -log, else -event file, else stdin.
	var eventBytes []byte
	var err error
	switch {
	case *cmdLine != "":
		eventBytes, err = CommandToWazuhTelemetry(CommandInput{Command: *cmdLine, User: *cmdUser, Host: *cmdHost})
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
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
			fmt.Fprintln(stderr, "error: no event provided (use -cmd, -event, -log, or pipe JSON to stdin)")
			fs.Usage()
			return 2
		}
	}

	// Candidate mode: classify the candidate and route to EDR or WAF.
	if *candidatePath != "" {
		candData, err := os.ReadFile(*candidatePath)
		if err != nil {
			fmt.Fprintf(stderr, "error: reading candidate file: %v\n", err)
			return 2
		}
		cand, err := LoadCandidate(candData)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		report, err := EvaluateCandidate(cand, eventBytes)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		if *asJSON {
			if code := encodeJSON(stdout, stderr, report); code != 0 {
				return code
			}
		} else {
			printCandidateReport(stdout, report)
		}
		if report.Matched {
			return 0
		}
		return 1
	}

	// EDR direct mode: a Wazuh rule XML file evaluated against telemetry.
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
	event := LoadEvent(eventBytes)

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
		payload := any(results)
		if len(results) == 1 {
			payload = results[0]
		}
		if code := encodeJSON(stdout, stderr, payload); code != 0 {
			return code
		}
	} else {
		printReport(stdout, results)
	}

	if anyMatch {
		return 0
	}
	return 1
}

// encodeJSON writes v as indented JSON, returning a nonzero exit code on failure.
func encodeJSON(stdout, stderr io.Writer, v any) int {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(stderr, "error: encoding JSON: %v\n", err)
		return 2
	}
	return 0
}

// printCandidateReport prints the control-class header and each rule's breakdown.
func printCandidateReport(w io.Writer, rep *CandidateReport) {
	verdict := "NO MATCH"
	if rep.Matched {
		verdict = "MATCH"
	}
	fmt.Fprintf(w, "Candidate %s [%s", firstNonEmpty(rep.CandidateID, "-"), strings.ToUpper(rep.ControlClass))
	if rep.CandidateKind != "" {
		fmt.Fprintf(w, "/%s", rep.CandidateKind)
	}
	fmt.Fprintf(w, "]: %s\n\n", verdict)
	printReport(w, rep.Results)
	for _, n := range rep.Notes {
		fmt.Fprintf(w, "· %s\n", n)
	}
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
