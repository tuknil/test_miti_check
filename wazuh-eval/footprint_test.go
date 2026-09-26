package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// summarize returns "source|summary" lines for readable assertions.
func footprintLines(t *testing.T, cmd string) []TelemetryEvent {
	t.Helper()
	events, err := CommandTelemetryFootprint(CommandInput{Command: cmd, User: "root"})
	if err != nil {
		t.Fatal(err)
	}
	return events
}

// adduser expands to its own execve, a useradd child, and account-file FIM events.
func TestFootprintAdduser(t *testing.T) {
	events := footprintLines(t, "adduser niloy")
	var execCount, fimCount int
	sawUseradd, sawPasswd, sawShadow, sawHome := false, false, false, false
	for _, e := range events {
		switch e.Source {
		case sourceExecve:
			execCount++
			if strings.Contains(e.Summary, "useradd") || strings.Contains(e.Summary, "spawned") {
				sawUseradd = true
			}
		case sourceFIM:
			fimCount++
			if strings.Contains(e.Summary, "/etc/passwd") {
				sawPasswd = true
			}
			if strings.Contains(e.Summary, "/etc/shadow") {
				sawShadow = true
			}
			if strings.Contains(e.Summary, "/home/niloy") {
				sawHome = true
			}
		}
	}
	if execCount < 2 || !sawUseradd {
		t.Fatalf("expected adduser + useradd execve events; got %d execs, sawUseradd=%v", execCount, sawUseradd)
	}
	if !sawPasswd || !sawShadow || !sawHome || fimCount < 4 {
		t.Fatalf("missing FIM events: passwd=%v shadow=%v home=%v count=%d", sawPasswd, sawShadow, sawHome, fimCount)
	}
	// Each event must be valid Wazuh telemetry (parseable, non-empty).
	for _, e := range events {
		var m map[string]any
		if err := json.Unmarshal(e.Event, &m); err != nil {
			t.Fatalf("event not valid JSON (%s): %v", e.Summary, err)
		}
	}
}

// A file-reading command emits a file-access event for its path arg.
func TestFootprintFileRead(t *testing.T) {
	events := footprintLines(t, "cat /etc/shadow")
	sawAccess := false
	for _, e := range events {
		if e.Source == sourceFileAccess && strings.Contains(e.Summary, "/etc/shadow") {
			sawAccess = true
		}
	}
	if !sawAccess {
		t.Fatalf("expected a file-access event for /etc/shadow")
	}
}

// A pipeline decomposes into one execve per stage (children of the shell).
func TestFootprintPipeline(t *testing.T) {
	events := footprintLines(t, "cat /etc/passwd | grep root")
	execs := 0
	for _, e := range events {
		if e.Source == sourceExecve {
			execs++
		}
	}
	if execs < 2 { // cat, grep
		t.Fatalf("expected >=2 execve events for a pipeline, got %d", execs)
	}
}

// The decomposer handles arbitrary shell constructs without error, and resolves
// wrappers, redirections, substitutions, assignments, and builtins.
func TestFootprintHandlesArbitraryShell(t *testing.T) {
	cases := []string{
		"sudo useradd bob",
		"FOO=bar BAZ=1 /usr/bin/env python3 -c 'print(1)'",
		"nohup timeout 5s wget https://x/y -O /tmp/y &",
		"cat < /etc/passwd > /tmp/out 2> /tmp/err",
		"echo $(whoami) && ls -la /root || true",
		"( cd /tmp && rm -rf ./junk ); tar czf /tmp/a.tgz /var/log",
		"cd /tmp",                          // pure builtin
		"export PATH=/usr/local/bin:$PATH", // builtin + assignment
		"for f in *; do chmod 600 \"$f\"; done",
		"",         // empty
		"!@#$%^&*", // garbage — must not panic
	}
	for _, c := range cases {
		events, err := CommandTelemetryFootprint(CommandInput{Command: c, User: "root"})
		if err != nil {
			t.Fatalf("error on %q: %v", c, err)
		}
		if len(events) == 0 {
			t.Fatalf("no telemetry produced for %q (must never be empty)", c)
		}
	}
}

// sudo elevates the effective uid of the executed process.
func TestFootprintSudoElevates(t *testing.T) {
	events, _ := CommandTelemetryFootprint(CommandInput{Command: "sudo cat /etc/shadow", User: "analyst", UID: "1000"})
	found := false
	for _, e := range events {
		if e.Source != sourceExecve {
			continue
		}
		if strings.Contains(e.Summary, "cat") {
			found = true
			var ev map[string]any
			if err := json.Unmarshal(e.Event, &ev); err != nil {
				t.Fatal(err)
			}
			audit := ev["data"].(map[string]any)["audit"].(map[string]any)
			if audit["uid"] != "0" {
				t.Fatalf("expected uid 0 under sudo, got %v", audit["uid"])
			}
			if audit["exe"] != "/usr/bin/cat" {
				t.Fatalf("expected exe /usr/bin/cat after unwrapping sudo, got %v", audit["exe"])
			}
		}
	}
	if !found {
		t.Fatal("did not find the wrapped cat execve")
	}
}
