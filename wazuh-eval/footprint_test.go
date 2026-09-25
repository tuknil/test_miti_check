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

// A pipeline expands into the shell plus each stage as a child process.
func TestFootprintPipeline(t *testing.T) {
	events := footprintLines(t, "cat /etc/passwd | grep root")
	execs := 0
	for _, e := range events {
		if e.Source == sourceExecve {
			execs++
		}
	}
	if execs < 3 { // sh -c, cat, grep
		t.Fatalf("expected >=3 execve events for a pipeline, got %d", execs)
	}
}
