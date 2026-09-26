package main

import (
	"strings"
	"testing"
)

// A bare command yields decoded execve fields and a matching full_log.
func TestCommandToWazuhTelemetryBare(t *testing.T) {
	ev, err := CommandToWazuhEvent(CommandInput{Command: "cat /etc/passwd", User: "root", Host: "web01"})
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string]string{
		"data.audit.execve.a0":   "cat",
		"data.audit.execve.a1":   "/etc/passwd",
		"data.audit.execve.argc": "2",
		"data.audit.exe":         "/usr/bin/cat",
		"data.audit.comm":        "cat",
		"data.audit.syscall":     "59",
		"data.audit.uid":         "0",
		"data.audit.cwd":         "/root",
	}
	for k, want := range checks {
		if got, ok := ev.get(k); !ok || got != want {
			t.Errorf("%s = %q (present=%v), want %q", k, got, ok, want)
		}
	}
	if !strings.Contains(ev.FullLog, "type=EXECVE") || !strings.Contains(ev.FullLog, `a1="/etc/passwd"`) {
		t.Errorf("full_log missing EXECVE record:\n%s", ev.FullLog)
	}
	if !strings.Contains(ev.FullLog, "type=SYSCALL") || !strings.Contains(ev.FullLog, "type=PROCTITLE") {
		t.Errorf("full_log missing SYSCALL/PROCTITLE records")
	}
}

// A shell pipeline is recorded as a single /bin/sh -c execve (as the kernel does).
func TestCommandToWazuhTelemetryShellWrapping(t *testing.T) {
	ev, err := CommandToWazuhEvent(CommandInput{Command: "cat /etc/passwd | grep root"})
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := ev.get("data.audit.exe"); v != "/bin/sh" {
		t.Errorf("exe = %q, want /bin/sh", v)
	}
	if v, _ := ev.get("data.audit.execve.a1"); v != "-c" {
		t.Errorf("a1 = %q, want -c", v)
	}
	if v, _ := ev.get("data.audit.execve.a2"); v != "cat /etc/passwd | grep root" {
		t.Errorf("a2 = %q, want the full command", v)
	}
}

// Quoted arguments are tokenized correctly.
func TestShellSplitQuotes(t *testing.T) {
	got := shellSplit(`/usr/bin/curl -H "User-Agent: x y" 'http://a b/c'`)
	want := []string{"/usr/bin/curl", "-H", "User-Agent: x y", "http://a b/c"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("arg %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// End-to-end: synthesize telemetry for a command, then evaluate a Wazuh rule.
func TestCommandTelemetryFeedsEvaluator(t *testing.T) {
	rule := `
<group name="audit,">
  <rule id="80790" level="7">
    <decoded_as>auditd</decoded_as>
    <field name="audit.exe">/usr/bin/cat$</field>
    <field name="audit.execve.a1">/etc/passwd</field>
    <description>Sensitive file read via cat</description>
  </rule>
</group>`
	rules, err := ParseRules([]byte(rule))
	if err != nil {
		t.Fatal(err)
	}
	ev, err := CommandToWazuhEvent(CommandInput{Command: "cat /etc/passwd", User: "root"})
	if err != nil {
		t.Fatal(err)
	}
	res := Evaluate(rules[0], ev)
	if !res.Matched {
		t.Fatalf("expected rule to match synthesized telemetry: %+v", res.Conditions)
	}

	// A different command must not match.
	benign, _ := CommandToWazuhEvent(CommandInput{Command: "ls -la /tmp", User: "root"})
	if Evaluate(rules[0], benign).Matched {
		t.Fatalf("benign command should not match the /etc/passwd rule")
	}
}
