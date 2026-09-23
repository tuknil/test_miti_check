package wazuh

import "testing"

// mustEval parses rules, selects the rule with id, loads the event, and evaluates.
func mustEval(t *testing.T, ruleXML, id, eventJSON string) Result {
	t.Helper()
	rules, err := ParseRules([]byte(ruleXML))
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	var rule *Rule
	for i := range rules {
		if rules[i].ID == id {
			rule = &rules[i]
			break
		}
	}
	if rule == nil {
		t.Fatalf("rule id %s not found", id)
	}
	ev := LoadEvent([]byte(eventJSON))
	return Evaluate(*rule, ev)
}

// Sysmon (Windows EventChannel) — process creation of powershell with encoded
// command. Rule matches on two decoded fields.
func TestSysmonEncodedPowerShell(t *testing.T) {
	rule := `
<group name="sysmon,">
  <rule id="100100" level="12">
    <field name="win.system.channel">^Microsoft-Windows-Sysmon</field>
    <field name="win.eventdata.image">\\powershell\.exe$</field>
    <field name="win.eventdata.commandLine">-enc|-EncodedCommand</field>
    <description>Encoded PowerShell via Sysmon</description>
  </rule>
</group>`
	event := `{
      "win": {
        "system": {"channel": "Microsoft-Windows-Sysmon/Operational", "eventID": "1"},
        "eventdata": {
          "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          "commandLine": "powershell.exe -enc SQBFAFgA"
        }
      }
    }`
	res := mustEval(t, rule, "100100", event)
	if !res.Matched {
		t.Fatalf("expected match, got NO MATCH: %+v", res.Conditions)
	}
}

// Negative sysmon: different image should not match.
func TestSysmonNoMatchImage(t *testing.T) {
	rule := `
<rule id="100101" level="12">
  <field name="win.eventdata.image">\\powershell\.exe$</field>
</rule>`
	event := `{"win":{"eventdata":{"image":"C:\\Windows\\System32\\cmd.exe"}}}`
	res := mustEval(t, rule, "100101", event)
	if res.Matched {
		t.Fatalf("expected NO MATCH for cmd.exe")
	}
}

// sshd failed login — classic full_log regex match with a srcip comparator.
func TestSSHFailedLogin(t *testing.T) {
	rule := `
<rule id="5710" level="5">
  <decoded_as>sshd</decoded_as>
  <match>Failed password</match>
  <srcip>10.0.0.0/8</srcip>
  <description>sshd: failed password</description>
</rule>`
	event := `{
      "decoder": {"name": "sshd"},
      "srcip": "10.4.5.6",
      "full_log": "Jan  1 00:00:00 host sshd[123]: Failed password for root from 10.4.5.6 port 22 ssh2"
    }`
	res := mustEval(t, rule, "5710", event)
	if !res.Matched {
		t.Fatalf("expected match: %+v", res.Conditions)
	}
}

// srcip CIDR miss: an out-of-range IP must fail.
func TestSrcIPCIDRMiss(t *testing.T) {
	rule := `<rule id="5711" level="5"><srcip>10.0.0.0/8</srcip></rule>`
	event := `{"srcip":"192.168.1.1"}`
	res := mustEval(t, rule, "5711", event)
	if res.Matched {
		t.Fatalf("expected NO MATCH for 192.168.1.1 vs 10.0.0.0/8")
	}
}

// FIM / syscheck — file added under a sensitive path.
func TestFIMSyscheck(t *testing.T) {
	rule := `
<rule id="100200" level="7">
  <field name="syscheck.path">^/etc/</field>
  <field name="syscheck.event">added|modified</field>
  <description>Change under /etc</description>
</rule>`
	event := `{"syscheck":{"path":"/etc/passwd","event":"modified","mode":"realtime"}}`
	res := mustEval(t, rule, "100200", event)
	if !res.Matched {
		t.Fatalf("expected match: %+v", res.Conditions)
	}
}

// negate: a field must NOT match a value.
func TestNegateField(t *testing.T) {
	rule := `
<rule id="100300" level="3">
  <field name="data.status" negate="yes">success</field>
</rule>`
	// status=failure -> negated "success" passes.
	fail := mustEval(t, rule, "100300", `{"data":{"status":"failure"}}`)
	if !fail.Matched {
		t.Fatalf("expected match when status != success")
	}
	// status=success -> negated "success" fails.
	ok := mustEval(t, rule, "100300", `{"data":{"status":"success"}}`)
	if ok.Matched {
		t.Fatalf("expected NO MATCH when status == success (negated)")
	}
}

// Raw log line (non-JSON) matched by <match>/<regex>.
func TestRawLogLine(t *testing.T) {
	rule := `
<rule id="100400" level="4">
  <match>authentication failure</match>
</rule>`
	rules, err := ParseRules([]byte(rule))
	if err != nil {
		t.Fatal(err)
	}
	ev := LoadEvent([]byte("pam_unix(sshd:auth): authentication failure; user=root"))
	res := Evaluate(rules[0], ev)
	if !res.Matched {
		t.Fatalf("expected match on raw log line")
	}
}

// osMatch anchors: '^' prefix and '$' suffix.
func TestOSMatchAnchors(t *testing.T) {
	if !osMatch("^Micro", "Microsoft") {
		t.Error("^Micro should prefix-match Microsoft")
	}
	if osMatch("^soft", "Microsoft") {
		t.Error("^soft should not prefix-match Microsoft")
	}
	if !osMatch("soft$", "Microsoft") {
		t.Error("soft$ should suffix-match Microsoft")
	}
	if !osMatch("cmd|powershell", "run powershell now") {
		t.Error("alternation should match powershell")
	}
}

// osRegex translation of \p (punctuation) and \d.
func TestOSRegexClasses(t *testing.T) {
	if ok, _ := osRegex(`\d\d\d`, "abc123"); !ok {
		t.Error(`\d\d\d should match 123`)
	}
	if ok, _ := osRegex(`user\p`, "user!"); !ok {
		t.Error(`\p should match punctuation`)
	}
}

// Correlation elements produce notes but do not fail an otherwise-matching rule.
func TestCorrelationNotes(t *testing.T) {
	rule := `
<rule id="100500" level="10" frequency="8" timeframe="120">
  <if_matched_sid>5710</if_matched_sid>
  <same_source_ip />
  <match>Failed password</match>
</rule>`
	event := `{"full_log":"Failed password for root"}`
	res := mustEval(t, rule, "100500", event)
	if !res.Matched {
		t.Fatalf("expected match on content condition despite correlation elements")
	}
	if len(res.Notes) == 0 {
		t.Fatalf("expected correlation notes")
	}
}
