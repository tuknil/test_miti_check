package main

import "testing"

func TestCompileRuleDecodesModSecurityQuotedRegex(t *testing.T) {
	candidate := CandidateSpec{
		Rule: `SecRule ARGS "@rx person\\[0\\]\\[\\]=malicious" "id:1001,phase:2,deny,status:403"`,
	}

	rule, err := compileRule(candidate)
	if err != nil {
		t.Fatalf("compileRule: %v", err)
	}

	matched, value := rule.evaluate(TestRequest{Body: `person[0][]=malicious`})
	if !matched {
		t.Fatal("escaped-bracket rule did not match the request body")
	}
	if value != `person[0][]=malicious` {
		t.Errorf("matched value = %q, want %q", value, `person[0][]=malicious`)
	}
	if rule.ruleID != "1001" {
		t.Errorf("rule ID = %q, want 1001", rule.ruleID)
	}
	if rule.status != 403 {
		t.Errorf("status = %d, want 403", rule.status)
	}
}

func TestExtractRxDecodesQuotedStringOnce(t *testing.T) {
	tests := []struct {
		name string
		rule string
		want string
	}{
		{
			name: "serialized backslashes",
			rule: `SecRule ARGS "@rx person\\[0\\]\\[\\]=malicious" "deny"`,
			want: `person\[0\]\[\]=malicious`,
		},
		{
			name: "existing regex escapes",
			rule: `SecRule ARGS "@rx \d+\s+\[" "deny"`,
			want: `\d+\s+\[`,
		},
		{
			name: "escaped quotes",
			rule: `SecRule ARGS "@rx value\"quoted\"" "deny"`,
			want: `value"quoted"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := extractRx(tt.rule)
			if !ok {
				t.Fatal("extractRx did not find the @rx operator")
			}
			if got != tt.want {
				t.Errorf("extractRx() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCompileRulePreservesSimpleSQLiPattern(t *testing.T) {
	candidate := CandidateSpec{
		Rule: `SecRule ARGS "@rx Researcher=' OR '1'='1" "id:1002,phase:2,deny,status:403"`,
	}

	rule, err := compileRule(candidate)
	if err != nil {
		t.Fatalf("compileRule: %v", err)
	}

	matched, _ := rule.evaluate(TestRequest{Body: `Researcher=' OR '1'='1`})
	if !matched {
		t.Fatal("simple SQL injection rule no longer matches")
	}
}
