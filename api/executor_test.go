package main

import "testing"

func TestCompileRuleDecodesModSecurityQuotedRegex(t *testing.T) {
	candidate := CandidateSpec{
		Rule: `SecRule REQUEST_BODY "@rx person\\[0\\]\\[\\]=malicious" "id:1001,phase:2,deny,status:403"`,
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
		Rule: `SecRule REQUEST_BODY "@rx Researcher=' OR '1'='1" "id:1002,phase:2,deny,status:403"`,
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

func TestNamedArgumentTargetDoesNotMatchSerializedBody(t *testing.T) {
	candidate := CandidateSpec{
		Rule: `SecRule ARGS:Researcher "@rx Researcher=' OR '1'='1&action=saveUser" "id:1003,phase:2,deny,status:403"`,
	}
	rule, err := compileRule(candidate)
	if err != nil {
		t.Fatalf("compileRule: %v", err)
	}

	matched, _ := rule.evaluate(TestRequest{Body: `Researcher=' OR '1'='1&action=saveUser`})
	if matched {
		t.Fatal("ARGS:Researcher incorrectly matched the complete serialized body")
	}
}

func TestNamedArgumentTargetMatchesOnlyArgumentValue(t *testing.T) {
	candidate := CandidateSpec{
		Rule: `SecRule ARGS:Researcher "@rx ^' OR '1'='1$" "id:1004,phase:2,deny,status:403"`,
	}
	rule, err := compileRule(candidate)
	if err != nil {
		t.Fatalf("compileRule: %v", err)
	}

	matched, value := rule.evaluate(TestRequest{Body: `Researcher=%27+OR+%271%27%3D%271&action=saveUser`})
	if !matched {
		t.Fatal("ARGS:Researcher did not match its decoded argument value")
	}
	if value != `' OR '1'='1` {
		t.Fatalf("matched value = %q, want named argument value", value)
	}
}

func TestCompileRuleRejectsUnsupportedTarget(t *testing.T) {
	_, err := compileRule(CandidateSpec{Rule: `SecRule REMOTE_ADDR "@rx test" "deny"`})
	if err == nil {
		t.Fatal("unsupported target was accepted")
	}
}

func TestCombinedTargetsMatchAnySelectedCollection(t *testing.T) {
	candidate := CandidateSpec{
		Rule: `SecRule ARGS|REQUEST_HEADERS "@rx (?i)(?:^test$|injected-header)" "id:106841,phase:2,deny,status:403"`,
	}
	rule, err := compileRule(candidate)
	if err != nil {
		t.Fatalf("compileRule: %v", err)
	}

	tests := []struct {
		name    string
		request TestRequest
		matched bool
	}{
		{name: "form argument", request: TestRequest{Body: "username=test&password=benign"}, matched: true},
		{name: "request header", request: TestRequest{Body: "username=benign", Headers: map[string]string{"X-Test-Input": "injected-header"}}, matched: true},
		{name: "neither", request: TestRequest{Body: "username=benign", Headers: map[string]string{"X-Test-Input": "benign"}}, matched: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, _ := rule.evaluate(tt.request)
			if matched != tt.matched {
				t.Fatalf("matched = %t, want %t", matched, tt.matched)
			}
		})
	}
}

func TestArgumentCollectionDoesNotMatchSerializedFormBody(t *testing.T) {
	rule, err := compileRule(CandidateSpec{
		Rule: `SecRule ARGS|REQUEST_HEADERS "@rx username=test&password=attack" "deny,status:403"`,
	})
	if err != nil {
		t.Fatalf("compileRule: %v", err)
	}

	matched, _ := rule.evaluate(TestRequest{Body: "username=test&password=attack"})
	if matched {
		t.Fatal("ARGS incorrectly matched the complete serialized form body")
	}
}

func TestCombinedTargetsRejectUnsupportedOrMalformedComponents(t *testing.T) {
	for _, expression := range []string{
		"ARGS|REMOTE_ADDR",
		"ARGS:Researcher|REMOTE_ADDR",
		"ARGS|",
		"|ARGS",
		"ARGS||REQUEST_HEADERS",
		"ARGS:",
		"ARGS|!ARGS:csrf_token",
	} {
		t.Run(expression, func(t *testing.T) {
			_, err := compileRule(CandidateSpec{Rule: `SecRule ` + expression + ` "@rx test" "deny"`})
			if err == nil {
				t.Fatal("unsupported target expression was accepted")
			}
		})
	}
}

func TestTargetValuesAreDeterministicAndRetainDuplicates(t *testing.T) {
	request := TestRequest{
		Path:    "/probe?z=query&a=first",
		Body:    "z=body&a=second&a=attack",
		Headers: map[string]string{"Z-Header": "last", "A-Header": "first"},
	}

	values := targetValues([]string{"REQUEST_HEADERS", "ARGS"}, request)
	want := []string{"first", "last", "second", "attack", "first", "body", "query"}
	if len(values) != len(want) {
		t.Fatalf("values = %#v, want %#v", values, want)
	}
	for index := range want {
		if values[index] != want[index] {
			t.Fatalf("values = %#v, want %#v", values, want)
		}
	}
}
