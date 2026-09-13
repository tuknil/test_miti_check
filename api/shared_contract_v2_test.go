package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const sharedFixtureDir = "testdata/shared-attack-contracts-v2"

func loadSharedFixture(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(sharedFixtureDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func loadSharedMap(t *testing.T, name string) map[string]any {
	t.Helper()
	var value any
	if err := decodeStrictJSON(loadSharedFixture(t, name), &value); err != nil {
		t.Fatal(err)
	}
	result, ok := value.(map[string]any)
	if !ok {
		t.Fatal("fixture is not an object")
	}
	return result
}

func loadSharedSemantics(t *testing.T) (map[string]any, sharedSemantics) {
	t.Helper()
	cg := loadSharedMap(t, "check-generation-complete-result.json")
	semantics, err := validateSharedCGDocument(cg)
	if err != nil {
		t.Fatalf("validate authoritative CG fixture: %v", err)
	}
	return cg, semantics
}

func TestSharedContractCatalogAndFixtureProvenanceAreImmutable(t *testing.T) {
	if embeddedSharedCatalogErr != nil {
		t.Fatal(embeddedSharedCatalogErr)
	}
	if embeddedRouteProfileErr != nil {
		t.Fatal(embeddedRouteProfileErr)
	}
	var provenance struct {
		ManifestVersion  int               `json:"manifest_version"`
		SourceRepository string            `json:"source_repository"`
		SourceCommit     string            `json:"source_commit"`
		SourcePath       string            `json:"source_path"`
		ProducerCommits  map[string]string `json:"producer_commits"`
		Files            map[string]struct {
			SHA256     string `json:"sha256"`
			ByteLength int64  `json:"byte_length"`
		} `json:"files"`
		Models     bool `json:"models"`
		Network    bool `json:"network"`
		Databricks bool `json:"databricks"`
	}
	if err := decodeStrictJSON(loadSharedFixture(t, "provenance.json"), &provenance); err != nil {
		t.Fatal(err)
	}
	for name, expected := range provenance.Files {
		content := loadSharedFixture(t, name)
		if sha256Value(content) != expected.SHA256 || int64(len(content)) != expected.ByteLength {
			t.Fatalf("fixture %s differs from provenance", name)
		}
	}
}

func TestAuthoritativeCGAndCandidateFixturesPassPublishedSchemas(t *testing.T) {
	cg, _ := loadSharedSemantics(t)
	if cg["content_digest"] == nil {
		t.Fatal("authoritative fixture did not exercise outer content digest")
	}
	bundle := loadSharedMap(t, "waf-atomic-v2.candidate-bundle.json")
	if err := validateSharedSchema(candidateBundleSchemaID, bundle); err != nil {
		t.Fatalf("candidate schema: %v", err)
	}
}

func TestStrictJSONRejectsDuplicateKeysAndTrailingData(t *testing.T) {
	for _, content := range []string{`{"a":1,"a":2}`, `{"a":{"b":1,"b":2}}`, `{} {}`} {
		var value any
		if err := decodeStrictJSON([]byte(content), &value); err == nil {
			t.Fatalf("accepted malformed JSON %s", content)
		}
	}
}

func TestSharedCGRejectsDigestAncestryAssignmentAndPartitionTampering(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"content digest", func(cg map[string]any) { cg["content_digest"] = "sha256:" + strings.Repeat("0", 64) }},
		{"semantics digest", func(cg map[string]any) {
			delete(cg, "content_digest")
			delete(cg, "digest_profile")
			mapValue(cg["attack_match_semantics"])["semantics_digest"] = "sha256:" + strings.Repeat("0", 64)
		}},
		{"source projection", func(cg map[string]any) {
			delete(cg, "content_digest")
			delete(cg, "digest_profile")
			semantics := mapValue(cg["attack_match_semantics"])
			mapValue(mapValue(semantics["source_binding"])["check_generation"])["source_projection_digest"] = "sha256:" + strings.Repeat("0", 64)
			resignSemantics(t, semantics)
		}},
		{"member ancestry", func(cg map[string]any) {
			member := mapValue(anySlice(cg["member_results"])[0])
			member["signal_id"] = "invented"
			resignCG(t, cg)
		}},
		{"duplicate assignment", func(cg map[string]any) {
			semantics := mapValue(cg["attack_match_semantics"])
			obligation := mapValue(anySlice(semantics["obligations"])[0])
			refs := anySlice(obligation["required_input_refs"])
			obligation["required_input_refs"] = append(refs, refs[0])
			resignCG(t, cg)
		}},
		{"incomplete partition", func(cg map[string]any) {
			semantics := mapValue(cg["attack_match_semantics"])
			unsupported := anySlice(semantics["unsupported_dimensions"])
			semantics["unsupported_dimensions"] = unsupported[:2]
			resignCG(t, cg)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cg := loadSharedMap(t, "check-generation-complete-result.json")
			test.mutate(cg)
			if _, err := validateSharedCGDocument(cg); err == nil {
				t.Fatal("tampered CG document accepted")
			}
		})
	}
}

func resignSemantics(t *testing.T, semantics map[string]any) {
	t.Helper()
	preimage := cloneMap(semantics)
	delete(preimage, "semantics_digest")
	semantics["semantics_digest"] = digestAny(preimage)
}
func resignCG(t *testing.T, cg map[string]any) {
	t.Helper()
	delete(cg, "content_digest")
	delete(cg, "digest_profile")
	semantics := mapValue(cg["attack_match_semantics"])
	projection := map[string]any{}
	for _, key := range []string{"artifacts", "input_membership", "member_results", "test_inputs"} {
		projection[key] = cg[key]
	}
	mapValue(mapValue(semantics["source_binding"])["check_generation"])["source_projection_digest"] = digestAny(projection)
	resignSemantics(t, semantics)
}

func preparedArchitectureWAF(t *testing.T) (sharedCandidateBundle, sharedPreparedWAF) {
	t.Helper()
	bundleBytes := loadSharedFixture(t, "waf-atomic-v2.candidate-bundle.json")
	var bundle sharedCandidateBundle
	if err := json.Unmarshal(bundleBytes, &bundle); err != nil {
		t.Fatal(err)
	}
	contents := map[string][]byte{"artifact-main": loadSharedFixture(t, "waf-rule-main.json"), "artifact-carriers": loadSharedFixture(t, "waf-rule-carriers.json")}
	waf, applied, err := prepareSharedWAF(bundle, contents)
	if err != nil {
		t.Fatalf("prepare complete application unit: %v", err)
	}
	if !applied.ReadbackVerified || len(applied.ArtifactIDs) != 2 {
		t.Fatalf("application unit = %#v", applied)
	}
	return bundle, waf
}

func TestCompleteApplicationUnitExecutesEveryRequiredAssignment(t *testing.T) {
	cg, semantics := loadSharedSemantics(t)
	_, waf := preparedArchitectureWAF(t)
	inputs := map[string]sharedTestInput{}
	for _, input := range semantics.TestInputs {
		inputs[input.InputID] = input
	}
	count := 0
	for _, obligation := range semantics.Obligations {
		for _, ref := range obligation.RequiredInputRefs {
			result := executeSharedCase(context.Background(), "http://127.0.0.1:1", inputs[ref.ID], cg, sharedV2ProfileID, waf)
			if result.Disposition != "blocked" {
				t.Fatalf("%s/%s = %#v", obligation.ObligationID, ref.ID, result)
			}
			count++
		}
	}
	if count != 10 {
		t.Fatalf("disposed %d assignments, want 10", count)
	}
}

func TestApplicationUnitRejectsOmittedAndInventedArtifacts(t *testing.T) {
	bundle, _ := preparedArchitectureWAF(t)
	contents := map[string][]byte{"artifact-main": loadSharedFixture(t, "waf-rule-main.json")}
	if _, _, err := prepareSharedWAF(bundle, contents); err == nil {
		t.Fatal("omitted supporting artifact accepted")
	}
	contents["artifact-carriers"] = loadSharedFixture(t, "waf-rule-carriers.json")
	contents["invented"] = []byte(`{}`)
	if _, _, err := prepareSharedWAF(bundle, contents); err == nil {
		t.Fatal("invented artifact accepted")
	}
}

func validLocalBundle(t *testing.T) (map[string]any, sharedCandidateBundle, map[string][]byte, ImmutableResultLocator, map[string]any, sharedSemantics) {
	t.Helper()
	cg, semantics := loadSharedSemantics(t)
	check := ImmutableResultLocator{ResultRef: upstreamRef{Catalog: locatorCatalog, Schema: checkSchema, Table: checkTable, Key: "check-generation-result:test"}}
	cgBytes, _ := marshalRFC8785(cg)
	bundleDoc := loadSharedMap(t, "waf-atomic-v2.candidate-bundle.json")
	binding := mapValue(bundleDoc["semantics_binding"])
	binding["locator"] = map[string]any{"uri": "databricks-result:///36889_janus_dev/check_generation/check_generation_results/check-generation-result:test", "digest": sha256Value(cgBytes), "media_type": "application/json", "byte_length": len(cgBytes), "immutable": true}
	contents := map[string][]byte{}
	for _, name := range []string{"waf-rule-main.json", "waf-rule-carriers.json"} {
		var value any
		if err := decodeStrictJSON(loadSharedFixture(t, name), &value); err != nil {
			t.Fatal(err)
		}
		content, _ := marshalRFC8785(value)
		id := map[string]string{"waf-rule-main.json": "artifact-main", "waf-rule-carriers.json": "artifact-carriers"}[name]
		contents[id] = content
	}
	resultID := "defense-generation-result:test"
	artifacts := anySlice(mapValue(bundleDoc["primary_candidate"])["artifacts"])
	for _, raw := range artifacts {
		artifact := mapValue(raw)
		id := stringValue(artifact["artifact_id"])
		content := contents[id]
		artifact["content"] = map[string]any{"uri": "janus-result-internal:defense-generation-result%3Atest#/candidate_artifact_contents/" + id, "digest": sha256Value(content), "media_type": "application/json", "byte_length": len(content), "immutable": true}
	}
	resignBundle(bundleDoc)
	encoded, _ := json.Marshal(bundleDoc)
	var bundle sharedCandidateBundle
	if err := json.Unmarshal(encoded, &bundle); err != nil {
		t.Fatal(err)
	}
	if err := validateSharedBundle(bundleDoc, bundle, contents, resultID, check, cg, semantics); err != nil {
		t.Fatalf("valid local bundle: %v", err)
	}
	return bundleDoc, bundle, contents, check, cg, semantics
}

func resignBundle(bundle map[string]any) {
	candidate := mapValue(bundle["primary_candidate"])
	candidatePreimage := cloneMap(candidate)
	delete(candidatePreimage, "candidate_digest")
	candidate["candidate_digest"] = digestAny(candidatePreimage)
	bundlePreimage := cloneMap(bundle)
	delete(bundlePreimage, "bundle_digest")
	delete(mapValue(bundlePreimage["primary_candidate"]), "candidate_digest")
	bundle["bundle_digest"] = digestAny(bundlePreimage)
}

func TestCandidateBundleRejectsMappingsLocatorsAncestryAndApplicationTampering(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any, map[string][]byte)
	}{
		{"duplicate mapping", func(bundle map[string]any, _ map[string][]byte) {
			candidate := mapValue(bundle["primary_candidate"])
			mappings := anySlice(candidate["obligation_mappings"])
			candidate["obligation_mappings"] = append(mappings, mappings[0])
		}},
		{"mapping ancestry", func(bundle map[string]any, _ map[string][]byte) {
			mapping := mapValue(anySlice(mapValue(bundle["primary_candidate"])["obligation_mappings"])[0])
			refs := anySlice(mapping["source_member_refs"])
			mapping["source_member_refs"] = refs[:1]
		}},
		{"application omission", func(bundle map[string]any, _ map[string][]byte) {
			unit := mapValue(bundle["application_unit"])
			unit["artifact_refs"] = anySlice(unit["artifact_refs"])[:1]
		}},
		{"candidate locator", func(bundle map[string]any, _ map[string][]byte) {
			artifact := mapValue(anySlice(mapValue(bundle["primary_candidate"])["artifacts"])[0])
			mapValue(artifact["content"])["uri"] = "janus-result-internal:wrong#/candidate_artifact_contents/artifact-main"
		}},
		{"artifact bytes", func(_ map[string]any, contents map[string][]byte) {
			contents["artifact-main"] = []byte(`{"changed":true}`)
		}},
		{"semantics binding", func(bundle map[string]any, _ map[string][]byte) {
			mapValue(bundle["semantics_binding"])["semantics_digest"] = "sha256:" + strings.Repeat("0", 64)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bundleDoc, _, contents, check, cg, semantics := validLocalBundle(t)
			test.mutate(bundleDoc, contents)
			resignBundle(bundleDoc)
			encoded, _ := json.Marshal(bundleDoc)
			var bundle sharedCandidateBundle
			_ = json.Unmarshal(encoded, &bundle)
			if err := validateSharedBundle(bundleDoc, bundle, contents, "defense-generation-result:test", check, cg, semantics); err == nil {
				t.Fatal("tampered candidate bundle accepted")
			}
		})
	}
}

func TestRouteAdapterPreservesTemplateOwnedFieldsAndFailsClosed(t *testing.T) {
	var template sharedHTTPInput
	if err := json.Unmarshal(loadSharedFixture(t, "destination-free-http-request-template.json"), &template); err != nil {
		t.Fatal(err)
	}
	resolution, err := resolveSharedTemplate("input-http-template-42", template, sharedV2ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if resolution.TemplateID != "input-http-template-42" || resolution.PathKey != template.PathKey || resolution.ResolverProfileDigest != sharedV2ResolverProfileDigest || resolution.RenderedRequest.Scheme != "https" || resolution.RenderedRequest.Authority != "approved-mc-target.internal" || resolution.RenderedRequest.Path != "/inventory/items/42" {
		t.Fatalf("resolution = %#v", resolution)
	}
	if resolution.RenderedRequest.Method != template.Method || !equalHTTPFields(resolution.RenderedRequest.Query, template.Query) || !equalHTTPFields(resolution.RenderedRequest.Headers, template.Headers) || !equalHTTPFields(resolution.RenderedRequest.Cookies, template.Cookies) || resolution.RenderedRequest.Body != template.Body {
		t.Fatal("adapter changed template-owned fields")
	}
	mutated := resolution.RenderedRequest
	mutated.Headers = append([]sharedHTTPField(nil), mutated.Headers...)
	mutated.Headers[0].Value = "changed"
	if verifyTemplateOwnedFields(template, mutated) == nil {
		t.Fatal("changed template-owned header accepted")
	}
	changed := template
	changed.PathKey = "unknown"
	if _, err := resolveSharedTemplate("input", changed, sharedV2ProfileID); err == nil {
		t.Fatal("unknown path accepted")
	}
	if _, err := resolveSharedTemplate("input", template, "unknown@1"); err == nil {
		t.Fatal("unknown profile accepted")
	}
}

func TestHTTPAssignmentsPreserveNamedHeaderCookieMethodAndBodyStates(t *testing.T) {
	bodyContent := map[string]any{"payload": "attack"}
	enclosing := map[string]any{"result_id": "cg-result", "body": bodyContent, "raw_body": "raw-attack"}
	bodyBytes, _ := marshalRFC8785(bodyContent)
	present := sharedHTTPBody{State: "present", ContentLength: int64(len(bodyBytes)), Content: &sharedContentLocator{URI: "janus-result-internal:cg-result#/body", Digest: sha256Value(bodyBytes), MediaType: "application/json", ByteLength: int64(len(bodyBytes)), Immutable: true}}
	for _, body := range []sharedHTTPBody{{State: "absent"}, {State: "empty", ContentBase64: "", Digest: sha256Value(nil)}, present} {
		if _, err := resolveSharedBody(body, enclosing); err != nil {
			t.Fatalf("body %s: %v", body.State, err)
		}
	}
	rawBytes := []byte("raw-attack")
	raw := sharedHTTPBody{State: "present", ContentLength: int64(len(rawBytes)), Content: &sharedContentLocator{URI: "janus-result-internal:cg-result#/raw_body", Digest: sha256Value(rawBytes), MediaType: "text/plain", ByteLength: int64(len(rawBytes)), Immutable: true}}
	if resolved, err := resolveSharedBody(raw, enclosing); err != nil || string(resolved) != "raw-attack" {
		t.Fatalf("raw body changed: %q, %v", resolved, err)
	}
	rule := func(id, carrier, name, pattern string) sharedPreparedRule {
		return sharedPreparedRule{ID: id, Carrier: carrier, Name: name, Pattern: regexpMust(t, pattern)}
	}
	request := sharedHTTPInput{Method: "PATCH", Headers: []sharedHTTPField{{Name: "X-Exact-Name", Value: "header-value"}}, Cookies: []sharedHTTPField{{Name: "session", Value: "cookie-value"}}, Body: present}
	for _, candidate := range []sharedPreparedRule{rule("h", "header", "x-exact-name", "^header-value$"), rule("c", "cookie", "session", "^cookie-value$"), rule("m", "method", "", "^PATCH$"), rule("b", "body", "", "attack")} {
		waf := sharedPreparedWAF{rules: map[string]sharedPreparedRule{"component": candidate}, alternatives: [][]string{{"component"}}}
		matched, _, err := waf.evaluate(request, bodyBytes)
		if err != nil || !matched {
			t.Fatalf("carrier %s matched=%v err=%v", candidate.Carrier, matched, err)
		}
	}
}

func regexpMust(t *testing.T, pattern string) *regexp.Regexp {
	t.Helper()
	value, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestV2RequestIsCompactAndLegacyReplayRemainsValid(t *testing.T) {
	_, defense, check, _ := locatorFixture(t, false)
	check.ContractID = "check-generation@2.1"
	request := SubmitMitigationCheckRequest{ContractID: contractID, RequestID: "request", CorrelationID: defense.CorrelationID, RoutePolicy: sharedV2RoutePolicy, ProfileID: sharedV2ProfileID, DefenseResult: &defense, CheckResult: &check, ExecutionMode: execInMemory}
	if fields := validate(request); len(fields) != 0 {
		t.Fatalf("valid v2 request: %v", fields)
	}
	legacyCheck := check
	legacyCheck.ContractID = "check-generation-result@1.0"
	request.CheckResult = &legacyCheck
	if fields := validate(request); !hasField(fields, "check_result") {
		t.Fatalf("shared v2 request accepted legacy Check Generation locator: %v", fields)
	}
	request.CheckResult = &check
	request.TestBasis = json.RawMessage(`{}`)
	if fields := validate(request); !hasField(fields, "inline_content") {
		t.Fatalf("hydrated body accepted: %v", fields)
	}
	if fields := validate(validLifecycleRequest("legacy-v2-regression")); len(fields) != 0 {
		t.Fatalf("legacy replay changed: %v", fields)
	}
}

func TestCoverageAccountingRelationshipsAndDispositions(t *testing.T) {
	_, semantics := loadSharedSemantics(t)
	work := 0
	results := []ObligationResult{}
	for _, obligation := range semantics.Obligations {
		cases := []ObligationCaseResult{}
		for _, ref := range obligation.RequiredInputRefs {
			cases = append(cases, ObligationCaseResult{InputID: ref.ID, Disposition: "unsupported"})
			work++
		}
		results = append(results, ObligationResult{ObligationID: obligation.ObligationID, CaseResults: cases})
	}
	accounting := CoverageAccounting{RequiredObligationCount: len(semantics.Obligations), AccountedObligationCount: len(results), SourceMemberCount: len(semantics.SourceBinding.Members), RepresentedSourceMemberCount: 6, UnsupportedSourceMemberCount: 3, RequiredWorkItemCount: work, DisposedWorkItemCount: work}
	if accounting.RequiredObligationCount != accounting.AccountedObligationCount || accounting.SourceMemberCount != accounting.RepresentedSourceMemberCount+accounting.UnsupportedSourceMemberCount || accounting.RequiredWorkItemCount != accounting.DisposedWorkItemCount || work != 10 {
		t.Fatalf("accounting = %#v", accounting)
	}
	if err := validateSharedOutcomeAccounting(semantics, results, accounting); err != nil {
		t.Fatal(err)
	}
	badCounts := accounting
	badCounts.UnaccountedRequiredWorkItemCount = 1
	if validateSharedOutcomeAccounting(semantics, results, badCounts) == nil {
		t.Fatal("nonzero unaccounted count accepted")
	}
	omitted := append([]ObligationResult(nil), results...)
	omitted[0].CaseResults = omitted[0].CaseResults[1:]
	if validateSharedOutcomeAccounting(semantics, omitted, accounting) == nil {
		t.Fatal("omitted case accepted")
	}
	invented := append([]ObligationResult(nil), results...)
	invented[0].CaseResults = append([]ObligationCaseResult(nil), invented[0].CaseResults...)
	invented[0].CaseResults[0].InputID = "invented"
	if validateSharedOutcomeAccounting(semantics, invented, accounting) == nil {
		t.Fatal("invented case accepted")
	}
	duplicated := append(append([]ObligationResult(nil), results...), results[0])
	if validateSharedOutcomeAccounting(semantics, duplicated, accounting) == nil {
		t.Fatal("duplicate obligation accepted")
	}
}

func TestOpenAPIV2SchemaReferencesAreSynchronized(t *testing.T) {
	spec := string(openapiSpec)
	for _, required := range []string{"shared-attack-contracts-v2", "profile_id:", "obligation_results:", "CoverageAccounting:", "HttpRequestTemplateResolution:", "AppliedApplicationUnit:"} {
		if !strings.Contains(spec, required) {
			t.Fatalf("OpenAPI is missing %q", required)
		}
	}
	definitions := map[string]bool{}
	definitionPattern := regexp.MustCompile(`(?m)^    ([A-Za-z][A-Za-z0-9]*):\s*$`)
	for _, match := range definitionPattern.FindAllStringSubmatch(spec, -1) {
		definitions[match[1]] = true
	}
	referencePattern := regexp.MustCompile(`#/components/schemas/([A-Za-z][A-Za-z0-9]*)`)
	for _, match := range referencePattern.FindAllStringSubmatch(spec, -1) {
		if !definitions[match[1]] {
			t.Fatalf("OpenAPI reference %s has no schema definition", match[1])
		}
	}
}
