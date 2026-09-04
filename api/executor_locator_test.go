package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

type fakeLocatorSource struct {
	defense     []defenseRow
	check       []checkRow
	volumes     map[string][]byte
	volumePaths []string
}

func (f *fakeLocatorSource) Defense(context.Context, string) ([]defenseRow, error) {
	return f.defense, nil
}
func (f *fakeLocatorSource) Check(context.Context, string) ([]checkRow, error) { return f.check, nil }
func (f *fakeLocatorSource) Volume(_ context.Context, path string, _ int64) ([]byte, error) {
	f.volumePaths = append(f.volumePaths, path)
	content, ok := f.volumes[path]
	if !ok {
		return nil, context.Canceled
	}
	return content, nil
}

func locatorFixture(t *testing.T, volume bool) (*databricksLocatorResolver, ImmutableResultLocator, ImmutableResultLocator, *fakeLocatorSource) {
	t.Helper()
	created := "2026-09-03T12:00:00Z"
	correlation := "correlation-1"
	fixture, err := os.ReadFile("testdata/defense-generation-canonical-result.json")
	if err != nil {
		t.Fatal(err)
	}
	var defenseDocument defenseCanonicalResult
	if err := json.Unmarshal(fixture, &defenseDocument); err != nil {
		t.Fatal(err)
	}
	unsigned, err := json.Marshal(defenseDocument)
	if err != nil {
		t.Fatal(err)
	}
	defenseDocument.ContentSHA256, defenseDocument.SizeBytes = sha256Value(unsigned), int64(len(unsigned))
	defenseJSON, _ := json.Marshal(defenseDocument)
	defenseLocator := ImmutableResultLocator{Capability: capDefenseGeneration, ContractID: defenseDocument.ContractID, RequestID: defenseDocument.RequestID, CorrelationID: correlation, RunID: defenseDocument.RunID, ResultID: defenseDocument.ResultID, Status: defenseDocument.Status, TerminalState: defenseDocument.TerminalState, ResultRef: upstreamRef{System: "databricks", Catalog: locatorCatalog, Schema: defenseSchema, Table: defenseTable, Key: defenseDocument.ResultID}, ContentSHA256: defenseDocument.ContentSHA256, SizeBytes: defenseDocument.SizeBytes, CreatedAt: created}

	runResult := json.RawMessage(`{"contract_id":"check-generation@2.1","result_id":"nested","run_id":"cg-run","request_id":"cg-request","run_status":"completed","artifacts":[{"artifact_id":"network-artifact","artifact_kind":"mitigation-checkable-signal","mitigation_checkable_signal":{"candidate_family":"network-probe","stimulus":{"method":"POST","path_key":"ignored"}}},{"artifact_id":"check-artifact:http","artifact_kind":"mitigation-checkable-signal","mitigation_checkable_signal":{"candidate_family":"http-probe","stimulus":{"artifact_type":"http-probe","method":"POST","path_key":"flowise_custom_mcp_stdio_config","headers":{"Content-Type":"application/json"},"json_body":{"env":{"node_options":"--require control.js"}}}}}]}`)
	completion := map[string]any{
		"capability": capCheckGeneration, "contract_id": "capability-completion@1.0", "result_id": "check-generation-result:cg-run", "run_id": "cg-run", "request_id": "cg-request", "correlation_id": correlation, "terminal_state": "completed", "status": "completed", "result_ref": map[string]any{"system": "databricks", "catalog": locatorCatalog, "schema": checkSchema, "table": checkTable, "key": "check-generation-result:cg-run"}, "upstream_result_refs": []any{map[string]any{"capability": "vuln-research", "result_id": "vr-result"}}, "evidence_refs": []any{"evidence://sha256/3333333333333333333333333333333333333333333333333333333333333333"}, "subject_record_revision_id": "subject-1", "characterization_revision_id": "characterization-1", "result_contract_type": "check-generation-result", "result_contract_version": "1.0", "created_at": created,
	}
	core := map[string]any{}
	for _, key := range []string{"capability", "result_id", "run_id", "request_id", "correlation_id", "terminal_state", "status", "upstream_result_refs", "evidence_refs", "subject_record_revision_id", "characterization_revision_id", "created_at"} {
		core[key] = completion[key]
	}
	core["contract_id"] = "check-generation-result@1.0"
	var nested any
	if err := decodeJSONAny(runResult, &nested); err != nil {
		t.Fatal(err)
	}
	core["run_result"] = nested
	logical, _ := marshalRFC8785(core)
	checkLocator := ImmutableResultLocator{Capability: capCheckGeneration, ContractID: "check-generation-result@1.0", RequestID: "cg-request", CorrelationID: correlation, RunID: "cg-run", ResultID: "check-generation-result:cg-run", Status: "completed", TerminalState: "completed", ResultRef: upstreamRef{System: "databricks", Catalog: locatorCatalog, Schema: checkSchema, Table: checkTable, Key: "check-generation-result:cg-run"}, ContentSHA256: sha256Value(logical), SizeBytes: int64(len(logical)), CreatedAt: created}
	completion["content_sha256"] = checkLocator.ContentSHA256
	completion["size_bytes"] = checkLocator.SizeBytes
	storedPayload, _ := marshalSortedJSON(map[string]any{"contract_type": "check-generation-persisted-result", "contract_version": "1.0", "result_id": checkLocator.ResultID, "run_result": nested})
	storedResult := storedPayload
	volumes := map[string][]byte{}
	if volume {
		digest := strings.TrimPrefix(sha256Value(storedPayload), "sha256:")
		manifest := map[string]any{"contract_type": "janus-volume-payload-manifest", "contract_version": "1.0", "reference": "payload://sha256/" + digest, "media_type": "application/json", "encoding": "identity", "content_sha256": "sha256:" + digest, "size_bytes": len(storedPayload), "volume": map[string]any{"catalog": locatorCatalog, "schema": checkSchema, "name": checkPayloadVolume}}
		storedResult, _ = marshalSortedJSON(manifest)
		path := "/Volumes/" + locatorCatalog + "/" + checkSchema + "/" + checkPayloadVolume + "/sha256/" + digest[:2] + "/" + digest[2:4] + "/" + digest
		volumes[path] = storedPayload
	}
	completionJSON, _ := marshalSortedJSON(completion)
	source := &fakeLocatorSource{defense: []defenseRow{{RunID: defenseLocator.RunID, ResultID: defenseLocator.ResultID, TerminalState: defenseLocator.TerminalState, ResultJSON: string(defenseJSON)}}, check: []checkRow{{ResultID: checkLocator.ResultID, RunID: checkLocator.RunID, RequestID: checkLocator.RequestID, CorrelationID: correlation, Capability: capCheckGeneration, TerminalState: "completed", Status: "completed", ResultJSON: string(storedResult), CompletionJSON: string(completionJSON), ResultSHA256: sha256Value(storedResult), ResultSizeBytes: int64(len(storedResult)), CreatedAt: created}}, volumes: volumes}
	return &databricksLocatorResolver{source: source}, defenseLocator, checkLocator, source
}

func TestLocatorResolutionHydratesVolumeAndUsesRegisteredHTTPSelection(t *testing.T) {
	resolver, defense, check, source := locatorFixture(t, true)
	resolved, err := resolver.Resolve(context.Background(), defense, check, "check-artifact:http")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(source.volumePaths) != 1 || !strings.HasPrefix(source.volumePaths[0], "/Volumes/36889_janus_dev/check_generation/payloads/sha256/") {
		t.Fatalf("Volume paths = %v", source.volumePaths)
	}
	if resolved.Candidate.RuleID != "candidate-1" || resolved.Provenance.SelectedTestBasisID != "check-artifact:http" {
		t.Fatalf("resolved provenance = %+v candidate=%+v", resolved.Provenance, resolved.Candidate)
	}
	if resolved.TestBasis.Request.Path != "/" || !strings.Contains(resolved.TestBasis.Request.Body, "node_options") || resolved.TestBasis.ProofBasis != "mitigation-discriminator" {
		t.Fatalf("test basis = %+v", resolved.TestBasis)
	}
	if resolved.Provenance.DefenseResult.ResultID != defense.ResultID || resolved.Provenance.CheckResult.ResultID != check.ResultID {
		t.Fatal("both verified locators were not retained")
	}
	if len(resolved.EvidenceRefs) != 3 {
		t.Fatalf("verified evidence lineage = %v", resolved.EvidenceRefs)
	}
}

func TestRFC8785LogicalCanonicalizationNormalizesNumbersAndStrings(t *testing.T) {
	var value any
	if err := decodeJSONAny([]byte(`{"whole":1.0,"small":0.0000001,"body":"a&b"}`), &value); err != nil {
		t.Fatal(err)
	}
	encoded, err := marshalRFC8785(value)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(encoded), `{"body":"a&b","small":1e-7,"whole":1}`; got != want {
		t.Fatalf("canonical JSON = %s, want %s", got, want)
	}
}

func TestLocatorResolutionRejectsTamperingAndNonUniqueRows(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fakeLocatorSource, *ImmutableResultLocator)
	}{
		{"defense logical tamper", func(source *fakeLocatorSource, _ *ImmutableResultLocator) {
			source.defense[0].ResultJSON = strings.Replace(source.defense[0].ResultJSON, "@rx attack", "@rx changed", 1)
		}},
		{"check physical tamper", func(source *fakeLocatorSource, _ *ImmutableResultLocator) {
			source.check[0].ResultJSON = strings.Replace(source.check[0].ResultJSON, "check-generation-persisted-result", "tampered-result", 1)
		}},
		{"check logical locator tamper", func(_ *fakeLocatorSource, locator *ImmutableResultLocator) {
			locator.ContentSHA256 = "sha256:" + strings.Repeat("0", 64)
		}},
		{"duplicate defense rows", func(source *fakeLocatorSource, _ *ImmutableResultLocator) {
			source.defense = append(source.defense, source.defense[0])
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver, defense, check, source := locatorFixture(t, false)
			test.mutate(source, &check)
			_, err := resolver.Resolve(context.Background(), defense, check, "")
			if err == nil {
				t.Fatal("tampered/non-unique input was accepted")
			}
		})
	}
}

func TestLocatorResolutionRejectsVolumePayloadTamper(t *testing.T) {
	resolver, defense, check, source := locatorFixture(t, true)
	for path, content := range source.volumes {
		mutated := append([]byte(nil), content...)
		mutated[len(mutated)-1] ^= 1
		source.volumes[path] = mutated
	}
	if _, err := resolver.Resolve(context.Background(), defense, check, ""); err == nil || !strings.Contains(err.Error(), "Volume payload integrity") {
		t.Fatalf("Volume tamper error = %v", err)
	}
}

func TestReferenceOnlyValidationIsStrictAndLegacyInlineRemainsValid(t *testing.T) {
	resolver, defense, check, _ := locatorFixture(t, false)
	_ = resolver
	reference := SubmitMitigationCheckRequest{ContractID: contractID, RequestID: "mc-request", CorrelationID: "correlation-1", RoutePolicy: locatorRoutePolicy, DefenseResult: &defense, CheckResult: &check, TestBasisID: "check-artifact:http", ExecutionMode: execInMemory}
	if fields := validate(reference); len(fields) != 0 {
		t.Fatalf("valid locator request fields=%v", fields)
	}
	reference.CandidateArtifactID = "caller-content-not-allowed"
	if fields := validate(reference); !hasField(fields, "candidate_artifact_id") {
		t.Fatalf("mixed locator/inline request accepted: %v", fields)
	}
	if fields := validate(validLifecycleRequest("legacy-inline")); len(fields) != 0 {
		t.Fatalf("legacy inline request rejected: %v", fields)
	}
}

func TestLocatorSelectionRequiresExactEligibleArtifactID(t *testing.T) {
	resolver, defense, check, _ := locatorFixture(t, false)
	if _, err := resolver.Resolve(context.Background(), defense, check, "network-artifact"); err == nil || !strings.Contains(err.Error(), "not an eligible HTTP mitigation artifact") {
		t.Fatalf("ineligible selection error = %v", err)
	}
	if _, err := resolver.Resolve(context.Background(), defense, check, "missing-artifact"); err == nil || !strings.Contains(err.Error(), "not an eligible HTTP mitigation artifact") {
		t.Fatalf("missing selection error = %v", err)
	}
}

func TestDefenseArtifactHashMustMatchContent(t *testing.T) {
	resolver, defense, check, source := locatorFixture(t, false)
	var document defenseCanonicalResult
	if err := json.Unmarshal([]byte(source.defense[0].ResultJSON), &document); err != nil {
		t.Fatal(err)
	}
	document.PrimaryCandidate.ArtifactHash = "sha256:" + strings.Repeat("0", 64)
	document.ContentSHA256, document.SizeBytes = "", 0
	unsigned, _ := json.Marshal(document)
	document.ContentSHA256, document.SizeBytes = sha256Value(unsigned), int64(len(unsigned))
	defense.ContentSHA256, defense.SizeBytes = document.ContentSHA256, document.SizeBytes
	encoded, _ := json.Marshal(document)
	source.defense[0].ResultJSON = string(encoded)
	if _, err := resolver.Resolve(context.Background(), defense, check, ""); err == nil || !strings.Contains(err.Error(), "artifact_hash") {
		t.Fatalf("artifact hash error = %v", err)
	}
}

func TestCheckWrapperAndCompletionContractsAreStrict(t *testing.T) {
	t.Run("wrapper identity", func(t *testing.T) {
		resolver, defense, check, source := locatorFixture(t, false)
		source.check[0].ResultJSON = strings.Replace(source.check[0].ResultJSON, `"contract_version":"1.0"`, `"contract_version":"2.0"`, 1)
		source.check[0].ResultSHA256 = sha256Value([]byte(source.check[0].ResultJSON))
		source.check[0].ResultSizeBytes = int64(len(source.check[0].ResultJSON))
		if _, err := resolver.Resolve(context.Background(), defense, check, ""); err == nil || !strings.Contains(err.Error(), "wrapper identity") {
			t.Fatalf("wrapper error = %v", err)
		}
	})
	t.Run("completion contract", func(t *testing.T) {
		resolver, defense, check, source := locatorFixture(t, false)
		source.check[0].CompletionJSON = strings.Replace(source.check[0].CompletionJSON, `"result_contract_version":"1.0"`, `"result_contract_version":"2.0"`, 1)
		if _, err := resolver.Resolve(context.Background(), defense, check, ""); err == nil || !strings.Contains(err.Error(), "completion identity") {
			t.Fatalf("completion error = %v", err)
		}
	})
}

func TestCompatibilityDispatchPreservesInlineRequestWhenUpstreamModeEnabled(t *testing.T) {
	previous := upstreamInputMode
	upstreamInputMode = true
	t.Cleanup(func() { upstreamInputMode = previous })
	out := executeRequestedScenario(context.Background(), validLifecycleRequest("compat-inline"), "run-inline", "result-inline")
	if strings.Contains(out.Actual.Detail, "Databricks") {
		t.Fatalf("inline request was sent to upstream resolver: %+v", out)
	}
}

func TestLocatorSQLContextIsBounded(t *testing.T) {
	ctx, cancel := locatorSQLContext(context.Background())
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > locatorSQLTimeout {
		t.Fatalf("locator SQL deadline = %v, present=%t", deadline, ok)
	}
}

func TestInlineExecutionDoesNotInitializeLocatorDatabricks(t *testing.T) {
	previous := newLocatorInputResolver
	called := false
	newLocatorInputResolver = func() (locatorInputResolver, error) { called = true; return nil, context.Canceled }
	t.Cleanup(func() { newLocatorInputResolver = previous })
	req := validLifecycleRequest("inline-local")
	out := executeScenario(context.Background(), req, "run-inline", "result-inline")
	if called {
		t.Fatal("inline execution initialized locator Databricks")
	}
	if out.TerminalState == stateCouldNotTest && strings.Contains(out.Actual.Detail, "Databricks") {
		t.Fatalf("inline execution depended on Databricks: %+v", out)
	}
}
