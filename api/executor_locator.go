package main

// executor_locator.go implements the additive reference-only input contract. It
// resolves two immutable, allowlisted producer rows and hydrates the existing
// executor only after verifying physical storage and logical producer integrity.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	locatorRoutePolicy        = "registered-waf-route-v1"
	locatorCatalog            = "36889_janus_dev"
	defenseSchema             = "defense_generation"
	defenseTable              = "defense_generation_results"
	checkSchema               = "check_generation"
	checkTable                = "check_generation_results"
	checkPayloadVolume        = "payloads"
	maxLocatorPayloadBytes    = 200 << 20
	locatorDatabricksTimeout  = 30 * time.Second
	maxStatementResponseBytes = 4 << 20
)

type ImmutableResultLocator struct {
	Capability    string      `json:"capability"`
	ContractID    string      `json:"contract_id"`
	RequestID     string      `json:"request_id"`
	CorrelationID string      `json:"correlation_id"`
	RunID         string      `json:"run_id"`
	ResultID      string      `json:"result_id"`
	Status        string      `json:"status"`
	TerminalState string      `json:"terminal_state"`
	ResultRef     upstreamRef `json:"result_ref"`
	ContentSHA256 string      `json:"content_sha256"`
	SizeBytes     int64       `json:"size_bytes"`
	CreatedAt     string      `json:"created_at"`
}

type LocatorProvenance struct {
	RoutePolicy         string                 `json:"route_policy"`
	DefenseResult       ImmutableResultLocator `json:"defense_result"`
	CheckResult         ImmutableResultLocator `json:"check_result"`
	SelectedTestBasisID string                 `json:"selected_test_basis_id,omitempty"`
	Verification        string                 `json:"verification"`
}

type resolvedLocatorInputs struct {
	Candidate    CandidateSpec
	TestBasis    TestBasisSpec
	Provenance   LocatorProvenance
	EvidenceRefs []string
}

type locatorInputResolver interface {
	Resolve(context.Context, ImmutableResultLocator, ImmutableResultLocator, string) (resolvedLocatorInputs, error)
	Close() error
}

var newLocatorInputResolver = func() (locatorInputResolver, error) {
	return newDatabricksLocatorResolverFromEnv()
}

func locatorMode(req SubmitMitigationCheckRequest) bool {
	return req.DefenseResult != nil || req.CheckResult != nil || strings.TrimSpace(req.RoutePolicy) != ""
}

func validateLocatorRequest(req SubmitMitigationCheckRequest) []string {
	var bad []string
	if req.RoutePolicy != locatorRoutePolicy {
		bad = append(bad, "route_policy")
	}
	if req.DefenseResult == nil {
		bad = append(bad, "defense_result")
	} else if err := validateImmutableLocator(*req.DefenseResult, capDefenseGeneration); err != nil {
		bad = append(bad, "defense_result")
	}
	if req.CheckResult == nil {
		bad = append(bad, "check_result")
	} else if err := validateImmutableLocator(*req.CheckResult, capCheckGeneration); err != nil {
		bad = append(bad, "check_result")
	}
	if req.DefenseResult != nil && req.CheckResult != nil && req.DefenseResult.CorrelationID != req.CheckResult.CorrelationID {
		bad = append(bad, "check_result.correlation_id")
	}
	if req.DefenseResult != nil && req.DefenseResult.CorrelationID != req.CorrelationID {
		bad = append(bad, "defense_result.correlation_id")
	}
	// Reference-only means no caller-supplied executable or derived content.
	if req.CandidateArtifactID != "" {
		bad = append(bad, "candidate_artifact_id")
	}
	if req.CheckProfileID != "" {
		bad = append(bad, "check_profile_id")
	}
	if req.ProfileID != "" {
		bad = append(bad, "profile_id")
	}
	if req.SubstrateSelector != "" {
		bad = append(bad, "substrate_selector")
	}
	if len(req.Substrate) > 0 {
		bad = append(bad, "substrate")
	}
	if len(req.Candidate) > 0 {
		bad = append(bad, "candidate")
	}
	if len(req.TestBasis) > 0 {
		bad = append(bad, "test_basis")
	}
	if len(req.UpstreamInputs) > 0 {
		bad = append(bad, "upstream_inputs")
	}
	if len(req.PrimaryCandidateRaw) > 0 || len(req.AttemptHistory) > 0 || len(req.OutcomeReason) > 0 || len(req.ProofHandoffs) > 0 || len(req.UpstreamResultRef) > 0 || req.ProducedAt != "" || req.UpstreamProse != "" || req.UpstreamResultID != "" || req.UpstreamTerminal != "" {
		bad = append(bad, "inline_upstream_content")
	}
	if req.ExecutionMode != "" && req.ExecutionMode != execInMemory {
		bad = append(bad, "execution_mode")
	}
	return bad
}

func validateImmutableLocator(locator ImmutableResultLocator, capability string) error {
	contract, schema, table, terminal := "", "", "", ""
	switch capability {
	case capDefenseGeneration:
		contract, schema, table, terminal = "defense-generation-result@1.0", defenseSchema, defenseTable, "candidate-produced"
	case capCheckGeneration:
		contract, schema, table, terminal = "check-generation-result@1.0", checkSchema, checkTable, "completed"
	default:
		return fmt.Errorf("unsupported capability")
	}
	if locator.Capability != capability || locator.ContractID != contract || locator.RequestID == "" || locator.CorrelationID == "" || locator.RunID == "" || locator.ResultID == "" || locator.Status != "completed" || locator.TerminalState != terminal {
		return fmt.Errorf("locator identity is invalid")
	}
	if capability == capDefenseGeneration && !strings.HasPrefix(locator.ResultID, "defense-generation-result:") {
		return fmt.Errorf("Defense Generation result_id is invalid")
	}
	if capability == capCheckGeneration && locator.ResultID != "check-generation-result:"+locator.RunID {
		return fmt.Errorf("Check Generation result_id does not derive from run_id")
	}
	ref := locator.ResultRef
	if ref.System != "databricks" || ref.Catalog != locatorCatalog || ref.Schema != schema || ref.Table != table || ref.Key != locator.ResultID {
		return fmt.Errorf("locator result_ref is not allowlisted")
	}
	if !validSHA256(locator.ContentSHA256) || locator.SizeBytes < 1 || locator.SizeBytes > maxLocatorPayloadBytes {
		return fmt.Errorf("locator integrity metadata is invalid")
	}
	if parsed, err := time.Parse(time.RFC3339Nano, locator.CreatedAt); err != nil || parsed.IsZero() {
		return fmt.Errorf("locator created_at is invalid")
	}
	return nil
}

func validSHA256(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && value == strings.ToLower(value)
}

func executeScenarioByLocator(ctx context.Context, req SubmitMitigationCheckRequest, runID, resultID string) RunOutcome {
	base := RunOutcome{RunID: runID, ResultID: resultID}
	resolver, err := newLocatorInputResolver()
	if err != nil {
		return couldNotTest(base, "reference-only input resolver: "+err.Error())
	}
	defer resolver.Close()
	resolved, err := resolver.Resolve(ctx, *req.DefenseResult, *req.CheckResult, strings.TrimSpace(req.TestBasisID))
	if err != nil {
		return couldNotTest(base, "reference-only input resolution failed: "+err.Error())
	}
	req.ExecutionMode = execInMemory
	req.CandidateArtifactID = resolved.Candidate.RuleID
	req.TestBasisID = resolved.Provenance.SelectedTestBasisID
	req.CheckProfileID = "mitigation-check-profile:waf-http:1"
	req.Candidate, _ = json.Marshal(resolved.Candidate)
	req.TestBasis, _ = json.Marshal(resolved.TestBasis)
	out := executeScenario(ctx, req, runID, resultID)
	out.InputProvenance = &resolved.Provenance
	out.EvidenceRefs = append([]string(nil), resolved.EvidenceRefs...)
	out.Steps = append([]string{"verified immutable Defense Generation and Check Generation locators", "hydrated registered WAF candidate and HTTP mitigation test basis"}, out.Steps...)
	return out
}

type locatorRowSource interface {
	Defense(context.Context, string) ([]defenseRow, error)
	Check(context.Context, string) ([]checkRow, error)
	Volume(context.Context, string, int64) ([]byte, error)
}

type databricksLocatorResolver struct {
	source locatorRowSource
	closer io.Closer
}

func newDatabricksLocatorResolverFromEnv() (*databricksLocatorResolver, error) {
	config, err := locatorDatabricksConfigFromEnv()
	if err != nil {
		return nil, err
	}
	source := newStatementLocatorRowSource(config, nil)
	return &databricksLocatorResolver{source: source}, nil
}

func (r *databricksLocatorResolver) Close() error {
	if r == nil || r.closer == nil {
		return nil
	}
	return r.closer.Close()
}

func (r *databricksLocatorResolver) Resolve(ctx context.Context, defense, check ImmutableResultLocator, selectedTestBasisID string) (resolvedLocatorInputs, error) {
	if err := validateImmutableLocator(defense, capDefenseGeneration); err != nil {
		return resolvedLocatorInputs{}, fmt.Errorf("defense_result: %w", err)
	}
	if err := validateImmutableLocator(check, capCheckGeneration); err != nil {
		return resolvedLocatorInputs{}, fmt.Errorf("check_result: %w", err)
	}
	if defense.CorrelationID != check.CorrelationID {
		return resolvedLocatorInputs{}, fmt.Errorf("producer correlation identities differ")
	}
	defenseRows, err := r.source.Defense(ctx, defense.ResultID)
	if err != nil {
		return resolvedLocatorInputs{}, fmt.Errorf("query Defense Generation row: %w", err)
	}
	if len(defenseRows) != 1 {
		return resolvedLocatorInputs{}, fmt.Errorf("Defense Generation locator resolved %d rows, expected exactly one", len(defenseRows))
	}
	candidate, defenseEvidence, err := verifyDefenseRow(defenseRows[0], defense)
	if err != nil {
		return resolvedLocatorInputs{}, err
	}
	checkRows, err := r.source.Check(ctx, check.ResultID)
	if err != nil {
		return resolvedLocatorInputs{}, fmt.Errorf("query Check Generation row: %w", err)
	}
	if len(checkRows) != 1 {
		return resolvedLocatorInputs{}, fmt.Errorf("Check Generation locator resolved %d rows, expected exactly one", len(checkRows))
	}
	runResult, checkEvidence, err := r.verifyCheckRow(ctx, checkRows[0], check)
	if err != nil {
		return resolvedLocatorInputs{}, err
	}
	basisID, basis, err := selectRegisteredHTTPTestBasis(runResult, selectedTestBasisID)
	if err != nil {
		return resolvedLocatorInputs{}, err
	}
	return resolvedLocatorInputs{Candidate: candidate, TestBasis: basis, EvidenceRefs: stableStringUnion(defenseEvidence, checkEvidence), Provenance: LocatorProvenance{RoutePolicy: locatorRoutePolicy, DefenseResult: defense, CheckResult: check, SelectedTestBasisID: basisID, Verification: "physical-and-logical-sha256-verified"}}, nil
}

type defenseRow struct{ RunID, ResultID, TerminalState, ResultJSON string }
type checkRow struct {
	ResultID, RunID, RequestID, CorrelationID, Capability, TerminalState, Status, ResultJSON, CompletionJSON, ResultSHA256 string
	ResultSizeBytes                                                                                                        int64
	CreatedAt                                                                                                              string
}

type locatorDatabricksConfig struct {
	baseURL, token, warehouseID string
	timeout                     time.Duration
}

func locatorDatabricksConfigFromEnv() (locatorDatabricksConfig, error) {
	dsn := strings.TrimSpace(os.Getenv("DATABRICKS_DSN"))
	host := strings.TrimSpace(os.Getenv("DATABRICKS_HOST"))
	token := strings.TrimSpace(os.Getenv("DATABRICKS_TOKEN"))
	warehouseID := strings.TrimSpace(os.Getenv("DATABRICKS_WAREHOUSE_ID"))
	if dsn != "" {
		parsed, err := url.Parse("databricks://" + dsn)
		if err != nil || parsed.User == nil || parsed.Hostname() == "" {
			return locatorDatabricksConfig{}, errors.New("DATABRICKS_DSN is invalid")
		}
		if host == "" {
			host = parsed.Hostname()
		}
		if token == "" {
			token, _ = parsed.User.Password()
		}
		if warehouseID == "" {
			const prefix = "/sql/1.0/warehouses/"
			if strings.HasPrefix(parsed.Path, prefix) {
				warehouseID = strings.Trim(strings.TrimPrefix(parsed.Path, prefix), "/")
			}
		}
	}
	if host == "" || token == "" || warehouseID == "" {
		return locatorDatabricksConfig{}, errors.New("Databricks host, token, and warehouse ID are required for reference-only execution")
	}
	if !strings.Contains(host, "://") {
		host = "https://" + host
	}
	parsedHost, err := url.Parse(host)
	if err != nil || parsedHost.Hostname() == "" || (parsedHost.Scheme != "https" && !(parsedHost.Scheme == "http" && isLoopbackLocatorHost(parsedHost.Hostname()))) {
		return locatorDatabricksConfig{}, errors.New("DATABRICKS_HOST must use https except for loopback test hosts")
	}
	timeout := locatorDatabricksTimeout
	if raw := strings.TrimSpace(os.Getenv("DATABRICKS_TIMEOUT")); raw != "" {
		parsed, parseErr := time.ParseDuration(raw)
		if parseErr != nil || parsed <= 0 {
			return locatorDatabricksConfig{}, fmt.Errorf("parse DATABRICKS_TIMEOUT: %q", raw)
		}
		timeout = parsed
	}
	return locatorDatabricksConfig{baseURL: strings.TrimRight(host, "/"), token: token, warehouseID: warehouseID, timeout: timeout}, nil
}

func isLoopbackLocatorHost(host string) bool {
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

type statementLocatorRowSource struct {
	config locatorDatabricksConfig
	client *http.Client
}

func newStatementLocatorRowSource(config locatorDatabricksConfig, client *http.Client) *statementLocatorRowSource {
	if config.timeout <= 0 {
		config.timeout = locatorDatabricksTimeout
	}
	if client == nil {
		client = &http.Client{Timeout: config.timeout}
	}
	return &statementLocatorRowSource{config: config, client: client}
}

type locatorStatementParameter struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Type  string `json:"type"`
}

type locatorStatementRequest struct {
	Statement   string                      `json:"statement"`
	WarehouseID string                      `json:"warehouse_id"`
	WaitTimeout string                      `json:"wait_timeout"`
	Parameters  []locatorStatementParameter `json:"parameters"`
}

func (s *statementLocatorRowSource) execute(ctx context.Context, statement, resultID string) ([][]string, error) {
	waitSeconds := int(s.config.timeout.Round(time.Second).Seconds())
	if waitSeconds < 5 {
		waitSeconds = 5
	}
	if waitSeconds > 50 {
		waitSeconds = 50
	}
	payload := locatorStatementRequest{
		Statement: statement, WarehouseID: s.config.warehouseID, WaitTimeout: fmt.Sprintf("%ds", waitSeconds),
		Parameters: []locatorStatementParameter{{Name: "result_id", Value: resultID, Type: "STRING"}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, s.config.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, s.config.baseURL+"/api/2.0/sql/statements", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.config.token)
	req.Header.Set("Content-Type", "application/json")
	response, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Databricks Statement Execution request: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxStatementResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read Databricks Statement Execution response: %w", err)
	}
	if len(responseBody) > maxStatementResponseBytes {
		return nil, errors.New("Databricks Statement Execution response exceeds byte limit")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("Databricks Statement Execution returned HTTP %d: %s", response.StatusCode, truncateLocatorError(responseBody))
	}
	var decoded struct {
		Status struct {
			State string `json:"state"`
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		} `json:"status"`
		Result struct {
			DataArray [][]string `json:"data_array"`
		} `json:"result"`
	}
	if err := json.Unmarshal(responseBody, &decoded); err != nil {
		return nil, fmt.Errorf("decode Databricks Statement Execution response: %w", err)
	}
	if decoded.Status.State != "SUCCEEDED" {
		if decoded.Status.Error.Message != "" {
			return nil, fmt.Errorf("Databricks statement %s: %s", strings.ToLower(decoded.Status.State), decoded.Status.Error.Message)
		}
		return nil, fmt.Errorf("Databricks statement did not succeed: %s", decoded.Status.State)
	}
	return decoded.Result.DataArray, nil
}

func truncateLocatorError(body []byte) string {
	value := strings.TrimSpace(string(body))
	if len(value) > 500 {
		return value[:500] + "..."
	}
	return value
}

func (s *statementLocatorRowSource) Defense(ctx context.Context, resultID string) ([]defenseRow, error) {
	rows, err := s.execute(ctx, "SELECT run_id, result_id, terminal_state, TO_JSON(result_json) FROM `36889_janus_dev`.`defense_generation`.`defense_generation_results` WHERE result_id = :result_id LIMIT 2", resultID)
	if err != nil {
		return nil, err
	}
	out := make([]defenseRow, 0, len(rows))
	for _, values := range rows {
		if len(values) != 4 {
			return nil, errors.New("Defense Generation locator row is incomplete")
		}
		out = append(out, defenseRow{RunID: values[0], ResultID: values[1], TerminalState: values[2], ResultJSON: values[3]})
	}
	return out, nil
}

func (s *statementLocatorRowSource) Check(ctx context.Context, resultID string) ([]checkRow, error) {
	rows, err := s.execute(ctx, "SELECT result_id, run_id, request_id, correlation_id, capability, terminal_state, status, TO_JSON(result_json), TO_JSON(completion_json), result_sha256, CAST(result_size_bytes AS STRING), CAST(created_at AS STRING) FROM `36889_janus_dev`.`check_generation`.`check_generation_results` WHERE result_id = :result_id LIMIT 2", resultID)
	if err != nil {
		return nil, err
	}
	out := make([]checkRow, 0, len(rows))
	for _, values := range rows {
		if len(values) != 12 {
			return nil, errors.New("Check Generation locator row is incomplete")
		}
		size, parseErr := strconv.ParseInt(values[10], 10, 64)
		if parseErr != nil {
			return nil, errors.New("Check Generation result_size_bytes is invalid")
		}
		out = append(out, checkRow{ResultID: values[0], RunID: values[1], RequestID: values[2], CorrelationID: values[3], Capability: values[4], TerminalState: values[5], Status: values[6], ResultJSON: values[7], CompletionJSON: values[8], ResultSHA256: values[9], ResultSizeBytes: size, CreatedAt: values[11]})
	}
	return out, nil
}

func (s *statementLocatorRowSource) Volume(ctx context.Context, path string, expected int64) ([]byte, error) {
	prefix := "/Volumes/" + locatorCatalog + "/" + checkSchema + "/" + checkPayloadVolume + "/sha256/"
	if !strings.HasPrefix(path, prefix) || expected < 1 || expected > maxLocatorPayloadBytes {
		return nil, errors.New("Volume path or size is outside the allowlist")
	}
	requestCtx, cancel := context.WithTimeout(ctx, s.config.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, s.config.baseURL+"/api/2.0/fs/files"+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.config.token)
	response, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Databricks Files API request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 501))
		return nil, fmt.Errorf("Databricks Files API returned HTTP %d: %s", response.StatusCode, truncateLocatorError(body))
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, expected+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) != expected {
		return nil, errors.New("Files API payload size differs from manifest")
	}
	return content, nil
}

// defenseCanonicalResult follows the producer's Go field order exactly.
type defenseResultRef struct {
	System  string `json:"system"`
	Catalog string `json:"catalog,omitempty"`
	Schema  string `json:"schema,omitempty"`
	Table   string `json:"table"`
	Key     string `json:"key"`
}
type defenseOutcomeReason struct {
	Code                          string `json:"code"`
	Detail                        string `json:"detail"`
	UnresolvedPayload             string `json:"unresolved_payload,omitempty"`
	EncodingKind                  string `json:"encoding_kind,omitempty"`
	UncoveredRequiredForm         string `json:"uncovered_required_form,omitempty"`
	RejectionReason               string `json:"rejection_reason,omitempty"`
	RepeatedFunctionalFingerprint string `json:"repeated_functional_fingerprint,omitempty"`
}
type defenseCollateralPrior struct {
	Verdict    string   `json:"verdict"`
	Confidence string   `json:"confidence"`
	Basis      string   `json:"basis"`
	Gaps       []string `json:"gaps"`
	Measured   bool     `json:"measured"`
}
type defenseCandidate struct {
	CandidateID           string                 `json:"candidate_id"`
	SelectedControlClass  string                 `json:"selected_control_class"`
	CandidateKind         string                 `json:"candidate_kind"`
	MitigationIntent      string                 `json:"mitigation_intent"`
	Discriminator         string                 `json:"discriminator"`
	ExpectedBlockBehavior string                 `json:"expected_block_behavior"`
	ExpectedAllowBehavior string                 `json:"expected_allow_behavior"`
	ArtifactType          string                 `json:"artifact_type"`
	ArtifactContent       string                 `json:"artifact_content"`
	ArtifactHash          string                 `json:"artifact_hash"`
	CollateralImpactPrior defenseCollateralPrior `json:"collateral_impact_prior"`
	Assumptions           []string               `json:"assumptions"`
	Limitations           []string               `json:"limitations"`
	EvidenceRefs          []string               `json:"evidence_refs"`
}
type defenseProofHandoff struct {
	Capability   string           `json:"capability"`
	ContractID   string           `json:"contract_id"`
	Substrate    string           `json:"substrate"`
	CandidateRef defenseResultRef `json:"candidate_ref"`
	EvidenceRefs []string         `json:"evidence_refs,omitempty"`
}
type defenseAttemptRecord struct {
	CandidateID  string   `json:"candidate_id"`
	Outcome      string   `json:"outcome"`
	FeedbackRefs []string `json:"feedback_refs"`
	Constraints  []string `json:"do_not_repeat_constraints"`
}
type defenseUpstreamResultRef struct {
	Capability    string           `json:"capability"`
	ContractID    string           `json:"contract_id"`
	RequestID     string           `json:"request_id,omitempty"`
	CorrelationID string           `json:"correlation_id,omitempty"`
	RunID         string           `json:"run_id,omitempty"`
	ResultID      string           `json:"result_id"`
	TerminalState string           `json:"terminal_state,omitempty"`
	Status        string           `json:"status,omitempty"`
	ResultRef     defenseResultRef `json:"result_ref"`
	EvidenceRefs  []string         `json:"evidence_refs,omitempty"`
	ContentSHA256 string           `json:"content_sha256,omitempty"`
	SizeBytes     int64            `json:"size_bytes,omitempty"`
	CreatedAt     string           `json:"created_at,omitempty"`
}
type defenseCanonicalResult struct {
	Capability                string                     `json:"capability"`
	ContractID                string                     `json:"contract_id"`
	RequestID                 string                     `json:"request_id"`
	CorrelationID             string                     `json:"correlation_id"`
	RunID                     string                     `json:"run_id"`
	ResultID                  string                     `json:"result_id"`
	Status                    string                     `json:"status"`
	TerminalState             string                     `json:"terminal_state"`
	ResultRef                 *defenseResultRef          `json:"result_ref,omitempty"`
	EvidenceRefs              []string                   `json:"evidence_refs"`
	OutcomeReason             defenseOutcomeReason       `json:"outcome_reason"`
	PrimaryCandidate          *defenseCandidate          `json:"primary_candidate,omitempty"`
	CandidateBundle           json.RawMessage            `json:"candidate_bundle,omitempty"`
	CandidateArtifactContents map[string]json.RawMessage `json:"candidate_artifact_contents,omitempty"`
	ProofHandoffs             []defenseProofHandoff      `json:"proof_handoffs,omitempty"`
	AttemptHistory            []defenseAttemptRecord     `json:"attempt_history"`
	ProseSummary              string                     `json:"prose_summary"`
	RequestDigest             string                     `json:"request_digest"`
	UpstreamResultRefs        []defenseUpstreamResultRef `json:"upstream_result_refs"`
	ContentSHA256             string                     `json:"content_sha256,omitempty"`
	SizeBytes                 int64                      `json:"size_bytes,omitempty"`
	CreatedAt                 string                     `json:"created_at"`
}

func verifyDefenseRow(row defenseRow, locator ImmutableResultLocator) (CandidateSpec, []string, error) {
	if row.RunID != locator.RunID || row.ResultID != locator.ResultID || row.TerminalState != locator.TerminalState {
		return CandidateSpec{}, nil, fmt.Errorf("Defense Generation physical row identity differs from locator")
	}
	var result defenseCanonicalResult
	if err := json.Unmarshal([]byte(row.ResultJSON), &result); err != nil {
		return CandidateSpec{}, nil, fmt.Errorf("decode Defense Generation result_json: %w", err)
	}
	if result.Capability != locator.Capability || result.ContractID != locator.ContractID || result.RequestID != locator.RequestID || result.CorrelationID != locator.CorrelationID || result.RunID != locator.RunID || result.ResultID != locator.ResultID || result.Status != locator.Status || result.TerminalState != locator.TerminalState || !sameTimestamp(result.CreatedAt, locator.CreatedAt) || result.ResultRef == nil || !sameDefenseResultRef(*result.ResultRef, locator.ResultRef) {
		return CandidateSpec{}, nil, fmt.Errorf("Defense Generation logical result identity differs from locator")
	}
	advertisedDigest, advertisedSize := result.ContentSHA256, result.SizeBytes
	result.ContentSHA256, result.SizeBytes = "", 0
	unsigned, err := json.Marshal(result)
	if err != nil {
		return CandidateSpec{}, nil, err
	}
	if advertisedDigest != sha256Value(unsigned) || advertisedSize != int64(len(unsigned)) || advertisedDigest != locator.ContentSHA256 || advertisedSize != locator.SizeBytes {
		return CandidateSpec{}, nil, fmt.Errorf("Defense Generation physical/logical integrity verification failed")
	}
	pc := result.PrimaryCandidate
	if pc == nil || pc.ArtifactType != "modsecurity-rule" || strings.TrimSpace(pc.CandidateID) == "" || strings.TrimSpace(pc.ArtifactContent) == "" {
		return CandidateSpec{}, nil, fmt.Errorf("Defense Generation result has no supported ModSecurity candidate")
	}
	if pc.ArtifactHash != sha256Value([]byte(pc.ArtifactContent)) {
		return CandidateSpec{}, nil, fmt.Errorf("Defense Generation candidate artifact_hash differs from artifact_content")
	}
	evidence := stableStringUnion(result.EvidenceRefs, pc.EvidenceRefs)
	for _, ref := range result.UpstreamResultRefs {
		evidence = stableStringUnion(evidence, ref.EvidenceRefs)
	}
	return CandidateSpec{Kind: "waf-rule", Engine: "modsecurity", RuleID: pc.CandidateID, Rule: pc.ArtifactContent, Action: deriveRuleAction(pc.ArtifactContent)}, evidence, nil
}

func sameDefenseResultRef(ref defenseResultRef, locator upstreamRef) bool {
	return ref.System == locator.System && ref.Catalog == locator.Catalog && ref.Schema == locator.Schema && ref.Table == locator.Table && ref.Key == locator.Key
}

func (r *databricksLocatorResolver) verifyCheckRow(ctx context.Context, row checkRow, locator ImmutableResultLocator) (json.RawMessage, []string, error) {
	if row.ResultID != locator.ResultID || row.RunID != locator.RunID || row.RequestID != locator.RequestID || row.CorrelationID != locator.CorrelationID || row.Capability != locator.Capability || row.TerminalState != locator.TerminalState || row.Status != locator.Status {
		return nil, nil, fmt.Errorf("Check Generation physical row identity differs from locator")
	}
	physical, err := canonicalSortedJSON([]byte(row.ResultJSON))
	if err != nil {
		return nil, nil, fmt.Errorf("canonicalize Check Generation result_json: %w", err)
	}
	var manifest volumeManifest
	isManifest := json.Unmarshal(physical, &manifest) == nil && manifest.ContractType == "janus-volume-payload-manifest"
	physicalMatches := sha256Value(physical) == row.ResultSHA256 && int64(len(physical)) == row.ResultSizeBytes
	// Inline Python payloads are stored as Databricks VARIANT. TO_JSON may
	// normalize numeric lexical forms, so authoritative cross-capability
	// verification uses the logical RFC 8785 digest reconstructed below.
	if !physicalMatches && isManifest {
		return nil, nil, fmt.Errorf("Check Generation physical result integrity verification failed")
	}
	if !physicalMatches && (!validSHA256(row.ResultSHA256) || row.ResultSizeBytes <= 0) {
		return nil, nil, fmt.Errorf("Check Generation physical result integrity metadata is invalid")
	}
	payload := physical
	if isManifest {
		if err := validateManifestShape(physical); err != nil {
			return nil, nil, fmt.Errorf("Check Generation Volume manifest: %w", err)
		}
		if err := manifest.validate(); err != nil {
			return nil, nil, fmt.Errorf("Check Generation Volume manifest: %w", err)
		}
		path := fmt.Sprintf("/Volumes/%s/%s/%s/sha256/%s/%s/%s", locatorCatalog, checkSchema, checkPayloadVolume, manifest.digest()[0:2], manifest.digest()[2:4], manifest.digest())
		payload, err = r.source.Volume(ctx, path, manifest.SizeBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("read Check Generation Volume payload: %w", err)
		}
		if int64(len(payload)) != manifest.SizeBytes || sha256Value(payload) != manifest.ContentSHA256 {
			return nil, nil, fmt.Errorf("Check Generation Volume payload integrity verification failed")
		}
	}
	var stored struct {
		ContractType    string          `json:"contract_type"`
		ContractVersion string          `json:"contract_version"`
		ResultID        string          `json:"result_id"`
		RunResult       json.RawMessage `json:"run_result"`
	}
	if err := json.Unmarshal(payload, &stored); err != nil || len(stored.RunResult) == 0 {
		return nil, nil, fmt.Errorf("Check Generation stored result has no run_result")
	}
	if stored.ContractType != "check-generation-persisted-result" || stored.ContractVersion != "1.0" || stored.ResultID != locator.ResultID {
		return nil, nil, fmt.Errorf("Check Generation persisted wrapper identity is invalid")
	}
	var completion map[string]any
	if err := decodeJSONMap([]byte(row.CompletionJSON), &completion); err != nil {
		return nil, nil, fmt.Errorf("decode Check Generation completion_json: %w", err)
	}
	if !hasExactFields(completion, "capability", "contract_id", "run_id", "result_id", "terminal_state", "status", "request_id", "correlation_id", "result_ref", "upstream_result_refs", "evidence_refs", "characterization_revision_id", "result_contract_type", "result_contract_version", "subject_record_revision_id", "content_sha256", "size_bytes", "created_at") {
		return nil, nil, fmt.Errorf("Check Generation completion contract shape is invalid")
	}
	completionRef, _ := completion["result_ref"].(map[string]any)
	completionSize, sizeOK := int64Value(completion["size_bytes"])
	resultContractType, resultContractVersion := "check-generation-result", "1.0"
	if locator.ContractID == "check-generation@2.1" {
		resultContractType, resultContractVersion = "check-generation", "2.1"
	}
	if stringValue(completion["capability"]) != locator.Capability || stringValue(completion["contract_id"]) != "capability-completion@1.0" || stringValue(completion["result_contract_type"]) != resultContractType || stringValue(completion["result_contract_version"]) != resultContractVersion || stringValue(completion["result_id"]) != locator.ResultID || stringValue(completion["run_id"]) != locator.RunID || stringValue(completion["request_id"]) != locator.RequestID || stringValue(completion["correlation_id"]) != locator.CorrelationID || stringValue(completion["terminal_state"]) != locator.TerminalState || stringValue(completion["status"]) != locator.Status || stringValue(completion["content_sha256"]) != locator.ContentSHA256 || !sizeOK || completionSize != locator.SizeBytes || stringValue(completionRef["system"]) != "databricks" || stringValue(completionRef["catalog"]) != locatorCatalog || stringValue(completionRef["schema"]) != checkSchema || stringValue(completionRef["table"]) != checkTable || stringValue(completionRef["key"]) != locator.ResultID {
		return nil, nil, fmt.Errorf("Check Generation completion identity differs from locator")
	}
	upstreamRefs, upstreamOK := completion["upstream_result_refs"].([]any)
	evidenceRefs, evidenceOK := stringArrayValue(completion["evidence_refs"])
	if !upstreamOK || len(upstreamRefs) != 1 || !evidenceOK {
		return nil, nil, fmt.Errorf("Check Generation completion lineage is invalid")
	}
	core := map[string]any{}
	for _, key := range []string{"capability", "result_id", "run_id", "request_id", "correlation_id", "terminal_state", "status", "upstream_result_refs", "evidence_refs", "subject_record_revision_id", "characterization_revision_id", "created_at"} {
		core[key] = completion[key]
	}
	core["contract_id"] = "check-generation-result@1.0"
	var nested any
	if err := decodeJSONAny(stored.RunResult, &nested); err != nil {
		return nil, nil, err
	}
	nestedResult, _ := nested.(map[string]any)
	if stringValue(nestedResult["contract_id"]) != "check-generation@2.1" || stringValue(nestedResult["run_id"]) != locator.RunID || stringValue(nestedResult["request_id"]) != locator.RequestID || stringValue(nestedResult["run_status"]) != "completed" {
		return nil, nil, fmt.Errorf("Check Generation nested run identity differs from locator")
	}
	core["run_result"] = nested
	logical, err := marshalRFC8785(core)
	if err != nil {
		return nil, nil, err
	}
	logicalMatches := sha256Value(logical) == locator.ContentSHA256 && int64(len(logical)) == locator.SizeBytes
	if !logicalMatches {
		// The Python producer hashes its pre-validation ISO timestamp with
		// +00:00; Pydantic serializes the completion projection with Z.
		if createdAt, ok := core["created_at"].(string); ok && strings.HasSuffix(createdAt, "Z") {
			core["created_at"] = strings.TrimSuffix(createdAt, "Z") + "+00:00"
			logical, err = marshalRFC8785(core)
			if err != nil {
				return nil, nil, err
			}
			logicalMatches = sha256Value(logical) == locator.ContentSHA256 && int64(len(logical)) == locator.SizeBytes
		}
	}
	if !logicalMatches {
		return nil, nil, fmt.Errorf("Check Generation logical result integrity verification failed")
	}
	if !sameTimestamp(stringValue(core["created_at"]), locator.CreatedAt) || !sameTimestamp(row.CreatedAt, locator.CreatedAt) {
		return nil, nil, fmt.Errorf("Check Generation created_at differs from locator")
	}
	return stored.RunResult, evidenceRefs, nil
}

func hasExactFields(document map[string]any, fields ...string) bool {
	if len(document) != len(fields) {
		return false
	}
	for _, field := range fields {
		if _, ok := document[field]; !ok {
			return false
		}
	}
	return true
}

func stringArrayValue(value any) ([]string, bool) {
	items, ok := value.([]any)
	if !ok {
		return nil, false
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok || strings.TrimSpace(text) == "" {
			return nil, false
		}
		result = append(result, text)
	}
	return result, true
}

func stableStringUnion(groups ...[]string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0)
	for _, group := range groups {
		for _, value := range group {
			if strings.TrimSpace(value) == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}
	return result
}

type volumeManifest struct {
	ContractType    string `json:"contract_type"`
	ContractVersion string `json:"contract_version"`
	Reference       string `json:"reference"`
	MediaType       string `json:"media_type"`
	Encoding        string `json:"encoding"`
	ContentSHA256   string `json:"content_sha256"`
	SizeBytes       int64  `json:"size_bytes"`
	Volume          struct {
		Catalog string `json:"catalog"`
		Schema  string `json:"schema"`
		Name    string `json:"name"`
	} `json:"volume"`
}

func (m volumeManifest) digest() string { return strings.TrimPrefix(m.ContentSHA256, "sha256:") }
func (m volumeManifest) validate() error {
	if m.ContractType != "janus-volume-payload-manifest" || m.ContractVersion != "1.0" || m.MediaType != "application/json" || m.Encoding != "identity" || !validSHA256(m.ContentSHA256) || m.Reference != "payload://sha256/"+m.digest() || m.SizeBytes < 1 || m.SizeBytes > maxLocatorPayloadBytes || m.Volume.Catalog != locatorCatalog || m.Volume.Schema != checkSchema || m.Volume.Name != checkPayloadVolume {
		return fmt.Errorf("manifest fields or namespace are invalid")
	}
	return nil
}
func validateManifestShape(raw []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || len(fields) != 8 {
		return fmt.Errorf("manifest fields are invalid")
	}
	var volume map[string]json.RawMessage
	if err := json.Unmarshal(fields["volume"], &volume); err != nil || len(volume) != 3 {
		return fmt.Errorf("manifest Volume fields are invalid")
	}
	return nil
}

type checkArtifactProjection struct {
	Artifacts []struct {
		ArtifactID   string `json:"artifact_id"`
		ArtifactKind string `json:"artifact_kind"`
		Signal       *struct {
			CandidateFamily string   `json:"candidate_family"`
			Stimulus        Stimulus `json:"stimulus"`
		} `json:"mitigation_checkable_signal"`
	} `json:"artifacts"`
}

func selectRegisteredHTTPTestBasis(runResult json.RawMessage, selectedID string) (string, TestBasisSpec, error) {
	var projection checkArtifactProjection
	if err := json.Unmarshal(runResult, &projection); err != nil {
		return "", TestBasisSpec{}, fmt.Errorf("decode Check Generation run_result: %w", err)
	}
	for _, artifact := range projection.Artifacts {
		if selectedID != "" && artifact.ArtifactID != selectedID {
			continue
		}
		if artifact.ArtifactKind != "mitigation-checkable-signal" || artifact.Signal == nil || artifact.Signal.CandidateFamily != "http-probe" || strings.TrimSpace(artifact.ArtifactID) == "" || strings.TrimSpace(artifact.Signal.Stimulus.Method) == "" || strings.TrimSpace(artifact.Signal.Stimulus.PathKey) == "" {
			continue
		}
		basis, err := TestBasisFromStimulus(artifact.Signal.Stimulus)
		if err != nil {
			return "", TestBasisSpec{}, err
		}
		basis.Kind, basis.ProofBasis = "http-request-attack", "mitigation-discriminator"
		basis.Request.Path = registeredWAFPath(artifact.Signal.Stimulus.PathKey)
		return artifact.ArtifactID, basis, nil
	}
	if selectedID != "" {
		return "", TestBasisSpec{}, fmt.Errorf("selected test_basis_id %q is not an eligible HTTP mitigation artifact", selectedID)
	}
	return "", TestBasisSpec{}, fmt.Errorf("Check Generation produced no supported HTTP mitigation test basis")
}
func registeredWAFPath(pathKey string) string {
	pathKey = strings.TrimSpace(pathKey)
	if pathKey == "public_submit_php" {
		return "/public/submit.php"
	}
	if strings.HasPrefix(pathKey, "/") {
		return pathKey
	}
	if strings.Contains(pathKey, "/") || strings.Contains(pathKey, ".") {
		return "/" + pathKey
	}
	return "/"
}

func sha256Value(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func canonicalSortedJSON(raw []byte) ([]byte, error) {
	var value any
	if err := decodeJSONAny(raw, &value); err != nil {
		return nil, err
	}
	return marshalSortedJSON(value)
}
func decodeJSONAny(raw []byte, target any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return dec.Decode(target)
}
func decodeJSONMap(raw []byte, target *map[string]any) error { return decodeJSONAny(raw, target) }
func marshalSortedJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}
func marshalRFC8785(value any) ([]byte, error) {
	var buffer bytes.Buffer
	if err := writeRFC8785(&buffer, value); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
func writeRFC8785(buffer *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		buffer.WriteString("null")
	case bool:
		if typed {
			buffer.WriteString("true")
		} else {
			buffer.WriteString("false")
		}
	case string:
		buffer.Write(canonicalJSONString(typed))
	case json.Number:
		number, err := strconv.ParseFloat(string(typed), 64)
		if err != nil || math.IsInf(number, 0) || math.IsNaN(number) {
			return fmt.Errorf("invalid canonical JSON number %q", typed)
		}
		buffer.WriteString(ecmaNumber(number))
	case []any:
		buffer.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				buffer.WriteByte(',')
			}
			if err := writeRFC8785(buffer, item); err != nil {
				return err
			}
		}
		buffer.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		buffer.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				buffer.WriteByte(',')
			}
			buffer.Write(canonicalJSONString(key))
			buffer.WriteByte(':')
			if err := writeRFC8785(buffer, typed[key]); err != nil {
				return err
			}
		}
		buffer.WriteByte('}')
	default:
		return fmt.Errorf("unsupported canonical JSON value %T", value)
	}
	return nil
}
func canonicalJSONString(value string) []byte {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
	encoded := bytes.TrimSuffix(buffer.Bytes(), []byte("\n"))
	encoded = bytes.ReplaceAll(encoded, []byte(`\u2028`), []byte(" "))
	return bytes.ReplaceAll(encoded, []byte(`\u2029`), []byte(" "))
}
func ecmaNumber(value float64) string {
	if value == 0 {
		return "0"
	}
	absolute := math.Abs(value)
	if absolute >= 1e-6 && absolute < 1e21 {
		return strconv.FormatFloat(value, 'f', -1, 64)
	}
	encoded := strconv.FormatFloat(value, 'e', -1, 64)
	encoded = strings.Replace(encoded, "e-0", "e-", 1)
	encoded = strings.Replace(encoded, "e+0", "e+", 1)
	return encoded
}
func utf16Less(first, second string) bool {
	a, b := utf16.Encode([]rune(first)), utf16.Encode([]rune(second))
	for index := 0; index < len(a) && index < len(b); index++ {
		if a[index] != b[index] {
			return a[index] < b[index]
		}
	}
	return len(a) < len(b)
}
func stringValue(value any) string { text, _ := value.(string); return text }
func int64Value(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := number.Int64()
	return parsed, err == nil
}
func sameTimestamp(first, second string) bool {
	parse := func(value string) (time.Time, error) {
		if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
			return parsed, nil
		}
		return time.ParseInLocation("2006-01-02 15:04:05.999999999", value, time.UTC)
	}
	a, firstErr := parse(first)
	b, secondErr := parse(second)
	return firstErr == nil && secondErr == nil && a.Equal(b)
}
