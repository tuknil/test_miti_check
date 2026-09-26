package wazuh_ssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	ruleIDJNDIAttempt  = "100210" // control detection
	ruleIDJNDIExecuted = "100211" // target-reach confirmation (outcome=executed)

	injectTimeout = 15 * time.Second
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// WazuhInjectObserve holds every environment-derived setting the execute step needs.
type WazuhInjectObserve struct {
	// Indexer — alert verification.
	IndexerURL       string // EDR_INDEXER_URL                 (required)
	IndexerUser      string // EDR_INDEXER_USERNAME            (required)
	IndexerPassword  string // EDR_INDEXER_PASSWORD            (required)
	IndexerVerifySSL bool   // EDR_INDEXER_VERIFY_SSL          (default true)

	// Target agent.
	AgentID      string // EDR_TARGET_AGENT_ID                 (required)
	AgentLogfile string // EDR_TARGET_AGENT_LOGFILE            (default "")

	// Injection channel.
	ExecutionMode  string // EDR_EXECUTION_MODE                (default "podman"; "ssh" to use SSH)
	AgentContainer string // EDR_AGENT_CONTAINER               (default "wazuh-agent-poc")
	SSHHost        string // EDR_SSH_HOST                      (ssh mode only)
	SSHPort        string // EDR_SSH_PORT                      (default "22")
	SSHUser        string // EDR_SSH_USER                      (ssh mode only)
	SSHKey         string // EDR_SSH_KEY                       (ssh mode only; ~ expanded)

	// Poll loop.
	AlertPollTimeout  time.Duration // EDR_ALERT_POLL_TIMEOUT_SECONDS  (default 8s)
	AlertPollInterval time.Duration // EDR_ALERT_POLL_INTERVAL_SECONDS (default 1s)
}

// LoadConfig reads the configuration from the process environment. Required
// variables that are unset or empty are reported together.
func LoadConfig() (WazuhInjectObserve, error) {
	var missing []string
	required := func(key string) string {
		v := strings.TrimSpace(os.Getenv(key))
		if v == "" {
			missing = append(missing, key)
		}
		return v
	}

	cfg := WazuhInjectObserve{
		IndexerURL:       strings.TrimRight(required("EDR_INDEXER_URL"), "/"),
		IndexerUser:      required("EDR_INDEXER_USERNAME"),
		IndexerPassword:  required("EDR_INDEXER_PASSWORD"),
		IndexerVerifySSL: envBool("EDR_INDEXER_VERIFY_SSL", true),

		AgentID:      required("EDR_TARGET_AGENT_ID"),
		AgentLogfile: os.Getenv("EDR_TARGET_AGENT_LOGFILE"),

		ExecutionMode:  strings.ToLower(strings.TrimSpace(envStr("EDR_EXECUTION_MODE", "podman"))),
		AgentContainer: envStr("EDR_AGENT_CONTAINER", "wazuh-agent-poc"),
		SSHHost:        os.Getenv("EDR_SSH_HOST"),
		SSHPort:        envStr("EDR_SSH_PORT", "22"),
		SSHUser:        os.Getenv("EDR_SSH_USER"),
		SSHKey:         expandUser(os.Getenv("EDR_SSH_KEY")),

		AlertPollTimeout:  envDuration("EDR_ALERT_POLL_TIMEOUT_SECONDS", 8*time.Second),
		AlertPollInterval: envDuration("EDR_ALERT_POLL_INTERVAL_SECONDS", time.Second),
	}

	if cfg.ExecutionMode == "ssh" {
		for key, val := range map[string]string{
			"EDR_SSH_HOST": cfg.SSHHost,
			"EDR_SSH_USER": cfg.SSHUser,
			"EDR_SSH_KEY":  cfg.SSHKey,
		} {
			if strings.TrimSpace(val) == "" {
				missing = append(missing, key)
			}
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		return WazuhInjectObserve{}, fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}
	return cfg, nil
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

// ControlObservation mirrors bypass_validation.domain.observations.ControlObservation.
type ControlObservation struct {
	AttemptID        string `json:"attempt_id"`
	CandidateState   string `json:"candidate_state"`  // active | inactive | unknown
	ControlDecision  string `json:"control_decision"` // blocked | allowed | logged-only | no-decision | unknown
	CorrelationToken string `json:"correlation_token"`
	ObservedAt       string `json:"observed_at"`
	EvidenceRef      string `json:"evidence_ref"`
}

// TargetObservation mirrors bypass_validation.domain.observations.TargetObservation.
type TargetObservation struct {
	AttemptID         string `json:"attempt_id"`
	TargetReach       string `json:"target_reach"`       // reached | not-reached | unknown
	ProtectedBehavior string `json:"protected_behavior"` // triggered | not-triggered
	CorrelationToken  string `json:"correlation_token"`
	ObservedAt        string `json:"observed_at"`
	EvidenceRef       string `json:"evidence_ref"`
}

// Alert is the slice of a Wazuh alert kept as evidence.
type Alert struct {
	RuleID          string `json:"rule_id"`
	RuleDescription string `json:"rule_description"`
	RuleLevel       int    `json:"rule_level"`
	Timestamp       string `json:"timestamp"`
	FullLog         string `json:"full_log"`
}

// EDRObservation is the raw request/response evidence blob.
type EDRObservation struct {
	Request struct {
		Injected        bool   `json:"injected"`
		InjectionDetail string `json:"injection_detail"`
		AgentLogfile    string `json:"agent_logfile"`
		LogLine         string `json:"log_line"`
	} `json:"request"`
	Response struct {
		Decision        string   `json:"decision"`
		DetectedRuleIDs []string `json:"detected_rule_ids"`
		Alerts          []Alert  `json:"alerts"`
	} `json:"response"`
}

// ExecuteResult is the four-tuple the Python adapter returns.
type ExecuteResult struct {
	Control        ControlObservation `json:"control"`
	Target         TargetObservation  `json:"target"`
	EDRObservation EDRObservation     `json:"edr_observation"`
	TargetRaw      struct {
		Reached                      bool `json:"reached"`
		VulnerablePredicateTriggered bool `json:"vulnerable_predicate_triggered"`
	} `json:"target_observation"`
}

// ---------------------------------------------------------------------------
// Execute
// ---------------------------------------------------------------------------

// Execute simulates running the JNDI payload on the endpoint: it appends a
// host command-execution syslog record (program_name "log4shell-exec",
// carrying the payload verbatim and outcome=executed) to the agent's
// monitored log, then polls the Indexer for rules 100210/100211.
//
// probeHost is cosmetic: it lands in the log text only, never in the SSH
// target. Empty means "wazuh-agent-ssh".
func (c WazuhInjectObserve) Execute(ctx context.Context, payload, correlationToken, probeHost string) (ExecuteResult, error) {
	var res ExecuteResult

	host := probeHost
	if host == "" {
		host = "wazuh-agent-ssh"
	}

	startedAt := time.Now().UTC()
	// Host-execution telemetry: emitted when the JNDI payload is *run on the
	// endpoint*. EDR flags host activity, not URL/access-log matches (that is
	// the WAF's job). The payload rides verbatim so the rule regex decides
	// detection; outcome=executed marks a confirmed run for rule 100211.
	logLine := fmt.Sprintf(
		"%s %s log4shell-exec[%d]: uid=1001 cmd=[java -jar demo.jar %s] probe=%s outcome=executed rc=0",
		startedAt.Format("Jan _2 15:04:05"), host, os.Getpid(), payload, correlationToken,
	)

	remoteCmd := fmt.Sprintf("echo %s >> %s", shellQuote(logLine), shellQuote(c.AgentLogfile))

	injectCtx, cancel := context.WithTimeout(ctx, injectTimeout)
	defer cancel()
	argv := c.injectionArgv(remoteCmd)
	cmd := exec.CommandContext(injectCtx, argv[0], argv[1:]...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	injected := cmd.Run() == nil

	var alerts []Alert
	if injected {
		alerts = c.pollForAlerts(ctx, startedAt.Format("2006-01-02T15:04:05Z"), correlationToken)
	}

	detected := make([]string, 0, len(alerts))
	seen := map[string]bool{}
	targetReached := false
	for _, a := range alerts {
		if !seen[a.RuleID] {
			seen[a.RuleID] = true
			detected = append(detected, a.RuleID)
		}
		if a.RuleID == ruleIDJNDIExecuted {
			targetReached = true
		}
	}
	sort.Strings(detected)

	controlDecision := "allowed"
	switch {
	case targetReached:
		controlDecision = "blocked"
	case len(detected) > 0:
		controlDecision = "logged-only"
	}

	targetReach := "unknown"
	if targetReached {
		targetReach = "reached"
	} else if len(detected) > 0 {
		targetReach = "not-reached"
	}

	protectedBehavior := "not-triggered"
	if targetReached {
		protectedBehavior = "triggered"
	}

	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	res.Control = ControlObservation{
		AttemptID:        correlationToken,
		CandidateState:   "active",
		ControlDecision:  controlDecision,
		CorrelationToken: correlationToken,
		ObservedAt:       now,
		EvidenceRef:      "evidence://control/" + correlationToken,
	}
	res.Target = TargetObservation{
		AttemptID:         correlationToken,
		TargetReach:       targetReach,
		ProtectedBehavior: protectedBehavior,
		CorrelationToken:  correlationToken,
		ObservedAt:        now,
		EvidenceRef:       "evidence://target/" + correlationToken,
	}

	detail := "ok"
	if !injected {
		detail = strings.TrimSpace(stderr.String())
	}
	res.EDRObservation.Request.Injected = injected
	res.EDRObservation.Request.InjectionDetail = detail
	res.EDRObservation.Request.AgentLogfile = c.AgentLogfile
	res.EDRObservation.Request.LogLine = logLine
	res.EDRObservation.Response.Decision = controlDecision
	res.EDRObservation.Response.DetectedRuleIDs = detected
	res.EDRObservation.Response.Alerts = alerts

	res.TargetRaw.Reached = targetReached
	res.TargetRaw.VulnerablePredicateTriggered = targetReached

	return res, nil
}

// injectionArgv builds the argv that runs remoteCmd on the log-tailing agent
// host. SSH mode targets an env-configured host/key (no caller input); podman
// mode execs the fixed lab container.
func (c WazuhInjectObserve) injectionArgv(remoteCmd string) []string {
	if c.ExecutionMode == "ssh" {
		return []string{
			"ssh", "-i", c.SSHKey, "-p", c.SSHPort,
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			"-o", "ConnectTimeout=10",
			c.SSHUser + "@" + c.SSHHost,
			remoteCmd,
		}
	}
	return []string{"podman", "exec", c.AgentContainer, "sh", "-c", remoteCmd}
}

// pollForAlerts queries the Indexer until a matching alert appears or the
// poll budget runs out. Transport errors are swallowed and retried, matching
// the Python adapter; an empty slice means "nothing seen in time".
func (c WazuhInjectObserve) pollForAlerts(ctx context.Context, sinceISO, correlationToken string) []Alert {
	query := map[string]any{
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"term": map[string]any{"agent.id": c.AgentID}},
			map[string]any{"terms": map[string]any{"rule.id": []string{ruleIDJNDIAttempt, ruleIDJNDIExecuted}}},
			map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": sinceISO}}},
			map[string]any{"match_phrase": map[string]any{"full_log": correlationToken}},
		}}},
		"sort": []any{map[string]any{"timestamp": "asc"}},
		"size": 10,
	}
	body, err := json.Marshal(query)
	if err != nil {
		return nil
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           nil, // trust_env=False: ignore HTTP(S)_PROXY
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !c.IndexerVerifySSL},
		},
	}
	url := c.IndexerURL + "/wazuh-alerts-*/_search"

	deadline := time.Now().Add(c.AlertPollTimeout)
	for time.Now().Before(deadline) {
		if alerts := c.searchOnce(ctx, client, url, body); len(alerts) > 0 {
			return alerts
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(c.AlertPollInterval):
		}
	}
	return nil
}

func (c WazuhInjectObserve) searchOnce(ctx context.Context, client *http.Client, url string, body []byte) []Alert {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.IndexerUser, c.IndexerPassword)

	resp, err := client.Do(req)
	if err != nil {
		return nil // retried until the deadline, as in the Python adapter
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}

	var decoded struct {
		Hits struct {
			Hits []struct {
				Source struct {
					Rule struct {
						ID          string `json:"id"`
						Description string `json:"description"`
						Level       int    `json:"level"`
					} `json:"rule"`
					Timestamp string `json:"timestamp"`
					FullLog   string `json:"full_log"`
				} `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil
	}

	alerts := make([]Alert, 0, len(decoded.Hits.Hits))
	for _, hit := range decoded.Hits.Hits {
		alerts = append(alerts, Alert{
			RuleID:          hit.Source.Rule.ID,
			RuleDescription: hit.Source.Rule.Description,
			RuleLevel:       hit.Source.Rule.Level,
			Timestamp:       hit.Source.Timestamp,
			FullLog:         hit.Source.FullLog,
		})
	}
	return alerts
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// shellQuote is the equivalent of Python's shlex.quote: one level of POSIX
// single-quoting, which is what both `sh -c` and sshd's remote shell apply.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func envStr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	seconds, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil || seconds <= 0 {
		return def
	}
	return time.Duration(seconds * float64(time.Second))
}

func expandUser(path string) string {
	if path == "" || !strings.HasPrefix(path, "~") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if path == "~" {
		return home
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(home, path[2:])
	}
	return path
}

// ---------------------------------------------------------------------------
// CLI entrypoint
// ---------------------------------------------------------------------------

// main wires the execute step to flags and the environment, then prints the
// four observations as JSON. WazuhInjectObserve comes entirely from the environment (see
// the package doc / LoadConfig); the payload and correlation token are the
// only per-invocation inputs.
func main() {
	payload := flag.String("payload", "", "payload string embedded verbatim in the telemetry line (required)")
	token := flag.String("token", "", "correlation token (default: random 32-hex)")
	probeHost := flag.String("probe-host", "", "hostname written into the log line only (default wazuh-agent-ssh)")
	compact := flag.Bool("compact", false, "emit single-line JSON instead of indented")
	flag.Parse()

	if strings.TrimSpace(*payload) == "" {
		fmt.Fprintln(os.Stderr, "error: -payload is required")
		flag.Usage()
		os.Exit(2)
	}
	if *token == "" {
		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err != nil {
			fmt.Fprintf(os.Stderr, "error: generating token: %v\n", err)
			os.Exit(1)
		}
		*token = hex.EncodeToString(buf)
	}

	cfg, err := LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	res, err := cfg.Execute(context.Background(), *payload, *token, *probeHost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "execute error: %v\n", err)
		os.Exit(1)
	}

	enc := json.NewEncoder(os.Stdout)
	if !*compact {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(res); err != nil {
		fmt.Fprintf(os.Stderr, "encode error: %v\n", err)
		os.Exit(1)
	}
	if !res.EDRObservation.Request.Injected {
		os.Exit(2) // injection failed
	}
}
