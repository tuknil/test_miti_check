// Package wazuh evaluates a Wazuh (endpoint-detection) rule against a decoded
// telemetry event. It is the EDR evaluator the mitigation-check service runs (see
// ../executor_edr.go), selected by candidate kind alongside the WAF and firewall
// evaluators.
//
// It also carries the command→telemetry generator (telemetry.go, footprint.go),
// used by the EDR executor to synthesize the Wazuh telemetry a command test basis
// would generate and evaluate the rule against it.
//
// This package is the stdlib-only core of the standalone `wazuh-eval` tool (repo
// root /wazuh-eval). It is kept as a sibling copy rather than a cross-module
// import on purpose: the api module carries heavy dependencies (Azure, Databricks,
// pgx) that must not leak into the stdlib-only standalone module, and the api
// container build context is ./api, so it cannot import the sibling module either.
// Keep rule.go / event.go / eval.go / telemetry.go / footprint.go in sync with
// /wazuh-eval.
package wazuh
