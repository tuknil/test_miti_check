package main

// substrate_github_ghcr.go is a SEPARATE GitHub execution mode ("github-ghcr")
// that relays the substrate image through the repo owner's GHCR before running
// the scenario on a GitHub Actions runner. It does NOT touch the plain "github"
// mode (substrate_github.go); it reuses that file's ghClient HTTP helpers.
//
// Flow on submit:
//  1. ensure a repo Actions secret (GHCR_PAT) so the runner can pull the private
//     relayed image (there is no API to change package visibility, so we grant
//     the runner a read token instead);
//  2. pull the source image locally, retag it under ghcr.io/<owner>, push it
//     (host-daemon push, so the container needs no direct registry egress);
//  3. dispatch the dedicated GHCR workflow with the scenario image rewritten to
//     the relayed GHCR reference; then poll + fetch the result like "github".
//
// Use this when the runner cannot reach the source registry (e.g. a private
// Artifactory) but can pull from GHCR.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/nacl/box"
)

const ghcrSecretName = "GHCR_PAT"

func runViaGitHubGHCR(ctx context.Context, req SubmitMitigationCheckRequest, out RunOutcome) RunOutcome {
	repo := os.Getenv("GITHUB_REPO")
	token := os.Getenv("GITHUB_TOKEN")
	workflow := firstNonEmpty(os.Getenv("MC_GHCR_WORKFLOW"), "mitigation-check-ghcr.yml")
	ref := firstNonEmpty(os.Getenv("GITHUB_REF"), "main")
	if repo == "" || token == "" {
		return couldNotTest(out, "github actions not configured (set GITHUB_REPO, GITHUB_TOKEN)")
	}
	gh := &ghClient{token: token, http: &http.Client{Timeout: 30 * time.Second}}
	owner := strings.SplitN(repo, "/", 2)[0]
	username := firstNonEmpty(os.Getenv("GITHUB_USERNAME"), owner)

	// 1. Grant the runner a way to pull the private relayed image: store a
	// read:packages token as a repo secret the workflow logs in with.
	if err := gh.ensureRepoSecret(ctx, repo, ghcrSecretName, token); err != nil {
		return couldNotTest(out, "could not set "+ghcrSecretName+" repo secret: "+err.Error())
	}
	out.Steps = append(out.Steps, "ensured "+ghcrSecretName+" repo secret for runner pull")

	// 2. Relay the substrate image into the owner's GHCR.
	var srcSpec SubstrateSpec
	_ = json.Unmarshal(nonNil(req.Substrate), &srcSpec)
	target, relaySteps, rerr := relayImageToGHCR(ctx, srcSpec.Image, owner, username, token)
	out.Steps = append(out.Steps, relaySteps...)
	if rerr != nil {
		return couldNotTest(out, "image relay to GHCR failed: "+trimErr(rerr))
	}

	// 3. Dispatch the dedicated GHCR workflow against the relayed image.
	scenario := req
	scenario.ExecutionMode = execLocal
	scenario.Substrate = overrideImage(req.Substrate, target)
	body, _ := json.Marshal(scenario)
	inputs := map[string]string{
		"run_id":   out.RunID,
		"scenario": base64.StdEncoding.EncodeToString(body),
	}

	dispatchedAt := time.Now().Add(-5 * time.Second)
	if err := gh.dispatch(ctx, repo, workflow, ref, inputs); err != nil {
		return couldNotTest(out, "github dispatch failed: "+err.Error())
	}
	out.Steps = append(out.Steps, "dispatched workflow "+workflow+" on "+repo+"@"+ref)

	runID, err := gh.findRun(ctx, repo, "mc-"+out.RunID, dispatchedAt)
	if err != nil {
		return couldNotTest(out, "could not locate GitHub run: "+err.Error())
	}
	out.Steps = append(out.Steps, "github run #"+strconv.FormatInt(runID, 10)+" started")

	conclusion, err := gh.waitRun(ctx, repo, runID)
	if err != nil {
		return couldNotTest(out, "waiting for GitHub run: "+err.Error())
	}
	out.Steps = append(out.Steps, "github run #"+strconv.FormatInt(runID, 10)+" completed: "+conclusion)

	result, err := gh.fetchResult(ctx, repo, runID)
	if err != nil {
		return couldNotTest(out, "run "+conclusion+", but no usable result: "+err.Error())
	}

	result.RunID = out.RunID
	result.ResultID = out.ResultID
	result.Substrate.Runner = execGitHubGHCR
	result.Steps = append(out.Steps, result.Steps...)
	result.Steps = append(result.Steps, "result retrieved from GitHub artifact "+githubResultArtifact)
	return result
}

// ensureRepoSecret creates/updates a repo Actions secret (libsodium sealed box).
func (c *ghClient) ensureRepoSecret(ctx context.Context, repo, name, value string) error {
	resp, err := c.do(ctx, http.MethodGet,
		fmt.Sprintf("%s/repos/%s/actions/secrets/public-key", githubAPI, repo), nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return fmt.Errorf("public-key HTTP %d: %s", resp.StatusCode, snippet(resp.Body))
	}
	var pk struct {
		KeyID string `json:"key_id"`
		Key   string `json:"key"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&pk)
	resp.Body.Close()

	pub, err := base64.StdEncoding.DecodeString(pk.Key)
	if err != nil || len(pub) != 32 {
		return fmt.Errorf("invalid repo public key")
	}
	var pubArr [32]byte
	copy(pubArr[:], pub)
	sealed, err := box.SealAnonymous(nil, []byte(value), &pubArr, rand.Reader)
	if err != nil {
		return err
	}

	payload, _ := json.Marshal(map[string]string{
		"encrypted_value": base64.StdEncoding.EncodeToString(sealed),
		"key_id":          pk.KeyID,
	})
	put, err := c.do(ctx, http.MethodPut,
		fmt.Sprintf("%s/repos/%s/actions/secrets/%s", githubAPI, repo, name), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer put.Body.Close()
	if put.StatusCode != http.StatusCreated && put.StatusCode != http.StatusNoContent {
		return fmt.Errorf("set secret HTTP %d: %s", put.StatusCode, snippet(put.Body))
	}
	return nil
}

// relayImageToGHCR pulls the source image, retags it under ghcr.io/<owner>, and
// pushes it. Returns the pushed target reference. Needs local docker + a token
// with write:packages.
func relayImageToGHCR(ctx context.Context, sourceImage, owner, username, token string) (string, []string, error) {
	var steps []string
	if strings.TrimSpace(sourceImage) == "" {
		return "", steps, fmt.Errorf("no substrate image to relay")
	}
	if err := dockerCLI(ctx, 300*time.Second, nil, "pull", sourceImage); err != nil {
		return "", steps, fmt.Errorf("pull %s: %w", sourceImage, err)
	}
	steps = append(steps, "relay: pulled "+sourceImage)

	target := ghcrTarget(owner, sourceImage)
	if err := dockerCLI(ctx, 30*time.Second, nil, "tag", sourceImage, target); err != nil {
		return "", steps, fmt.Errorf("tag %s: %w", target, err)
	}
	steps = append(steps, "relay: tagged "+target)

	if err := dockerPushWithAuth(ctx, target, username, token); err != nil {
		return target, steps, fmt.Errorf("push %s: %w", target, err)
	}
	steps = append(steps, "relay: pushed "+target)
	return target, steps, nil
}

// dockerPushWithAuth pushes target using a throwaway DOCKER_CONFIG holding the
// ghcr.io credential, so the host daemon performs the transfer (no container-side
// `docker login` network round-trip) and the shared docker config is untouched.
func dockerPushWithAuth(ctx context.Context, target, username, token string) error {
	tmp, err := os.MkdirTemp("", "ghcr-cfg-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + token))
	cfg := fmt.Sprintf(`{"auths":{"ghcr.io":{"auth":%q}}}`, auth)
	if err := os.WriteFile(filepath.Join(tmp, "config.json"), []byte(cfg), 0o600); err != nil {
		return err
	}
	c, cancel := context.WithTimeout(ctx, 300*time.Second)
	defer cancel()
	cmd := exec.CommandContext(c, "docker", "push", target)
	cmd.Env = append(os.Environ(), "DOCKER_CONFIG="+tmp)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(errb.String()+" "+err.Error()))
	}
	return nil
}

// dockerCLI runs `docker <args>` with an optional stdin, capturing stderr.
func dockerCLI(ctx context.Context, timeout time.Duration, stdin io.Reader, args ...string) error {
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(c, "docker", args...)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(errb.String()+" "+err.Error()))
	}
	return nil
}

// ghcrTarget maps a source image to ghcr.io/<owner>/<name>:<tag>.
func ghcrTarget(owner, sourceImage string) string {
	ref, tag := sourceImage, "latest"
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		tag, ref = ref[i+1:], ref[:i]
	}
	name := ref
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		name = ref[i+1:]
	}
	return "ghcr.io/" + strings.ToLower(owner) + "/" + name + ":" + tag
}

// overrideImage returns the substrate JSON with its image field replaced.
func overrideImage(raw json.RawMessage, image string) json.RawMessage {
	m := map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &m)
	}
	m["image"] = image
	out, _ := json.Marshal(m)
	return out
}
