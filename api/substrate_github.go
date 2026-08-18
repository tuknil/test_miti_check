package main

// substrate_github.go runs a scenario through GitHub Actions (another pluggable
// runner, LLD §3.3/§6.4). On submit the API dispatches a workflow in a configured
// repo, the workflow runs THIS executor (via `run-scenario`) on a GitHub-hosted
// runner, uploads the result as an artifact, and the API downloads it and returns
// it — so the outcome is stored in Postgres exactly like a local run.
//
// Config comes from docker compose env:
//   GITHUB_REPO      owner/repo that holds the workflow
//   GITHUB_TOKEN     PAT with actions:write on that repo
//   GITHUB_WORKFLOW  workflow file name (default mitigation-check.yml)
//   GITHUB_REF       branch to run on (default main)
//   GITHUB_USERNAME  informational only
// When repo/token are unset an aci/github run returns could-not-test.

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const githubAPI = "https://api.github.com"
const githubResultArtifact = "mitigation-check-result"

// runViaGitHub dispatches the workflow, waits for the run, and returns its result.
func runViaGitHub(ctx context.Context, req SubmitMitigationCheckRequest, out RunOutcome) RunOutcome {
	repo := os.Getenv("GITHUB_REPO")
	token := os.Getenv("GITHUB_TOKEN")
	workflow := firstNonEmpty(os.Getenv("GITHUB_WORKFLOW"), "mitigation-check.yml")
	ref := firstNonEmpty(os.Getenv("GITHUB_REF"), "main")
	if repo == "" || token == "" {
		return couldNotTest(out, "github actions not configured (set GITHUB_REPO, GITHUB_TOKEN)")
	}
	gh := &ghClient{token: token, http: &http.Client{Timeout: 30 * time.Second}}

	// The runner re-runs this scenario locally; strip the mode to avoid recursion.
	scenario := req
	scenario.ExecutionMode = execLocal
	body, _ := json.Marshal(scenario)
	inputs := map[string]string{
		"run_id":   out.RunID,
		"scenario": base64.StdEncoding.EncodeToString(body),
	}

	dispatchedAt := time.Now().Add(-5 * time.Second)
	if err := gh.dispatch(ctx, repo, workflow, ref, inputs); err != nil {
		return couldNotTest(out, "github dispatch failed: "+err.Error())
	}
	out.Steps = append(out.Steps, "dispatched workflow "+workflow+" on "+repo+"@"+ref+" (run_id "+out.RunID+")")

	// Find the run whose display name matches "mc-<run_id>" (set via run-name:).
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

	// Overlay our identity; keep the remote verdict/observations.
	result.RunID = out.RunID
	result.ResultID = out.ResultID
	result.Substrate.Runner = execGitHub
	result.Steps = append(out.Steps, result.Steps...)
	result.Steps = append(result.Steps, "result retrieved from GitHub artifact "+githubResultArtifact)
	return result
}

type ghClient struct {
	token string
	http  *http.Client
}

func (c *ghClient) do(ctx context.Context, method, url string, body io.Reader) (*http.Response, error) {
	r, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Authorization", "Bearer "+c.token)
	r.Header.Set("Accept", "application/vnd.github+json")
	r.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(r)
}

func (c *ghClient) dispatch(ctx context.Context, repo, workflow, ref string, inputs map[string]string) error {
	url := fmt.Sprintf("%s/repos/%s/actions/workflows/%s/dispatches", githubAPI, repo, workflow)
	payload, _ := json.Marshal(map[string]any{"ref": ref, "inputs": inputs})
	resp, err := c.do(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, snippet(resp.Body))
	}
	return nil
}

// findRun polls the recent workflow_dispatch runs for one named displayName.
func (c *ghClient) findRun(ctx context.Context, repo, displayName string, after time.Time) (int64, error) {
	url := fmt.Sprintf("%s/repos/%s/actions/runs?event=workflow_dispatch&per_page=30", githubAPI, repo)
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		resp, err := c.do(ctx, http.MethodGet, url, nil)
		if err == nil && resp.StatusCode == http.StatusOK {
			var body struct {
				WorkflowRuns []struct {
					ID           int64     `json:"id"`
					Name         string    `json:"name"`
					DisplayTitle string    `json:"display_title"`
					CreatedAt    time.Time `json:"created_at"`
				} `json:"workflow_runs"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&body)
			resp.Body.Close()
			for _, r := range body.WorkflowRuns {
				if (r.Name == displayName || r.DisplayTitle == displayName) && r.CreatedAt.After(after) {
					return r.ID, nil
				}
			}
		} else if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(3 * time.Second)
	}
	return 0, fmt.Errorf("timed out waiting for run to appear")
}

// waitRun polls a run until completed and returns its conclusion.
func (c *ghClient) waitRun(ctx context.Context, repo string, runID int64) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/actions/runs/%d", githubAPI, repo, runID)
	for {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		resp, err := c.do(ctx, http.MethodGet, url, nil)
		if err != nil {
			return "", err
		}
		var body struct {
			Status     string `json:"status"`
			Conclusion string `json:"conclusion"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if body.Status == "completed" {
			return body.Conclusion, nil
		}
		time.Sleep(5 * time.Second)
	}
}

// fetchResult downloads the result artifact zip and parses result.json.
func (c *ghClient) fetchResult(ctx context.Context, repo string, runID int64) (RunOutcome, error) {
	var zero RunOutcome
	listURL := fmt.Sprintf("%s/repos/%s/actions/runs/%d/artifacts", githubAPI, repo, runID)
	resp, err := c.do(ctx, http.MethodGet, listURL, nil)
	if err != nil {
		return zero, err
	}
	var list struct {
		Artifacts []struct {
			Name               string `json:"name"`
			ArchiveDownloadURL string `json:"archive_download_url"`
		} `json:"artifacts"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&list)
	resp.Body.Close()

	var dlURL string
	for _, a := range list.Artifacts {
		if a.Name == githubResultArtifact {
			dlURL = a.ArchiveDownloadURL
			break
		}
	}
	if dlURL == "" {
		return zero, fmt.Errorf("artifact %q not found", githubResultArtifact)
	}

	dl, err := c.do(ctx, http.MethodGet, dlURL, nil) // follows redirect to the zip
	if err != nil {
		return zero, err
	}
	defer dl.Body.Close()
	if dl.StatusCode != http.StatusOK {
		return zero, fmt.Errorf("artifact download HTTP %d", dl.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(dl.Body, 8<<20))
	if err != nil {
		return zero, err
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return zero, err
	}
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "result.json") {
			rc, err := f.Open()
			if err != nil {
				return zero, err
			}
			defer rc.Close()
			var oc RunOutcome
			if err := json.NewDecoder(rc).Decode(&oc); err != nil {
				return zero, err
			}
			return oc, nil
		}
	}
	return zero, fmt.Errorf("result.json missing from artifact")
}

func snippet(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 300))
	return strings.TrimSpace(string(b))
}
