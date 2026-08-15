# mitigation-check webapp

A stepwise prototype of the `mitigation-check@1.0` capability (see
[mitigation-check-lld.md](mitigation-check-lld.md)), built as a **separate UI and
Go API server**.

## Step 1 — Submit a mitigation-check run

Scope: create a mitigation scenario aligned with the input contract, render a
form to display/edit the input payload, and POST it.

- **API** (`api/`) — Go server exposing `POST /v1/mitigation-check-runs`
  (LLD §9.1). It strictly validates the `SubmitMitigationCheckRequest@1` contract
  (LLD §10.1): `contract_id` const, required non-empty `candidate_artifact_id` /
  `test_basis_id` / `check_profile_id`, optional `substrate_selector`, and
  rejects unknown fields (`additionalProperties: false`). On success it returns
  an accepted run reference `{run_id, result_id, status:"accepted"}`. Errors use
  the controlled `invalid-input` category (LLD §9.5).
- **UI** (`ui/`) — static HTML/CSS/JS. A contract-aligned form pre-filled with
  the LLD §9.1 example scenario, a live JSON request preview, and a Submit button
  that POSTs to the API.

Out of scope for Step 1: queue, persistence, events.

## Step 2 — Actually execute the scenario on submit

On submit the API now runs the scenario for real (LLD §5, §6.4 local-WAF
substrate adapter, §6.5 verdict engine):

1. **Bring up the substrate** — `docker run` the container image named in the
   request body (e.g. `ghcr.io/christophetd/log4shell-vulnerable-app`) on a
   private `127.0.0.1` port and wait until it is ready.
2. **Apply the candidate** — parse the candidate's actual ModSecurity `SecRule`
   (its `@rx` pattern + `id`/`status` actions) and stand it up as an in-process
   WAF in front of the container.
3. **Run the test** — send the supplied attack request through the WAF.
4. **Observe & decide** — a match denies at the WAF → `blocked`; otherwise the
   request reaches the live app and its status is observed → `not-blocked`. If the
   container can't be brought up or observed → `could-not-test` (never a
   fabricated verdict, per LLD §7.2).
5. **Tear down** the container (`--rm`).

The response returns the terminal state plus **actual vs expected** and an
execution step log. Requires a running Docker daemon; without one the run
returns `could-not-test` with a reason.

> The WAF faithfully enforces the *specific* SecRule shipped in the candidate
> (pattern, targets, deny/status). It is not the full ModSecurity engine —
> swapping in a real ModSecurity container is an adapter change behind the same
> flow.

## Step 3 — Run ledger

Every submitted run is recorded in an in-memory ledger (LLD §11.1), keeping the
**exact immutable request bytes** alongside the executed result.

- `GET /v1/mitigation-check-runs` — list runs, newest first (compact summaries).
- `GET /v1/mitigation-check-runs/{run_id}` — one run's immutable `request` + full
  `response`.

The UI shows a left **Runs** panel; clicking a run opens its immutable request
(marked immutable) and rendered result on the right.

**Persistence:** each run is written to disk as one immutable JSON file
(write-temp-then-rename) under `api/data/runs/` and reloaded on startup, so runs
survive API restarts. The directory is configurable via `MC_DATA_DIR`. The
`RunStore` surface is storage-agnostic — a PostgreSQL adapter (LLD §11) can
replace the file backend without touching the handlers.

## Run it — Docker (recommended)

Both services run as containers via Docker Compose:

```bash
docker compose up -d --build
```

- UI → http://localhost:8082
- API → http://localhost:8137

Then stop with `docker compose down` (keep `-v` off to preserve the ledger).

**Requires the host Docker socket.** The API launches the validation-substrate
container on the host daemon (`/var/run/docker.sock` is mounted) and attaches it
to the shared `mitigation-net` network, reaching it by container name — so the
containerized API can bring up substrates just like the local build.

### Ledger durability

The run ledger is stored on the named volume `ledger-data` (mounted at
`/app/data`). It **survives `docker stop` and `docker rm`** of the API container —
recreate the container and past runs reload automatically. Only
`docker compose down -v` deletes the volume.

## Run it — local (without Docker for the app itself)

**API** (defaults to port 8090; override with `PORT`):

```bash
cd api && PORT=8137 go run .
```

**UI** (any static file server):

```bash
cd ui && python3 -m http.server 5501
```

Open http://localhost:5501 and set the "API base URL" field to match the API
port (e.g. `http://localhost:8137`). In local mode the substrate is published on
`127.0.0.1:<free-port>` instead of the shared network.

## Verify the API directly

```bash
curl -s -X POST localhost:8137/v1/mitigation-check-runs \
  -H 'Content-Type: application/json' \
  -d '{"contract_id":"mitigation-check@1.0","candidate_artifact_id":"candidate:CVE-123:waf:3","test_basis_id":"test-basis:CVE-123:1","substrate_selector":"waf-nonprod-default","check_profile_id":"mitigation-check-profile:waf-http:1"}'
```
