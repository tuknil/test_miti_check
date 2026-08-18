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

### Execution mode: local Docker vs Azure ACI

The substrate can be brought up two ways, selected by the **Execution mode**
toggle in the UI (or `execution_mode` in the request: `local` | `aci`). Only the
bring-up/teardown differs — the WAF, test, and verdict are identical.

- **`local`** (default) — `docker run` on the host daemon (`docker.sock`). What
  Docker Compose uses.
- **`aci`** — Azure Container Instances. For when the API is hosted on **Azure
  Container Apps**, which can't mount a Docker socket or launch sibling
  containers. The adapter creates a per-run ACI container group, runs the test
  against it over the network, then deletes it (LLD §3.3, §6.4 pluggable
  substrate adapter). It authenticates with `DefaultAzureCredential` (a managed
  identity on ACA, or env/`az` locally) and needs:

  ```
  AZURE_SUBSCRIPTION_ID, MC_ACI_RESOURCE_GROUP, MC_ACI_REGION
  ```

  Optional: `MC_ACI_CPU`, `MC_ACI_MEMORY_GB`, and private-registry creds via
  `MC_ACI_REGISTRY_*` (falls back to `JFROG_*`). When Azure isn't configured, an
  `aci` run returns `could-not-test` with that reason rather than failing — so
  the mode is selectable everywhere; real execution needs Azure.

- **`aci-sp`** — same ACI substrate, but authenticated with an explicit **service
  principal** instead of a managed identity. Portable: works from a **laptop** or
  on **ACA** with the same env vars. In addition to the three `AZURE_*`/`MC_ACI_*`
  values above, set:

  ```
  AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
  ```

  (The `aci` mode also accepts these via `DefaultAzureCredential`; `aci-sp` just
  makes the service-principal path explicit and required.)

- **`github`** — runs the scenario on a **GitHub Actions** runner. On submit the
  API dispatches a `workflow_dispatch` in the configured repo (passing the run id
  + the scenario as inputs), waits for the run to complete, downloads the result
  artifact, and stores it — so the ledger row is identical to a local run. The
  workflow (`.github/workflows/mitigation-check.yml`) runs **this same executor**
  via the `run-scenario` CLI, so the logic is shared, not reimplemented. Config
  (via docker compose `.env`):

  ```
  GITHUB_REPO=owner/repo        # repo that holds the workflow (on its default branch)
  GITHUB_USERNAME=<user>        # informational
  GITHUB_TOKEN=<PAT>            # actions:write on that repo
  GITHUB_WORKFLOW=mitigation-check.yml   # optional (default)
  GITHUB_REF=main                        # optional (default)
  ```

  The workflow must exist on the repo's **default branch** for the dispatch API
  to find it. When GitHub isn't configured a `github` run returns
  `could-not-test`.

## Step 3 — Run ledger

Every submitted run is recorded in an in-memory ledger (LLD §11.1), keeping the
**exact immutable request bytes** alongside the executed result.

- `GET /v1/mitigation-check-runs` — list runs, newest first (compact summaries).
- `GET /v1/mitigation-check-runs/{run_id}` — one run's immutable `request` + full
  `response`.

The UI shows a left **Runs** panel; clicking a run opens its immutable request
(marked immutable) and rendered result on the right.

**Persistence — PostgreSQL container.** The ledger is stored in a `db` Postgres
service (`postgres:16-alpine`) defined in `docker-compose.yml`. The immutable
request and the executed response are `JSONB` columns of `mitigation_check_run`.
The API connects via `DATABASE_URL` (default `postgres://mc:mc@db:5432/mitigation`)
and waits for the db healthcheck before serving.

The db data lives on the named volume `pgdata` (`/var/lib/postgresql/data`), so
runs are **durable across `docker stop` and `docker rm` of the db container** —
recreate it and the data is intact; the API's connection pool reconnects
automatically. Only `docker compose down -v` deletes the volume.

For a local (non-Docker) API run, point `DATABASE_URL` at any reachable Postgres.

## Run it — Docker (recommended)

Both services run as containers via Docker Compose:

```bash
docker compose up -d --build
```

- UI → http://localhost:8082
- API → http://localhost:8137
- API docs (Swagger UI) → http://localhost:8137/docs · spec at http://localhost:8137/openapi.yaml

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
