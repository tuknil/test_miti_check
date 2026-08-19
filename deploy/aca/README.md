# Deploy to Azure Container Apps (ACA)

ACA runs the API and UI as managed containers. There is **no host Docker socket**,
so the `local` execution mode is unavailable — use `inmemory`, `aci`, `aci-sp`,
`github`, or `github-ghcr` (all daemonless). [deploy.sh](deploy.sh) wires it up
with the `az` CLI.

```bash
DATABASE_URL='postgres://mc:pass@myserver.postgres.database.azure.com:5432/mitigation?sslmode=require' \
RG=mc-nonprod-rg LOCATION=eastus \
  ./deploy.sh
```

## Prerequisites

### 1. Publish the images to a registry ACA can pull
The compose file builds images locally; ACA pulls from a registry. Push them to
GHCR (or ACR):

```bash
# from repo root — build for linux/amd64 (ACA runs amd64)
docker build --platform linux/amd64 -t ghcr.io/tuknil/mitigation-check-api:latest ./api
docker build --platform linux/amd64 -t ghcr.io/tuknil/mitigation-check-ui:latest  ./ui
docker push ghcr.io/tuknil/mitigation-check-api:latest
docker push ghcr.io/tuknil/mitigation-check-ui:latest
```

If the packages are **private**, set `REGISTRY_SERVER`/`REGISTRY_USERNAME`/
`REGISTRY_PASSWORD` so ACA can pull them (a `read:packages` token for GHCR).

### 2. PostgreSQL
Use **Azure Database for PostgreSQL Flexible Server** (ACA is stateless). Create
the `mitigation` database and pass its URL as `DATABASE_URL` (with
`sslmode=require`). The API creates its own table on start.

### 3. `az` CLI logged in
`az login`; the account needs rights to create the resource group, ACA
environment, apps, and (for `aci` mode) a role assignment.

## What the script sets up

- **API** container app — external ingress on `8137`, a **system-assigned managed
  identity**, `DATABASE_URL` as a secret, and the `MC_ACI_*` / `AZURE_SUBSCRIPTION_ID`
  env for ACI substrates.
- **Managed-identity RBAC:** the API identity gets **Contributor on the ACI
  resource group** so `aci` mode can create/delete container groups.
- Optional secrets for **`github`/`github-ghcr`** (`GITHUB_REPO`, `GITHUB_TOKEN`)
  and **`aci-sp`** (`AZURE_TENANT_ID`/`AZURE_CLIENT_ID`/`AZURE_CLIENT_SECRET`).
- **UI** container app — external ingress on `80`. Set its "API base URL" field to
  the API app's `https://…` FQDN (the API sends permissive CORS).

## Egress the API needs (per mode)

ACA has outbound internet by default. On a locked-down VNet-integrated
environment, allow egress to:

| Mode | Needs egress to |
|---|---|
| `aci` / `aci-sp` | Azure Resource Manager (`management.azure.com`, `login.microsoftonline.com`) |
| `github` | `api.github.com`, `objects.githubusercontent.com` (artifact download) |
| `github-ghcr` | the above **+** `ghcr.io` and any private **source** registry (e.g. `artifact.it.att.com`) — the daemonless relay copies registry→registry from the API |
| `inmemory` | none |

Plus the Postgres host in all cases.

## Notes / caveats

- This is a **template**, not run against a live subscription here — adjust names,
  SKUs, and networking to your environment.
- Drop the `docker.sock` mount and `MC_SUBSTRATE_NETWORK` — those are `local`-mode
  only and don't apply on ACA.
- For `github-ghcr`, the API's `GITHUB_TOKEN` needs `write:packages` (push) and
  `repo` (to set the `GHCR_PAT` runner secret); the relayed package stays private.
- For a private **source** registry in `github-ghcr`, set `MC_ACI_REGISTRY_*` (or
  `JFROG_*`) so the relay can authenticate the pull.
