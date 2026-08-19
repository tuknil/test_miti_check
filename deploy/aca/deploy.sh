#!/usr/bin/env bash
# Deploy mitigation-check (API + UI) to Azure Container Apps.
#
# ACA has no host Docker socket, so the `local` execution mode is unavailable;
# use inmemory / aci / aci-sp / github / github-ghcr (all daemonless). See
# deploy/aca/README.md for prerequisites (image publishing, Postgres, egress).
#
# Everything is parameterized by env vars — override as needed, e.g.:
#   RG=mc-rg LOCATION=eastus DATABASE_URL='postgres://...' ./deploy.sh
set -euo pipefail

# ---- required ----
: "${DATABASE_URL:?set DATABASE_URL, e.g. postgres://user:pass@host:5432/mitigation?sslmode=require}"

# ---- core config ----
RG="${RG:-mc-nonprod-rg}"
LOCATION="${LOCATION:-eastus}"
ENVIRONMENT="${ENVIRONMENT:-mc-aca-env}"
API_IMAGE="${API_IMAGE:-ghcr.io/tuknil/mitigation-check-api:latest}"
UI_IMAGE="${UI_IMAGE:-ghcr.io/tuknil/mitigation-check-ui:latest}"

# ---- substrate execution config ----
SUBSCRIPTION_ID="$(az account show --query id -o tsv)"
ACI_RG="${ACI_RG:-$RG}"          # resource group ACI substrates are created in
ACI_REGION="${ACI_REGION:-$LOCATION}"

# ---- optional: private image registry pull creds (if API/UI images are private) ----
REGISTRY_SERVER="${REGISTRY_SERVER:-}"
REGISTRY_USERNAME="${REGISTRY_USERNAME:-}"
REGISTRY_PASSWORD="${REGISTRY_PASSWORD:-}"

# ---- optional: github / github-ghcr mode ----
GITHUB_REPO="${GITHUB_REPO:-}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"

# ---- optional: aci-sp mode (service principal) ----
AZURE_TENANT_ID="${AZURE_TENANT_ID:-}"
AZURE_CLIENT_ID="${AZURE_CLIENT_ID:-}"
AZURE_CLIENT_SECRET="${AZURE_CLIENT_SECRET:-}"

echo "==> providers + extension"
az extension add --name containerapp --upgrade -y >/dev/null
az provider register -n Microsoft.App --wait >/dev/null
az provider register -n Microsoft.OperationalInsights --wait >/dev/null
az provider register -n Microsoft.ContainerInstance --wait >/dev/null

echo "==> resource group + environment"
az group create -n "$RG" -l "$LOCATION" -o none
az containerapp env create -n "$ENVIRONMENT" -g "$RG" -l "$LOCATION" -o none

# Optional registry auth for pulling the app images.
REG_ARGS=()
if [ -n "$REGISTRY_SERVER" ]; then
  REG_ARGS=(--registry-server "$REGISTRY_SERVER" --registry-username "$REGISTRY_USERNAME" --registry-password "$REGISTRY_PASSWORD")
fi

echo "==> API container app (system-assigned identity)"
az containerapp create \
  -n mitigation-api -g "$RG" --environment "$ENVIRONMENT" \
  --image "$API_IMAGE" \
  --ingress external --target-port 8137 \
  --system-assigned \
  --min-replicas 1 --max-replicas 1 \
  --cpu 0.5 --memory 1.0Gi \
  "${REG_ARGS[@]}" \
  --secrets "database-url=$DATABASE_URL" \
  --env-vars \
    PORT=8137 \
    "DATABASE_URL=secretref:database-url" \
    "AZURE_SUBSCRIPTION_ID=$SUBSCRIPTION_ID" \
    "MC_ACI_RESOURCE_GROUP=$ACI_RG" \
    "MC_ACI_REGION=$ACI_REGION" \
  -o none

# github / github-ghcr (optional)
if [ -n "$GITHUB_TOKEN" ]; then
  echo "==> wiring github secrets"
  az containerapp secret set -n mitigation-api -g "$RG" --secrets "github-token=$GITHUB_TOKEN" -o none
  az containerapp update -n mitigation-api -g "$RG" \
    --set-env-vars "GITHUB_REPO=$GITHUB_REPO" "GITHUB_TOKEN=secretref:github-token" -o none
fi

# aci-sp (optional)
if [ -n "$AZURE_CLIENT_SECRET" ]; then
  echo "==> wiring service-principal secrets"
  az containerapp secret set -n mitigation-api -g "$RG" --secrets "azure-client-secret=$AZURE_CLIENT_SECRET" -o none
  az containerapp update -n mitigation-api -g "$RG" \
    --set-env-vars "AZURE_TENANT_ID=$AZURE_TENANT_ID" "AZURE_CLIENT_ID=$AZURE_CLIENT_ID" "AZURE_CLIENT_SECRET=secretref:azure-client-secret" -o none
fi

echo "==> grant the API managed identity Contributor on the ACI resource group (aci mode)"
API_MI="$(az containerapp show -n mitigation-api -g "$RG" --query identity.principalId -o tsv)"
az role assignment create --assignee "$API_MI" --role Contributor \
  --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$ACI_RG" -o none || true

echo "==> UI container app"
az containerapp create \
  -n mitigation-ui -g "$RG" --environment "$ENVIRONMENT" \
  --image "$UI_IMAGE" \
  --ingress external --target-port 80 \
  --min-replicas 1 --max-replicas 1 \
  --cpu 0.25 --memory 0.5Gi \
  "${REG_ARGS[@]}" \
  -o none

API_FQDN="$(az containerapp show -n mitigation-api -g "$RG" --query properties.configuration.ingress.fqdn -o tsv)"
UI_FQDN="$(az containerapp show -n mitigation-ui -g "$RG" --query properties.configuration.ingress.fqdn -o tsv)"
echo
echo "API:  https://$API_FQDN   (docs: https://$API_FQDN/docs)"
echo "UI:   https://$UI_FQDN"
echo "In the UI, set 'API base URL' to https://$API_FQDN"
