#!/bin/sh
# The API needs no host Docker daemon: scenarios run in-process ("inmemory") or
# are delegated to Azure ACI / GitHub Actions. Private-registry access for the
# github-ghcr relay is handled in-process from the JFROG_* env vars.
exec /app/api
