#!/bin/sh
# Runs as root: make the mounted docker socket reachable by the non-root app
# user, then drop privileges. Postgres refuses to run as root, so the API (and
# the embedded Postgres it starts) must run as a non-root user.
set -e

if [ -S /var/run/docker.sock ]; then
  chown app /var/run/docker.sock 2>/dev/null || true
  chmod o+rw /var/run/docker.sock 2>/dev/null || true
fi

exec runuser -u app -- /app/api
