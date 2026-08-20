#!/bin/sh
# Runs from nginx's /docker-entrypoint.d at startup. Renders env.js from the
# API_BASE env var so the static UI can pick up the API endpoint per deploy.
set -e
: "${API_BASE:=http://localhost:8137}"
export API_BASE
envsubst '${API_BASE}' \
  < /usr/share/nginx/html/env.js.template \
  > /usr/share/nginx/html/env.js
echo "mc-ui: API_BASE=$API_BASE"
