#!/bin/sh
# Optionally authenticate to a private registry (e.g. JFrog Artifactory) before
# serving, so the worker can pull substrate images from it. No-op when the
# JFROG_* vars are unset. A login failure is logged but does not block startup
# (public images still pull).

if [ -n "$JFROG_REGISTRY" ] && [ -n "$JFROG_USER" ] && [ -n "$JFROG_TOKEN" ]; then
  echo "entrypoint: docker login to $JFROG_REGISTRY as $JFROG_USER"
  echo "$JFROG_TOKEN" | docker login "$JFROG_REGISTRY" -u "$JFROG_USER" --password-stdin \
    || echo "entrypoint: docker login to $JFROG_REGISTRY failed; continuing"
fi

exec /app/api
