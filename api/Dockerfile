# Build the Go API binary.
FROM artifact.it.att.com/astra-secure-container-catalog/go:1.26.5 AS build

ENV GONOSUMDB=off \
    GOPRIVATE=it.att.com
WORKDIR /src
COPY go.mod go.sum ./
COPY third_party/jsonschema ./third_party/jsonschema
RUN --mount=type=secret,id=go_proxy,required=false \
    --mount=type=secret,id=jfrog_username,required=false \
    --mount=type=secret,id=jfrog_access_token,required=false \
    set -eu; \
    if [ -s /run/secrets/go_proxy ]; then \
        export GOPROXY="$(cat /run/secrets/go_proxy)"; \
    elif [ -s /run/secrets/jfrog_username ] && [ -s /run/secrets/jfrog_access_token ]; then \
        printf 'machine artifact.it.att.com login %s password %s\n' "$(cat /run/secrets/jfrog_username)" "$(cat /run/secrets/jfrog_access_token)" > /root/.netrc; \
        chmod 0600 /root/.netrc; \
        export GOPROXY='https://artifact.it.att.com/artifactory/api/go/apm0047460-go-group'; \
    else \
        echo 'approved Go proxy credentials are required' >&2; exit 1; \
    fi; \
    go mod download; \
    rm -f /root/.netrc
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/api .

# Runtime image. Includes the docker CLI because the worker launches the
# validation-substrate container on the host daemon (mounted docker.sock), and
# runs as root so it can reach the root-owned docker socket. The run ledger uses
# a container/remote Postgres via DATABASE_URL — nothing runs a database here.
FROM artifact.it.att.com/docker-hub/debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/false app
# docker CLI: the worker launches the validation-substrate container on the host
# daemon (mounted docker.sock).
COPY --from=artifact.it.att.com/docker-hub/docker:cli /usr/local/bin/docker /usr/local/bin/docker

WORKDIR /app
COPY --from=build /out/api /app/api
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV PORT=8137
EXPOSE 8137

ENTRYPOINT ["/entrypoint.sh"]
