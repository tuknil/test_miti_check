# Build the Go API binary (CGO off; pgx + embedded-postgres are pure Go).
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/api .

# Runtime: Debian (glibc) because the embedded Postgres binaries are glibc-linked
# and will not run on Alpine/musl.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates util-linux \
    && rm -rf /var/lib/apt/lists/*

# docker CLI: the worker launches the validation-substrate container on the host
# daemon (mounted docker.sock).
COPY --from=docker:cli /usr/local/bin/docker /usr/local/bin/docker

# Postgres refuses to run as root, so run as a non-root user. Add it to group 0
# (root) so it can access the root:root-owned docker socket.
RUN useradd -u 1000 -m -s /usr/sbin/nologin app && usermod -aG 0 app

WORKDIR /app
COPY --from=build /out/api /app/api
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
# Own /app/data as app:0 so the (empty) named volume inherits writable ownership.
RUN mkdir -p /app/data && chown -R app:0 /app/data && chmod -R g+rwX /app/data

ENV PORT=8137
ENV MC_DATA_DIR=/app/data
EXPOSE 8137
VOLUME ["/app/data"]

# Starts as root (to fix docker.sock perms), then drops to the app user.
ENTRYPOINT ["/entrypoint.sh"]
