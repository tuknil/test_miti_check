# Build the Go API binary.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/api .

# Runtime image. Includes the docker CLI because the worker launches the
# validation-substrate container on the host daemon (mounted docker.sock).
# Runs as root so it can reach the root-owned docker socket; Postgres now lives
# in its own container, so there is no non-root requirement here.
FROM alpine:3.20
RUN apk add --no-cache docker-cli ca-certificates
WORKDIR /app
COPY --from=build /out/api /app/api
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV PORT=8137
EXPOSE 8137

# Entrypoint optionally logs in to a private registry (JFROG_*), then execs the API.
ENTRYPOINT ["/entrypoint.sh"]
