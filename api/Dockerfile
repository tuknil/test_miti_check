# Build the Go API binary.
FROM artifact.it.att.com/astra-secure-container-catalog/go:1.26.5 AS build

ENV GOPROXY=https://nm2553@att.com:cmVmdGtuOjAxOjE4MTg1MTYxOTE6WFg1VDFnd1Y5aDVYalFzT1lCbEs2ckQ4UmJa@artifact.it.att.com/artifactory/api/go/att-go-public-group
ENV GONOSUMDB=off
ENV GOPRIVATE=it.att.com
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/api .

# Runtime image. Includes the docker CLI because the worker launches the
# validation-substrate container on the host daemon (mounted docker.sock).
# Runs as root so it can reach the root-owned docker socket; Postgres now lives
# in its own container, so there is no non-root requirement here.
FROM  artifact.it.att.com/docker-hub/debian:bookworm-slim 
ENV GOPROXY=https://nm2553@att.com:cmVmdGtuOjAxOjE4MTg1MTYxOTE6WFg1VDFnd1Y5aDVYalFzT1lCbEs2ckQ4UmJa@artifact.it.att.com/artifactory/api/go/att-go-public-group
ENV GONOSUMDB=off
ENV GOPRIVATE=it.att.com
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
