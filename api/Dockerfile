# Build the Go API binary.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/api .

# Runtime image. Includes the docker CLI because the worker launches the
# validation-substrate container on the host daemon (mounted docker.sock).
FROM alpine:3.20
RUN apk add --no-cache docker-cli ca-certificates
WORKDIR /app
COPY --from=build /out/api /app/api

ENV PORT=8137
ENV MC_DATA_DIR=/app/data/runs
# Ledger lives on a mounted volume so it survives docker stop/rm.
VOLUME ["/app/data"]
EXPOSE 8137

ENTRYPOINT ["/app/api"]
