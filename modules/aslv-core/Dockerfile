# syntax=docker/dockerfile:1
# VLH-CTF — ASLV M0 aslv-core.
# Multi-target image:
#   target "collector" — Go activity sink + event-verified flag minter (scratch, CGO_ENABLED=0)
#   target "stubs"     — one image, three services via env STUB=auth|portal|mail (node:20-slim)
#
# Build:
#   docker build --target collector -t vlh-aslv-collector:1.0.0 ./modules/aslv-core
#   docker build --target stubs     -t vlh-aslv-stubs:1.0.0     ./modules/aslv-core
# Compose selects STUB per service (stub-auth / stub-portal / stub-mail).

# ---------------------------------------------------------------- collector
FROM golang:1.23-alpine AS build-collector
WORKDIR /src
COPY go.mod ./
COPY cmd/ ./cmd/
# stdlib-only module: `go mod tidy` is a no-op safety net (no external deps, no go.sum needed)
RUN go mod tidy && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/collector ./cmd/collector

FROM alpine:3.20 AS prep-collector
RUN mkdir -p /data /registry && chown -R 1000:1000 /data /registry

FROM scratch AS collector
LABEL 811911.vlh=1 aslv.module=m0 aslv.service=collector
COPY --from=build-collector /out/collector /collector
# pre-owned dirs so named volumes mounted at /data and /registry stay writable for uid 1000
COPY --from=prep-collector --chown=1000:1000 /data /data
COPY --from=prep-collector --chown=1000:1000 /registry /registry
USER 1000:1000
ENV COLLECTOR_PORT=8090 \
    DATA_DIR=/data \
    REGISTRY_DIR=/registry \
    ATTACKER_HOST=attacker.aslv.lab \
    PORTAL_INTERNAL_URL=http://portal:3000
EXPOSE 8090
ENTRYPOINT ["/collector"]

# -------------------------------------------------------------------- stubs
FROM node:20-slim AS stubs
LABEL 811911.vlh=1 aslv.module=m0 aslv.service=stubs
RUN mkdir -p /app /data && chown -R node:node /app /data
WORKDIR /app
COPY --chown=node:node stub/ ./stub/
COPY --chown=node:node entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh
USER node
ENV STUB=portal \
    PORT=3000 \
    SMTP_PORT=1025 \
    DATA_DIR=/data
EXPOSE 3000 1025
ENTRYPOINT ["/app/entrypoint.sh"]
