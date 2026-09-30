# syntax=docker/dockerfile:1
# VLH-CTF — ASLV M4 aslv-api (Go REST API, modernc.org/sqlite, CGO disabled).
#
# Build: docker build -t vlh-aslv-api:1.0.0 ./modules/aslv-api
#
# NOTE: go.sum is committed so the build verifies module checksums locally
# (modernc.org/sqlite and transitive deps). `go mod download` fetches deps
# from the module proxy once at build time; GOSUMDB=off avoids a hard
# dependency on sum.golang.org (unreachable from container network). RUNTIME
# is fully offline (NFR-1).

FROM golang:1.23-alpine AS build
WORKDIR /src
ENV GOSUMDB=off
COPY go.mod go.sum ./
COPY cmd/ ./cmd/
RUN go mod download && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/server

FROM alpine:3.20
LABEL 811911.vlh=1 aslv.module=m4
RUN adduser -D -u 1000 api && mkdir -p /data /registry && chown -R 1000:1000 /data /registry
COPY --from=build /out/api /app/api
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh /app/api
USER 1000
ENV API_PORT=8080 \
    DATA_DIR=/data \
    REGISTRY_DIR=/registry \
    JWKS_URL=http://identity:3000/jwks.json \
    ACTIVITY_SINK="" \
    LAB_DOMAIN=aslv.lab
EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]
