# syntax=docker/dockerfile:1
# VLH-CTF — ASLV M1 aslv-edge. FOUR build targets (compose picks by --target):
#
#   gateway-full        nginx:1.27-alpine, full-chain vhost gateway (host 18024)
#   gateway-standalone  nginx:1.27-alpine, M1 standalone gateway (host 18021)
#   edgefront           scratch, static raw TCP edge proxy (:8080)
#                       — compose should ALSO expose this port directly on the
#                       host (see README: deterministic desync labs): suggested
#                       18027 (m1 profile) / 18028 (full profile)
#   edgeback            alpine, raw HTTP origin + mini collector (:8081/:8090)
#                       (alpine instead of scratch so the specified sh
#                       entrypoint can generate the flag at start; edgefront
#                       stays pure scratch/static)

# ---- shared Go build stage -----------------------------------------------
FROM golang:1.23-alpine AS gobuild
WORKDIR /src
COPY go.mod ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/edgefront ./cmd/edgefront \
 && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/edgeback ./cmd/edgeback

# ---- target: gateway-full ------------------------------------------------
FROM nginx:1.27-alpine AS gateway-full
# conf.d-style file (upstreams + server blocks only — no events/http wrapper;
# the stock nginx.conf of the base image provides the http{} context).
COPY conf/gateway-full.conf /etc/nginx/conf.d/default.conf
EXPOSE 80

# ---- target: gateway-standalone -------------------------------------------
FROM nginx:1.27-alpine AS gateway-standalone
COPY conf/gateway-standalone.conf /etc/nginx/conf.d/default.conf
EXPOSE 80

# ---- target: edgefront ----------------------------------------------------
FROM scratch AS edgefront
COPY --from=gobuild /out/edgefront /edgefront
ENV EDGE_MODE=cl-te \
    EDGE_BACK=edge-back:8081 \
    LISTEN=:8080 \
    INTERNAL_HOST=internal.aslv.lab
EXPOSE 8080
ENTRYPOINT ["/edgefront"]

# ---- target: edgeback -----------------------------------------------------
FROM alpine:3.20 AS edgeback
COPY --from=gobuild /out/edgeback /usr/local/bin/edgeback
COPY entrypoint-edgeback.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && mkdir -p /data /registry
ENV LISTEN=:8081 \
    COLLECTOR_LISTEN=:8090 \
    DATA_DIR=/data \
    REGISTRY_DIR=/registry \
    INTERNAL_HOST=internal.aslv.lab \
    ACTIVITY_SINK=
EXPOSE 8081 8090
ENTRYPOINT ["/entrypoint.sh"]
