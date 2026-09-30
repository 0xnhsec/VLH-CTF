# syntax=docker/dockerfile:1
# VLH-CTF — ASLV M2 aslv-portal (Express, minimal — no CSRF/cors middleware on
# purpose). Listens internally on :3000 behind the module sidecar (standalone,
# host 18022) or the full-mode gateway (collector/attacker/aslv vhosts).
FROM node:20-slim

# build deps for better-sqlite3 native builds (prebuilt binaries usually win)
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force

COPY src ./src
COPY entrypoint.sh ./
RUN chmod +x entrypoint.sh

ENV NODE_ENV=production \
    LISTEN_PORT=3000 \
    LAB_DOMAIN=aslv.lab \
    DATA_DIR=/data \
    REGISTRY_DIR=/registry \
    STANDALONE=1 \
    PORTAL_PORT=18022 \
    ACTIVITY_SINK=

EXPOSE 3000
ENTRYPOINT ["./entrypoint.sh"]
