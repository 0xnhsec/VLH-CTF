# syntax=docker/dockerfile:1
# VLH-CTF DSLTV shared base image.
# Every subclass builds FROM this image and adds only vuln.js (+ optional seed.js).
FROM node:20-slim

# build deps fallback for better-sqlite3 native builds (prebuilt binaries usually win)
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force

COPY runtime.js entrypoint.sh ./
RUN chmod +x entrypoint.sh

ENV NODE_ENV=production \
    LISTEN_PORT=8080 \
    LAB_DOMAIN=target.lab \
    DATA_DIR=/data \
    REGISTRY_DIR=/registry

EXPOSE 8080
ENTRYPOINT ["./entrypoint.sh"]
