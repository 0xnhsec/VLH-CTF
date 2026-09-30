# syntax=docker/dockerfile:1
# VLH-CTF — ASLV M5 aslv-identity (Node/Express authorization server + client app).
#
# Build: docker build -t vlh-aslv-identity:1.0.0 ./modules/aslv-identity

FROM node:20-slim
LABEL 811911.vlh=1 aslv.module=m5

# python3/make/g++ are a fallback for better-sqlite3 native builds
# (prebuilt binaries usually win on node:20).
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app /data /registry && chown -R node:node /app /data /registry
WORKDIR /app

COPY --chown=node:node package.json ./
RUN npm install --omit=dev && npm cache clean --force

COPY --chown=node:node src/ ./src/
COPY --chown=node:node entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

USER node
ENV PORT=3000 \
    DATA_DIR=/data \
    REGISTRY_DIR=/registry \
    LAB_DOMAIN=aslv.lab \
    SMTP_HOST="" \
    MAIL_HTTP_URL=http://stub-mail:3000 \
    PORTAL_INTERNAL_URL="" \
    AUTH_ORIGIN=http://auth.aslv.lab:18026 \
    CLIENT_REDIRECT_URI=http://client.aslv.lab/client/callback \
    ACTIVITY_SINK=""
EXPOSE 3000
ENTRYPOINT ["/app/entrypoint.sh"]
