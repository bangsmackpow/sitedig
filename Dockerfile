# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Stage 1: dependencies
# ---------------------------------------------------------------------------
FROM node:22-bookworm-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

# ---------------------------------------------------------------------------
# Stage 2: build
# ---------------------------------------------------------------------------
FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ARG APP_VERSION=0.1.0
ENV APP_VERSION=${APP_VERSION}
# Builds the scanner worker (tsc -> dist-worker) and the Next.js web app.
RUN npm run build

# ---------------------------------------------------------------------------
# Stage 3: runtime
# ---------------------------------------------------------------------------
FROM node:22-bookworm-slim AS runtime

ENV NODE_ENV=production
ARG APP_VERSION=0.1.0
ENV APP_VERSION=${APP_VERSION}

# Scanner tools + system dependencies.
# - nmap: TCP connect scans (no raw sockets / no root required)
# - whatweb: web technology detection
# - curl: available for operators and health checks
# - openssl/ca-certificates: TLS checks
# WPScan is a Ruby gem; it is optional and installed only when INSTALL_WPSCAN=true.
# NOTE: keep ALL build/apt packages after installing wpscan. Its native
# extensions (curb/nokogiri/rugged) link against runtime libraries; purging
# or `autoremove` after install breaks wpscan at load time. The `wpscan
# --version` gate below fails the build if this ever regresses.
ARG INSTALL_WPSCAN=true
ARG WPSCAN_VERSION=3.8.25
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      nmap \
      openssl \
      whatweb \
    && if [ "$INSTALL_WPSCAN" = "true" ]; then \
         apt-get install -y --no-install-recommends \
           build-essential \
           git \
           libcurl4-openssl-dev \
           libxml2 \
           libxml2-dev \
           libxslt1-dev \
           pkg-config \
           ruby \
           ruby-dev \
           zlib1g-dev \
         && gem install wpscan --no-document -v "$WPSCAN_VERSION" \
         && wpscan --version >/dev/null 2>&1 || { echo 'ERROR: wpscan failed to run at runtime (missing native libraries)'; exit 1; }; \
       fi \
    && rm -rf /var/lib/apt/lists/* /tmp/*

# Non-root application user. HOME is set so Ruby tools (wpscan) can write caches.
RUN groupadd -r scanner && useradd -r -g scanner -d /app scanner

WORKDIR /app
COPY --from=build /app/package.json /app/package-lock.json ./
# Production dependencies only.
RUN npm ci --omit=dev && npm cache clean --force
# Build outputs.
COPY --from=build /app/.next ./.next
COPY --from=build /app/dist-worker ./dist-worker
COPY --from=build /app/next.config.mjs ./
COPY --from=build /app/public ./public

# Artifact workspace owned by the scanner user.
RUN mkdir -p /tmp/sitedig-artifacts && chown -R scanner:scanner /app /tmp/sitedig-artifacts

USER scanner
ENV HOME=/app

EXPOSE 3000 8081

# Web service entrypoint (also used by Compose to start the worker).
CMD ["node", "node_modules/next/dist/bin/next", "start", "-p", "3000"]
