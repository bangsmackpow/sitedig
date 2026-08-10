# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Stage 1: dependencies
# ---------------------------------------------------------------------------
FROM node:22-bookworm-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
# better-sqlite3 ships no prebuilt binary for this platform; its install script
# falls back to node-gyp, which needs Python and the toolchain.
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/* \
    && npm ci

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
# Ruby 3.1 moved `logger`/`base64` out of the default load path. wpscan's
# activesupport dependency references `Logger` without requiring it, so force
# both gems to be required at every Ruby process start.
ENV RUBYOPT="-rlogger -rbase64"

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
      g++ \
      libcurl4 \
      libxslt1.1 \
      libyaml-0-2 \
      make \
      nmap \
      openssl \
      python3 \
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
         # Ruby 3.1 moved `logger`/`base64` out of the default load path; wpscan's
         # activesupport dependency needs them at load time or it crashes.
         && gem install logger --no-document \
         && gem install base64 --no-document \
         && { wpscan --version || { echo '==== WPScan runtime failure - output below ===='; wpscan --version 2>&1 | tail -40; exit 1; }; }; \
       fi \
    && rm -rf /var/lib/apt/lists/* /tmp/*

# Non-root application user. HOME is set so Ruby tools (wpscan) can write caches.
RUN groupadd -r scanner && useradd -r -g scanner -d /app scanner

# --- Paid module tools --------------------------------------------------
# subfinder, dnsx, nuclei (ProjectDiscovery), feroxbuster, testssl.sh, retire.js.
# Pinned versions; static binaries extracted from GitHub release archives.
# NOTE: verify release asset names exist before bumping versions (a bad URL
# silently breaks the whole toolchain). The version gates below fail the build
# if any binary is missing or broken.
ARG SUBFINDER_VERSION=v2.6.7
ARG DNSX_VERSION=v1.2.3
ARG NUCLEI_VERSION=v3.11.1
ARG NUCLEI_TEMPLATES_VERSION=v10.4.7
ARG FEROXBUSTER_VERSION=v2.11.0
ARG TESTSSL_VERSION=v3.2.2
RUN apt-get update && apt-get install -y --no-install-recommends unzip bsdmainutils dnsutils procps which \
    && cd /tmp \
    && curl -fsSL "https://github.com/projectdiscovery/subfinder/releases/download/${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION#v}_linux_amd64.zip" -o subfinder.zip \
    && curl -fsSL "https://github.com/projectdiscovery/dnsx/releases/download/${DNSX_VERSION}/dnsx_${DNSX_VERSION#v}_linux_amd64.zip" -o dnsx.zip \
    && curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION#v}_linux_amd64.zip" -o nuclei.zip \
    && curl -fsSL "https://github.com/epi052/feroxbuster/releases/download/${FEROXBUSTER_VERSION}/x86_64-linux-feroxbuster.zip" -o ferox.zip \
    && curl -fsSL "https://github.com/drwetter/testssl.sh/archive/refs/tags/${TESTSSL_VERSION}.tar.gz" -o testssl.tar.gz \
    && for f in subfinder.zip dnsx.zip nuclei.zip ferox.zip; do unzip -o "$f"; done \
    && tar xzf testssl.tar.gz \
    && mv "testssl.sh-${TESTSSL_VERSION#v}" /opt/testssl \
    && chmod +x subfinder dnsx nuclei feroxbuster \
    && mv subfinder dnsx nuclei feroxbuster /usr/local/bin/ \
    # testssl.sh must run via bash with its own dir intact; use a shim.
    && printf '#!/bin/sh\nexec bash /opt/testssl/testssl.sh "$@"\n' > /usr/local/bin/testssl \
    && chmod +x /usr/local/bin/testssl \
    && npm install -g retire --silent \
    # Fail-fast runtime checks: every module binary must execute.
    && { subfinder -version && dnsx -version && nuclei -version && feroxbuster --version && retire --version && bash /opt/testssl/testssl.sh -V; } >/dev/null 2>&1 \
       || { echo 'ERROR: one or more module tools failed to run at runtime'; subfinder -version 2>&1; dnsx -version 2>&1; nuclei -version 2>&1; feroxbuster --version 2>&1; retire --version 2>&1; bash /opt/testssl/testssl.sh -V 2>&1; exit 1; } \
    # Curated, non-destructive Nuclei template set (allowlist). Installed from a
    # pinned nuclei-templates tarball (deterministic; no HOME/config dependency).
    # FAIL the build if any allowlisted template file is missing.
    && mkdir -p /opt/nuclei-templates \
    && curl -fsSL "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/${NUCLEI_TEMPLATES_VERSION}.tar.gz" -o nuclei-templates.tar.gz \
    && tar xzf nuclei-templates.tar.gz -C /opt/nuclei-templates --strip-components=1 \
    && for t in \
         http/technologies/tech-detect.yaml \
         http/exposures/configs/git-config.yaml \
         ssl/tls-version.yaml \
         ssl/deprecated-tls.yaml \
         ssl/self-signed-ssl.yaml \
         ssl/expired-ssl.yaml \
         ssl/weak-cipher-suites.yaml; do \
         test -f "/opt/nuclei-templates/$t" || { echo "ERROR: nuclei template missing: $t"; exit 1; }; \
       done \
    && rm -rf /tmp/* /var/lib/apt/lists/* \
    && apt-get purge -y unzip

WORKDIR /app
COPY --from=build /app/package.json /app/package-lock.json ./
# Production dependencies only. `--omit=optional` drops Next.js's bundled
# `sharp` image-optimization stack (~100MB+ of platform binaries), which this
# app never uses (image optimization is disabled in next.config).
RUN npm ci --omit=dev --omit=optional && npm cache clean --force
# Build outputs.
COPY --from=build /app/.next ./.next
COPY --from=build /app/dist-worker ./dist-worker
COPY --from=build /app/next.config.mjs ./
COPY --from=build /app/public ./public
# Content-discovery wordlist.
COPY --chown=scanner:scanner assets/wordlists/common.txt /opt/sitedig/wordlists/common.txt

# Artifact workspace owned by the scanner user.
RUN mkdir -p /tmp/sitedig-artifacts /data && chown -R scanner:scanner /app /tmp/sitedig-artifacts /opt/sitedig /data

USER scanner
ENV HOME=/app

EXPOSE 3000 8081

# Web service entrypoint (also used by Compose to start the worker).
CMD ["node", "node_modules/next/dist/bin/next", "start", "-p", "3000"]
