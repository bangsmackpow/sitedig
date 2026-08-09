<div align="center">

# SiteDig

**Run authorized reconnaissance scans against targets you own or are permitted to test — and get polished PDF & Markdown reports.**

Built with Next.js + a dedicated TypeScript scanner worker. Ships as a single public GHCR image and deploys to Portainer behind Nginx Proxy Manager.

</div>

---

## What it does

SiteDig executes a bounded, TCP-only reconnaissance scan of a domain, hostname, IPv4, IPv6, or full URL using safe, detection-oriented Linux tools — `nmap` (TCP connect), `whatweb`, `curl`/HTTP header inspection, in-process TLS certificate inspection, and conditional local-only `wpscan`. Each scan produces a **dual-format report** (client-facing executive summary + technical appendix) that you download as a **PDF** or **Markdown** file.

It is **not** a vulnerability scanner. It never runs exploitation, brute force, UDP, all-port, or CIDR scans, and it performs no external vulnerability-database lookups.

## Features

- **Four scan profiles** — Quick, Standard, Deep, and a bounded Custom profile, each with plain-language scope, tool, noise, and duration descriptions shown before you scan.
- **Strict target safety** — RFC1918, loopback, link-local, multicast, reserved, documentation, IPv6 ULA, and cloud-metadata addresses are rejected. DNS is re-validated before *every* tool, DNS rebinding is detected, and every HTTP redirect destination is safety-checked.
- **Authorization gate** — a consent modal with a required checkbox must be acknowledged for **every** scan.
- **Lifecycle transparency** — simple `queued → running → completed / failed / cancelled` status, with the option to cancel a queued or running scan.
- **Separate downloads** — one-click PDF and Markdown, generated from the same normalized report model (no content drift).
- **Hard limits** — configurable concurrency, queue depth, per-tool output caps, and a 5-minute maximum scan duration enforced with process-group cleanup.
- **Server-side logging** — verbose, structured logs to Docker/Portainer; logs are never exposed in the UI or reports.
- **No persistence** — no database, no Redis, no stored history. Artifacts are deleted after download or TTL sweep.
- **One image, two roles** — Compose runs the same GHCR image as `web` and `worker` services.

## Architecture

```
Browser ── HTTPS ──> Nginx Proxy Manager ──> web (Next.js, port 3000)
                                              │  internal HTTP + bearer token
                                              ▼
                                         worker (scanner, port 8081)
                                              │  execa(argv[]) — no shell
                                              ▼
                                   nmap · whatweb · HTTP/TLS · wpscan*
                                              │
                                              ▼
                                   PDF + Markdown artifacts (temp, TTL-swept)
```

- **web** — renders the UI, validates input with Zod, enforces consent, proxies jobs/status/downloads. Never executes scanner commands.
- **worker** — owns the in-memory queue, re-validates targets, executes approved commands as argv arrays, enforces timeouts, and renders reports.

The worker API is only reachable on the internal Docker network and is protected by a shared bearer token.

## Quick start (local development)

```bash
npm install

# Terminal 1 — scanner worker (stub tools are used in tests only; local dev
# expects real tools on PATH, or set SCANNER_BIN_DIR to a stub dir)
npm run dev:worker

# Terminal 2 — Next.js UI at http://localhost:3000
npm run dev
```

Set `WORKER_URL=http://localhost:8081` and (optionally) `SCAN_SERVICE_TOKEN` in your environment.

> Local Windows/macOS dev without `nmap`/`whatweb`/`wpscan` will still boot; scanner steps fail gracefully and are recorded as tool errors in the report. The Docker image includes all tools.

## Deploying with Docker / Portainer

### 1. Pre-requisites

- A host running Docker + Portainer.
- An existing **external Docker network** that Nginx Proxy Manager is attached to (default network name: `backend` — change it in the stack if yours differs).
- The GHCR image is **public**: `ghcr.io/bangsmackpow/sitedig`.

### 2. Portainer stack

In Portainer: **Stacks → Add stack**, choose the repo or paste this compose file, and add environment variables (see [Configuration](#configuration)).

```yaml
name: sitedig

services:
  web:
    image: ghcr.io/bangsmackpow/sitedig:latest
    command: ["node", "node_modules/next/dist/bin/next", "start", "-p", "3000"]
    environment:
      WORKER_URL: http://worker:8081
      SCAN_SERVICE_TOKEN: ${SCAN_SERVICE_TOKEN}
      LOG_LEVEL: ${LOG_LEVEL:-info}
    networks: [backend]
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://localhost:3000/api/health"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 20s
    deploy:
      resources:
        limits: { cpus: "0.5", memory: 512M }

  worker:
    image: ghcr.io/bangsmackpow/sitedig:latest
    command: ["node", "dist-worker/worker/index.js"]
    environment:
      SCAN_SERVICE_TOKEN: ${SCAN_SERVICE_TOKEN}
      MAX_CONCURRENT_SCANS: ${MAX_CONCURRENT_SCANS:-1}
      MAX_QUEUE: ${MAX_QUEUE:-3}
      SCAN_TIMEOUT_MS: ${SCAN_TIMEOUT_MS:-300000}
      ALLOW_INTERNAL_TARGETS: "false"
      ARTIFACT_TTL_MINUTES: ${ARTIFACT_TTL_MINUTES:-30}
      LOG_LEVEL: ${LOG_LEVEL:-info}
    networks: [backend]
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://localhost:8081/health"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 20s
    deploy:
      resources:
        limits: { cpus: "1.0", memory: 1G }

networks:
  backend:
    external: true
```

No host ports are published — the stack is only reachable through Nginx Proxy Manager on the `backend` network.

### 3. Nginx Proxy Manager

Create a **Proxy Host**:

| Field | Value |
| --- | --- |
| Domain Names | your public domain |
| Scheme | `http` |
| Forward Hostname/IP | `web` |
| Forward Port | `3000` |
| WebSockets | off |
| SSL | Force SSL (or as desired) |

### 4. Upgrade

```bash
# Pull the latest tag and redeploy the stack (Portainer: Recreate)
docker compose pull && docker compose up -d
```

## Configuration

| Variable | Service | Default | Description |
| --- | --- | --- | --- |
| `SITEDIG_IMAGE` | both | `ghcr.io/bangsmackpow/sitedig` | GHCR image name |
| `SITEDIG_TAG` | both | `latest` | Image tag |
| `SCAN_SERVICE_TOKEN` | both | — | **Required.** Shared secret between web and worker. Change it. |
| `WORKER_URL` | web | `http://worker:8081` | Worker HTTP base URL |
| `WEB_PORT` | web | `3000` | Internal web port |
| `WORKER_PORT` | worker | `8081` | Internal worker port |
| `MAX_CONCURRENT_SCANS` | worker | `1` | Concurrently executing scans |
| `MAX_QUEUE` | worker | `3` | Additional queued scans |
| `SCAN_TIMEOUT_MS` | worker | `300000` | Hard per-scan cap (max 300000) |
| `MAX_TOOL_OUTPUT_BYTES` | worker | `20971520` | Max captured output per tool |
| `ALLOW_INTERNAL_TARGETS` | worker | `false` | **Keep false on public deployments.** Allows RFC1918/private targets. |
| `ARTIFACT_DIR` | worker | `/tmp/sitedig-artifacts` | Temp report storage |
| `ARTIFACT_TTL_MINUTES` | worker | `30` | Minutes before finished artifacts are swept |
| `LOG_LEVEL` | both | `info` | `debug`, `info`, `warn`, `error`, `silent` |
| `APP_VERSION` | both | `0.1.0` | Version string reported in logs |
| `ENABLED_MODULES` | worker | *(empty)* | Comma-separated paid module ids to unlock |
| `WPSCAN_API_TOKEN` | worker | *(empty)* | WPScan API token for plugin/theme vulnerability data |
| `NUCLEI_TEMPLATES` | worker | `http/misconfiguration,http/exposed-panels,http/headers,ssl,exposures/configs` | Nuclei template allowlist |
| `NUCLEI_TEMPLATES_DIR` | worker | `/opt/nuclei-templates` | Nuclei template directory |
| `CONTENT_WORDLIST` | worker | `/opt/sitedig/wordlists/common.txt` | Wordlist for content discovery |

## Target safety model

Rejected at queue time and re-validated before **every** tool run:

- IPv4: RFC1918, loopback, link-local (incl. `169.254.169.254` metadata), CGNAT, multicast, TEST-NET documentation ranges, reserved/broadcast.
- IPv6: loopback, unspecified, ULA (`fc00::/7`), link-local, multicast, NAT64, Teredo, 6to4, documentation, IPv4-mapped private.
- HTTP redirect destinations are resolved and validated before being followed.
- DNS rebinding (a hostname resolving differently between checks) aborts the scan.

These checks live in `src/shared/net.ts` and are heavily unit-tested.

## Scanning profiles

| Profile | Port scope | Typical duration | Notes |
| --- | --- | --- | --- |
| **Quick** | Common ports (curated) | ~30–60s | Low noise; fast first look |
| **Standard** | Top 100 TCP | ~1–3 min | Expanded service/version detection |
| **Deep** | Top 1,000 TCP | up to 5 min | Detailed enumeration, still hard-capped |
| **Custom** | common / top100 / top1000 | user-selected | Bounded controls only — no raw args |

All profiles share one command pipeline, so safety rules cannot be bypassed by profile choice.

## Paid add-on modules

SiteDig ships a set of **env-gated add-on modules** (the paid-feature architecture). Set `ENABLED_MODULES` to a comma-separated list to unlock them; an empty value keeps the detection-only free behavior. Modules requested from the UI are rejected server-side with `403 module_not_enabled` when disabled.

| Module | Env id | Tools | What it adds |
| --- | --- | --- | --- |
| Asset & DNS Discovery | `asset-discovery` | subfinder, dnsx, WHOIS (RDAP) | Passive subdomain enumeration, DNS records, registration intel |
| Vulnerability Scan | `vuln-scan` | nuclei (curated allowlist), retire.js | Template-driven detection + vulnerable-JS checks |
| TLS Hardening Audit | `tls-hardening` | testssl.sh | Protocols, ciphers, known TLS weaknesses |
| Content Discovery | `content-discovery` | feroxbuster | Rate-limited directory/path discovery against a bounded wordlist |
| CVE Context | `cve-context` | OSV API | Enrich detected technologies with known-CVE counts |

Each module's tools are guarded by argument allowlists (`assertApprovedArgs`), per-tool timeouts, and non-destructive template/wordlist policies. The vulnerability-scan module runs **only** the curated `NUCLEI_TEMPLATES` allowlist.

## Report contents

Each report includes:

- Scan metadata (target, host, path, profile, port scope, timestamps, tool versions)
- Executive summary with severity roll-up and key observations
- Findings with category (`Exposure`, `Misconfiguration`, `Outdated Technology`, `WordPress Finding`, `Informational`), severity, evidence, confidence, and remediation
- Discovered ports/services, HTTP observations (headers, security headers, redirects), TLS certificate details, detected technologies, and WordPress notes
- Sanitized tool execution summary and explicit limitations

Severity ratings are **inferred** from observed evidence and clearly flagged as such; the report states that this is a detection-oriented reconnaissance report, not a vulnerability assessment.

## CI/CD

`.github/workflows/ci.yml`:

1. Installs dependencies, lints, typechecks (web + worker), runs all tests.
2. Validates `docker-compose.yml` (via a Node script and `docker compose config`).
3. On pushes to `main` or version tags, builds `linux/amd64`, pushes to **public GHCR** (`latest` + `sha-…` or `vX.Y.Z`), and runs a Trivy vulnerability scan.

## Development

```bash
npm run lint           # next lint (web + shared)
npm run typecheck      # tsc (web) + tsc (worker)
npm test               # vitest — 71 tests, including stub-tool integration tests
npm run build          # worker compile + Next.js production build
npm run validate:compose
```

Test scanners are Node stubs under `tests/fixtures/stub-bin/` — the test suite never scans real targets.

## Security notes

- Commands are built as argv arrays and executed with `execa` — **no shell interpolation**, and arguments are asserted against an allowlist (`assertApprovedArgs`).
- The worker runs as a **non-root** user; `nmap -sT` (TCP connect) requires no raw sockets or `privileged: true`.
- Web and worker are process-isolated; the worker is only reachable on the internal network behind a bearer token.
- Reports never include raw tool output; troubleshooting logs stay in Docker/Portainer.

## Known limitations

- Detection-oriented only — no exploit validation or vulnerability confirmation.
- External vulnerability APIs (e.g. WPScan API tokens) are intentionally not integrated.
- `npm audit` reports transitive `postcss`/`sharp` advisories from the Next.js 15 toolchain; these are build/runtime-image-optimization dependencies this app does not exercise. Upgrading to Next 16 (a breaking change) resolves them and is a recommended follow-up.

## Roadmap (explicitly deferred)

Authentication & accounts, persistent scan history, Redis-backed queues, CIDR scanning, scan comparison/diffs, custom branding, UDP/all-port scanning, and external vulnerability APIs.

## License

MIT
