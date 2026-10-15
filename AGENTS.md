# AGENTS.md

Guidance for AI agents working in this repository.

## Project

SiteDig — an authorized, detection-oriented reconnaissance scanner. Next.js 15 (App Router) **web** service + a separate TypeScript **worker** that executes scanner tools. One Docker image, two Compose services (`web`, `worker`). SQLite (`better-sqlite3`) for accounts, sessions, entitlements, billing, MFA state, and scan-history metadata. See `README.md` for the full feature set and `DEEPSEEK-V4-FLASH-IMPLEMENTATION.md` for the original handoff.

## Commands

```bash
npm install
npm run dev            # Next.js web at http://localhost:3000
npm run dev:worker     # scanner worker (needs tools on PATH, or SCANNER_BIN_DIR)
npm run lint           # next lint (src)
npm run typecheck      # tsc web + worker
npm test               # vitest (stub tools; never scans real targets)
npm run build          # worker compile + Next.js production build
npm run validate:compose
node scripts/generate-icons.mjs   # regenerate apple-icon.png + favicon.ico from icon.svg
```

Run `npm run lint`, `npm run typecheck`, and `npm test` before declaring work complete. CI (`.github/workflows/ci.yml`) runs all three plus a Docker build/Trivy scan on `main`.

## Architecture boundaries (do not violate)

- The **web** service never executes scanner commands; it only talks to the worker over HTTP with a shared bearer token (`SCAN_SERVICE_TOKEN`).
- The **worker** owns the queue, re-validates targets before every tool, and runs commands as **argv arrays** via `execa` — never shell strings. Generated args are asserted with `assertApprovedArgs` (`src/shared/profiles.ts`).
- Target safety rules live in `src/shared/net.ts` and `src/worker/dns.ts` and are security-critical. Never weaken blocked-range or DNS-rebinding checks.
- Shared code (types, schemas, config, profiles, report model) lives in `src/shared/` and is imported by both services.

## Conventions

- Validate all external input with **Zod** (`src/shared/schemas.ts`, route handlers).
- Web routes: guard with `guardUser`/`guardAdmin` (`src/server/http.ts`); mutating requests call `verifyCsrfOrOrigin` (`src/server/auth/csrf.ts`).
- DB changes are **additive migrations** appended to the `MIGRATIONS` array in `src/server/db.ts` (bump `version`). Never edit a shipped migration.
- Reports are never stored. Scan history persists metadata + finding counts only.
- Do not add code comments unless they explain non-obvious intent.

## Subsystems added recently

- **Email** (`src/server/email/`): provider-selectable `Mailer` — Resend (REST via `fetch`, no SDK) or SMTP. Chosen by `EMAIL_PROVIDER`; defaults to Resend when `RESEND_API_KEY` is set. Templates in `templates.ts`.
- **MFA** (`src/server/auth/mfa.ts`): email OTP + TOTP (RFC 6238, `node:crypto`) + recovery codes. Login issues a challenge and only creates a session after verification (`/api/auth/mfa/verify`). Enrollment via `/api/account/mfa`.
- **Scan history** (`src/server/scans.ts`): the worker POSTs a report-free summary to `POST /api/internal/scan-events` (bearer token); the web upserts `scans`/`scan_tools`. UIs: `/history` (user) and `/admin/scans` (admin analytics + CSV).
- **Digest** (`src/server/digest.ts`, `src/instrumentation.ts`): hourly in-process tick sends the daily admin digest and sweeps scan history.

## Environment

`.env.example` is the authoritative list. New vars: `EMAIL_PROVIDER`, `RESEND_API_KEY`, `EMAIL_FROM`, `WEB_BASE_URL` (worker), `SCAN_HISTORY_RETENTION_DAYS`, `ADMIN_DIGEST_ENABLED`, `ADMIN_DIGEST_HOUR`, `ADMIN_DIGEST_RECIPIENTS`. Keep `docker-compose.yml`, the README config table, and `.env.example` in sync when adding config.
