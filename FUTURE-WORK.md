# Future work

Items identified during the production-readiness review that were not part of the
completed P0/P1 fix train. Work through these in priority order.

## Security hardening

- [ ] Raise scrypt cost and add hash versioning with rehash-on-login. Keep
      verifying existing `scrypt$1$` hashes while issuing a stronger format.
- [ ] Add HMAC/pepper for low-entropy hashes (`mfa_challenges.code_hash`,
      `recovery_codes.code_hash`) and encrypt TOTP secrets at rest.
- [ ] Pin GitHub Actions to commit SHAs; verify scanner release-asset SHA256
      checksums; pin the Docker base image by digest.
- [ ] Add a worker egress firewall/policy that denies RFC1918, link-local, and
      metadata ranges, and pin validated IPs for HTTP checks where possible.
      Pre-tool DNS validation alone does not stop tool-level rebinding.
- [ ] Segment networks so the proxy cannot reach worker endpoints, and deny
      `/api/internal/*` at the proxy layer.

## Data and operations

- [ ] SQLite backup automation (`VACUUM INTO`) plus a tested restore drill.
- [ ] Metrics and alerts: queue depth, scan failure rate, worker restarts,
      artifact disk usage, DB/WAL size, auth-failure spikes.
- [ ] Shared rate-limit store (SQLite/Redis) for multi-instance web.
- [ ] Audit-log retention/export policy and optional SIEM forwarding.

## Detection coverage

- [ ] PHP core CVE detection: add a nuclei template or explicit version check
      for CVE-2026-109618 / CVE-2026-109619. Today `cve-context` has no PHP
      mapping (`src/worker/osv.ts`) and the nuclei allowlist
      (`.env.example`, `src/shared/config.ts`) contains only tech-detect,
      git-config, and TLS templates.
- [ ] Expand `mapTechnologyToOsv` to cover PHP, IIS, Tomcat/Java, and other
      commonly fingerprinted runtimes.
- [ ] Establish a cadence for reviewing the nuclei allowlist against new
      high-severity, unauthenticated RCE advisories.

## Review cadence

- [ ] Quarterly review of blocked address ranges, nuclei templates, and
      dependency advisories.
