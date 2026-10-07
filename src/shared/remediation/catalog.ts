/**
 * Remediation playbook catalog (Premium "remediation-playbook" module).
 *
 * Static, curated, stack-aware fix plans keyed by the `playbookKey` that the
 * findings builder attaches to each finding. Content is intentionally exact:
 * copy-paste commands, verification checks, owner, and effort.
 */

export type WebStack = 'nginx' | 'apache' | 'generic';
export type Effort = 'S' | 'M' | 'L';

export interface PlaybookStep {
  title: string;
  detail?: string;
  commands?: string[];
}

export interface PlaybookVariant {
  owner: string;
  effort: Effort;
  when?: string;
  steps: PlaybookStep[];
  verify: string[];
  refs: string[];
}

export interface PlaybookEntry {
  key: string;
  title: string;
  /** Why it matters, in plain executive language. */
  execSummary: string;
  generic: PlaybookVariant;
  stacks?: Partial<Record<WebStack, PlaybookVariant>>;
}

export function detectWebStack(input: {
  technologies: Array<{ name: string }>;
  serverBanner?: string | null;
  poweredBy?: string | null;
  wordpressDetected?: boolean;
}): WebStack {
  const hay = [
    input.serverBanner ?? '',
    input.poweredBy ?? '',
    ...input.technologies.map((t) => t.name),
  ]
    .join(' ')
    .toLowerCase();
  if (hay.includes('nginx')) return 'nginx';
  if (hay.includes('apache') || hay.includes('caddy') || hay.includes('litespeed') || hay.includes('iis')) return 'apache';
  if (input.wordpressDetected) return 'apache';
  return 'generic';
}

export function getVariant(entry: PlaybookEntry, stack: WebStack): PlaybookVariant {
  return entry.stacks?.[stack] ?? entry.generic;
}

const RE_FW = ['https://owasp.org/www-project-top-ten/'];

export const PLAYBOOKS: Record<string, PlaybookEntry> = {
  'open-port': {
    key: 'open-port',
    title: 'Internet-reachable TCP port',
    execSummary: 'A network port is reachable from the public internet. Every exposed port is a potential entry point; anything not deliberately published should be closed.',
    generic: {
      owner: 'Network / DevOps engineer',
      effort: 'S',
      steps: [
        { title: 'Confirm the service is intentional', detail: 'Check with the owning team that this port must be public. If it is only needed internally, keep it closed to the internet.' },
        {
          title: 'Restrict the port at the firewall',
          detail: 'For cloud workloads, tighten the security-group/firewall rule to your office/VPN CIDRs. On the host, allow only the required source ranges.',
          commands: ['ufw allow from 203.0.113.0/24 to any port <PORT> proto tcp', 'ufw deny <PORT>/tcp'],
        },
        { title: 'Or stop the service from binding publicly', detail: 'Change its listen address from 0.0.0.0 to 127.0.0.1 and front it with an internal proxy if it only serves localhost.' },
      ],
      verify: ['Re-scan the host and confirm the port no longer reports open from an external vantage point.'],
      refs: RE_FW,
    },
  },
  'open-db-port': {
    key: 'open-db-port',
    title: 'Database/cache port reachable from the internet',
    execSummary: 'A data store (database or cache) is answering on the public internet. These services have no user-facing reason to be public; exposed instances are routinely harvested and dumped.',
    generic: {
      owner: 'Database / DevOps engineer',
      effort: 'M',
      steps: [
        { title: 'Bind the service to a private interface', detail: 'Edit the server configuration to bind to a private IP or 127.0.0.1.' },
        {
          title: 'Block the port at the perimeter',
          detail: 'Remove any security-group/firewall rule allowing 0.0.0.0/0 to this port.',
          commands: ['iptables -I INPUT -p tcp --dport <PORT> -s 0.0.0.0/0 -j DROP'],
        },
        { title: 'Rotate credentials that may have been exposed', detail: 'If the service was public for any period, treat its accounts and any cached secrets as compromised.' },
      ],
      verify: ['External scan shows the port filtered/closed.', 'Application connects via the private path.'],
      refs: ['https://owasp.org/Top10/A05_Security-Misconfiguration/'],
    },
    stacks: {
      nginx: {
        owner: 'Database / DevOps engineer',
        effort: 'M',
        when: 'Same steps apply regardless of web server.',
        steps: [
          { title: 'Bind the service to a private interface', detail: 'Edit the server configuration to bind to a private IP or 127.0.0.1.' },
          { title: 'Block the port at the perimeter', detail: 'Remove any security-group/firewall rule allowing 0.0.0.0/0 to this port.' },
          { title: 'Rotate credentials that may have been exposed' },
        ],
        verify: ['External scan shows the port filtered/closed.'],
        refs: ['https://owasp.org/Top10/A05_Security-Misconfiguration/'],
      },
    },
  },
  'open-ssh': {
    key: 'open-ssh',
    title: 'SSH exposed to the internet',
    execSummary: 'SSH is reachable from anywhere on the internet. Key-only authentication plus source restrictions turns an always-brute-forced door into a manageable one.',
    generic: {
      owner: 'System administrator',
      effort: 'S',
      steps: [
        {
          title: 'Restrict source addresses',
          detail: 'Allow SSH only from office/VPN CIDRs.',
          commands: ['ufw allow from 203.0.113.0/24 to any port 22 proto tcp', 'ufw deny 22/tcp'],
        },
        {
          title: 'Disable password authentication',
          commands: ['# /etc/ssh/sshd_config', 'PasswordAuthentication no', 'PermitRootLogin no', 'systemctl reload sshd'],
        },
        { title: 'Prefer SSH over a VPN/bastion instead of public exposure' },
      ],
      verify: ['Password auth rejected externally (ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password host).'],
      refs: ['https://www.cisecurity.org/cis-benchmarks'],
    },
  },
  'missing-headers': {
    key: 'missing-headers',
    title: 'Missing HTTP security headers',
    execSummary: 'The web server does not send the response headers that modern browsers use to block clickjacking, MIME-sniffing, and downgrade attacks. Adding them is a low-cost, high-coverage win.',
    generic: {
      owner: 'Web developer / DevOps',
      effort: 'S',
      steps: [
        { title: 'Add the headers at the reverse proxy or application level', detail: 'HSTS (after confirming HTTPS is stable), X-Content-Type-Options: nosniff, X-Frame-Options: SAMEORIGIN (or CSP frame-ancestors), Referrer-Policy: strict-origin-when-cross-origin, Permissions-Policy, and a Content-Security-Policy starting in report-only.' },
      ],
      verify: ['curl -sI https://<target>/ shows every header listed in the finding.'],
      refs: ['https://owasp.org/www-project-secure-headers/'],
    },
    stacks: {
      nginx: {
        owner: 'DevOps / sysadmin',
        effort: 'S',
        steps: [
          {
            title: 'Add the headers in the server block',
            commands: [
              '# /etc/nginx/sites-available/<site>',
              'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
              'add_header X-Content-Type-Options "nosniff" always;',
              'add_header X-Frame-Options "SAMEORIGIN" always;',
              'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
              'add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;',
              '# Start CSP in report-only, then enforce once reports are clean:',
              'add_header Content-Security-Policy-Report-Only "default-src \'self\'; report-uri /csp-report;" always;',
              'nginx -t && systemctl reload nginx',
            ],
          },
        ],
        verify: ['curl -sI https://<target>/ lists all added headers.'],
        refs: ['https://owasp.org/www-project-secure-headers/', 'https://nginx.org/en/docs/http/ngx_http_headers_module.html'],
      },
      apache: {
        owner: 'DevOps / sysadmin',
        effort: 'S',
        steps: [
          {
            title: 'Add the headers in the vhost or .htaccess',
            commands: [
              '# /etc/apache2/sites-available/<site>.conf',
              'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"',
              'Header always set X-Content-Type-Options "nosniff"',
              'Header always set X-Frame-Options "SAMEORIGIN"',
              'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
              '# requires: a2enmod headers',
              'apachectl configtest && systemctl reload apache2',
            ],
          },
        ],
        verify: ['curl -sI https://<target>/ lists all added headers.'],
        refs: ['https://owasp.org/www-project-secure-headers/', 'https://httpd.apache.org/docs/current/mod/mod_headers.html'],
      },
    },
  },
  'server-banner': {
    key: 'server-banner',
    title: 'Server banner discloses software/version',
    execSummary: 'The Server header advertises the exact software and version, giving attackers a ready-made target list. Hiding it is one line of configuration.',
    generic: {
      owner: 'DevOps / sysadmin',
      effort: 'S',
      steps: [
        { title: 'Suppress or neutralize the Server header at the edge (CDN/reverse proxy) when possible.' },
      ],
      verify: ['curl -sI shows no version string (or an intentional value).'],
      refs: ['https://owasp.org/www-community/attacks/Server_Inclusion'],
    },
    stacks: {
      nginx: {
        owner: 'DevOps / sysadmin',
        effort: 'S',
        steps: [
          {
            title: 'Disable version tokens',
            commands: ['server_tokens off;  # http or server block', 'nginx -t && systemctl reload nginx'],
          },
        ],
        verify: ['curl -sI https://<target>/ shows only "Server: nginx".'],
        refs: ['https://nginx.org/en/docs/ngx_core_module.html#server_tokens'],
      },
      apache: {
        owner: 'DevOps / sysadmin',
        effort: 'S',
        steps: [
          {
            title: 'Reduce ServerTokens',
            commands: ['# /etc/apache2/conf-available/security.conf', 'ServerTokens Prod', 'ServerSignature Off', 'systemctl reload apache2'],
          },
        ],
        verify: ['curl -sI https://<target>/ shows only "Server: Apache".'],
        refs: ['https://httpd.apache.org/docs/current/mod/core.html#servertokens'],
      },
    },
  },
  'powered-by': {
    key: 'powered-by',
    title: 'X-Powered-By discloses the application stack',
    execSummary: 'The framework header tells attackers exactly which stack and version to target; removing it is trivial.',
    generic: {
      owner: 'Application developer',
      effort: 'S',
      steps: [
        {
          title: 'Remove the header in the framework',
          detail: 'Express: app.disable("x-powered-by"). PHP: header removal/expose_php=Off. ASP.NET: <httpProtocol> customHeaders remove X-AspNet-Version.',
          commands: ['// Express example', 'app.disable("x-powered-by");'],
        },
        { title: 'Strip it at the proxy as a belt-and-braces measure', commands: ['proxy_hide_header X-Powered-By;  # nginx'] },
      ],
      verify: ['curl -sI shows no X-Powered-By.'],
      refs: ['https://owasp.org/www-project-secure-headers/'],
    },
  },
  'cert-expired': {
    key: 'cert-expired',
    title: 'TLS certificate expired',
    execSummary: 'Browsers now block visitors outright ("your connection is not private"). Every visitor sees an error until this is fixed — it is an availability incident, not just a security item.',
    generic: {
      owner: 'DevOps / sysadmin',
      effort: 'S',
      steps: [
        {
          title: 'Re-issue the certificate',
          detail: 'For Let\'s Encrypt/certbot:',
          commands: ['certbot renew --force-renewal', 'or: certbot --nginx/-–apache -d <domain>'],
        },
        {
          title: 'Automate renewal so it cannot lapse again',
          detail: 'certbot timers handle this; or install an auto-renewing CA client. Verify the renewal hook reloads the server.',
          commands: ['systemctl list-timers | grep certbot'],
        },
      ],
      verify: ['openssl s_client -connect <host>:443 -servername <host> </dev/null 2>/dev/null | openssl x509 -noout -dates'],
      refs: ['https://letsencrypt.org/docs/'],
    },
  },
  'cert-expiring': {
    key: 'cert-expiring',
    title: 'TLS certificate expiring soon',
    execSummary: 'The certificate will expire within the renewal window. Renew now while there is time, and fix the process so it cannot happen again.',
    generic: {
      owner: 'DevOps / sysadmin',
      effort: 'S',
      steps: [
        { title: 'Renew the certificate before the expiry date.' },
        { title: 'Enable/repair automated renewal (certbot timer, CA dashboard, or CDN-managed certs).' },
        { title: 'Add expiry monitoring' , detail: 'Alert at 30/14/7 days remaining.' },
      ],
      verify: ['openssl s_client -connect <host>:443 | x509 -noout -enddate shows the new date.'],
      refs: ['https://letsencrypt.org/docs/'],
    },
  },
  'tls-legacy': {
    key: 'tls-legacy',
    title: 'Legacy TLS/SSL protocol or weak cipher enabled',
    execSummary: 'Old TLS versions are forbidden by PCI-DSS and vulnerable to downgrade attacks. Modern browsers have also dropped support, so keeping them enabled only helps attackers.',
    generic: {
      owner: 'DevOps / sysadmin',
      effort: 'M',
      steps: [
        { title: 'Enable only TLS 1.2 and 1.3 with modern cipher suites.' },
        { title: 'Re-run the TLS audit to confirm.' },
      ],
      verify: ['testssl.sh / openssl s_client -tls1 / -tls1_1 fail against the host.'],
      refs: ['https://wiki.mozilla.org/Security/Server_Side_TLS'],
    },
    stacks: {
      nginx: {
        owner: 'DevOps / sysadmin',
        effort: 'S',
        steps: [
          {
            title: 'Pin protocols and ciphers',
            commands: [
              'ssl_protocols TLSv1.2 TLSv1.3;',
              'ssl_prefer_server_ciphers on;',
              '# modern suite recommendation (Mozilla Intermediate)',
              'ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;',
              'nginx -t && systemctl reload nginx',
            ],
          },
        ],
        verify: ['openssl s_client -connect <host>:443 -tls1 fails.'],
        refs: ['https://wiki.mozilla.org/Security/Server_Side_TLS', 'https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_protocols'],
      },
      apache: {
        owner: 'DevOps / sysadmin',
        effort: 'S',
        steps: [
          {
            title: 'Pin protocols and ciphers',
            commands: [
              '# /etc/apache2/mods-available/ssl.conf',
              'SSLProtocol -all +TLSv1.2 +TLSv1.3',
              'SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384',
              'systemctl reload apache2',
            ],
          },
        ],
        verify: ['openssl s_client -connect <host>:443 -tls1 fails.'],
        refs: ['https://wiki.mozilla.org/Security/Server_Side_TLS', 'https://httpd.apache.org/docs/current/mod/mod_ssl.html#sslprotocol'],
      },
    },
  },
  'self-signed': {
    key: 'self-signed',
    title: 'Self-signed TLS certificate',
    execSummary: 'Visitors see a scary security warning and cannot verify they are talking to your real site. A free CA certificate removes this entirely.',
    generic: {
      owner: 'DevOps / sysadmin',
      effort: 'S',
      steps: [
        { title: 'Issue a certificate from a public CA', commands: ['certbot --nginx -d <domain>  # or --apache'] },
        { title: 'Set the CA cert as the default and automate renewal.' },
      ],
      verify: ['Certificate chain validates with openssl verify / browser padlock.'],
      refs: ['https://letsencrypt.org/'],
    },
  },
  'tech-versions': {
    key: 'tech-versions',
    title: 'Detected web technologies',
    execSummary: 'The report lists the software the site runs on. The job here is patch management: anything publicly fingerprinted should have a named owner and an upgrade cadence.',
    generic: {
      owner: 'Application owner',
      effort: 'M',
      steps: [
        { title: 'Inventory each technology against its vendor security advisory feed.' },
        { title: 'Upgrade anything with a released patch; schedule the rest.' },
        { title: 'Suppress version disclosure (see banner/header playbooks).' },
      ],
      verify: ['Re-scan: versions match patched releases or are hidden.'],
      refs: ['https://owasp.org/www-project-dependency-check/'],
    },
  },
  wordpress: {
    key: 'wordpress',
    title: 'WordPress detected',
    execSummary: 'WordPress powers a large share of the web and is continuously probed for outdated plugins and exposed files. Baseline hardening closes the most common doors.',
    generic: {
      owner: 'Site / WordPress administrator',
      effort: 'M',
      steps: [
        { title: 'Update core, themes, and plugins to current releases (Dashboard → Updates).', commands: ['wp core update && wp plugin update --all && wp theme update --all'] },
        { title: 'Delete unused themes/plugins; remove readme/license files where possible.' },
        { title: 'Limit login attempts and enable 2FA for admin users.' },
        { title: 'Disable XML-RPC if not required (a frequent DDoS/brute-force vector).', commands: ['# .htaccess', '<Files xmlrpc.php>', 'Order Deny,Allow', 'Deny from all', '</Files>'] },
      ],
      verify: ['wpscan --url https://<target> --enumerate p,t shows no outdated items.'],
      refs: ['https://wordpress.org/documentation/article/hardening-wordpress/'],
    },
  },
  'vuln-generic': {
    key: 'vuln-generic',
    title: 'Template-detected web misconfiguration/exposure',
    execSummary: 'A detection rule matched a known misconfiguration or exposed resource. These are almost always real and usually quick to fix at the web-server layer.',
    generic: {
      owner: 'DevOps / web developer',
      effort: 'M',
      steps: [
        { title: 'Read the finding\'s matched template description (CWE/reference where listed).' },
        { title: 'Reproduce with curl or a browser to confirm live exposure.' },
        { title: 'Remove the exposed file/directory or add an access rule; for server-status/config pages, restrict by IP.' },
      ],
      verify: ['Re-run the scan: the template no longer matches.'],
      refs: ['https://cwe.mitre.org/'],
    },
  },
  'cve-package': {
    key: 'cve-package',
    title: 'Component with known CVEs',
    execSummary: 'A specific software component is mapped to published vulnerabilities. Upgrading the component is the direct fix; the OSV record lists affected and fixed ranges.',
    generic: {
      owner: 'Application owner',
      effort: 'M',
      steps: [
        { title: 'Open the OSV advisory for the package and check fixed versions.', commands: ['# OSV lookup', 'curl -s https://api.osv.dev/v1/query -d \'{"package":{"name":"<pkg>","ecosystem":"<eco>"}}\' | head -50'] },
        { title: 'Upgrade to the patched release in a staging environment first.' },
        { title: 'If upgrade is blocked, apply the advisory\'s workaround or mitigate (WAF rule, feature disable).' },
      ],
      verify: ['Re-scan: OSV enrichment reports no critical/high for the version.'],
      refs: ['https://osv.dev/'],
    },
  },
  'exposed-paths': {
    key: 'exposed-paths',
    title: 'Discoverable web paths',
    execSummary: 'Content discovery found live directories/files beyond the public site. Anything here that was not deliberately published should be protected or removed.',
    generic: {
      owner: 'Site administrator / developer',
      effort: 'M',
      steps: [
        { title: 'Review each discovered path and classify intended vs accidental.' },
        { title: 'Remove stale content (old backups, installers, dev stubs); move anything sensitive behind authentication.' },
        { title: 'Disable directory listings.', commands: ['# nginx', 'autoindex off;', '# apache', 'Options -Indexes'] },
      ],
      verify: ['Re-run content discovery: paths of concern return 403/404.'],
      refs: ['https://owasp.org/Top10/A01_Broken-Access-Control/'],
    },
  },
  'archived-exposure': {
    key: 'archived-exposure',
    title: 'Sensitive path found in URL history',
    execSummary: 'The Internet Archive stored copies of sensitive-looking URLs (config dumps, backups, admin tools). Even if the file is gone now, the archived copy may still leak the data.',
    generic: {
      owner: 'Site administrator / security lead',
      effort: 'M',
      steps: [
        { title: 'Check the live site: if the path still serves content, remove/protect it immediately (see "Discoverable web paths").' },
        {
          title: 'Request removal of archived copies',
          detail: 'The Wayback Machine honours takedown for content you own: use the archive\'s contact/form, or mark the robots.txt exclusion and re-request.',
          commands: ['curl -sI "https://web.archive.org/web/<timestamp>id_/<url>"  # confirm archived bytes'],
        },
        { title: 'Rotate any credentials/keys contained in the exposed files, treating them as public.' },
        { title: 'Block crawlers for new captures of sensitive paths (robots.txt, X-Robots-Tag).' },
      ],
      verify: ['Archived URLs return 404/deleted or are flagged; live paths are closed.'],
      refs: ['https://help.archive.org/help/how-do-i-request-to-remove-something-from-the-internet-archive/'],
    },
  },
  'leaked-url-credentials': {
    key: 'leaked-url-credentials',
    title: 'Credential-like parameter in archived URL',
    execSummary: 'The archive history contains URLs whose query strings carried credential-like values. Assume those secrets are public and rotate them.',
    generic: {
      owner: 'Security lead / application owner',
      effort: 'M',
      steps: [
        { title: 'Identify the system that issued the token/key and revoke & rotate every affected value.' },
        { title: 'Stop passing secrets in URLs: move them to request bodies/headers; add "Cache-Control: no-store" to responses issued with them.' },
        { title: 'Request Wayback Machine removal for the affected captures.' },
        { title: 'Audit web-server/access logs for these parameter names going forward.' },
      ],
      verify: ['Rotated values; new scans show no credential-pattern URLs.'],
      refs: ['https://cwe.mitre.org/data/definitions/598.html'],
    },
  },
  'insecure-cookie': {
    key: 'insecure-cookie',
    title: 'Session cookie missing Secure/HttpOnly flags',
    execSummary: 'Cookies without Secure/HttpOnly can be stolen by script injection or sent over unencrypted connections — the classic session-hijacking path.',
    generic: {
      owner: 'Application developer',
      effort: 'S',
      steps: [
        { title: 'Set Secure, HttpOnly, and SameSite=Lax (or Strict) on every session cookie in the application framework.' },
        { title: 'Ensure HTTPS is enforced first — Secure cookies require TLS.' },
      ],
      verify: ['curl -sI shows Set-Cookie with Secure; HttpOnly; SameSite.'],
      refs: ['https://owasp.org/www-community/controls/SecureCookieAttribute'],
    },
  },
  'dmarc-missing': {
    key: 'dmarc-missing',
    title: 'No DMARC policy published',
    execSummary: 'Anyone can send email that looks like it comes from your domain today. DMARC is the industry-standard defense; without it, phishing using your domain works against customers, staff, and partners.',
    generic: {
      owner: 'DNS / email administrator',
      effort: 'S',
      steps: [
        {
          title: 'Publish a monitoring DMARC record first',
          detail: 'Start with p=none plus a reporting address so you can see every system that sends mail as your domain before you start blocking anything.',
          commands: ['# Add TXT record at _dmarc.<domain>:', '_dmarc.<domain>. TXT "v=DMARC1; p=none; rua=mailto:dmarc-reports@<domain>"'],
        },
        { title: 'Review aggregate reports for ~2 weeks; fix any legitimate senders that fail SPF/DKIM alignment.' },
        {
          title: 'Raise to enforcement',
          commands: ['# Once all legitimate mail passes:', '_dmarc.<domain>. TXT "v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc-reports@<domain>"', '# Finally: p=reject'],
        },
      ],
      verify: ['dig +short TXT _dmarc.<domain> returns the policy; dmarc reports show senders aligned.'],
      refs: ['https://dmarc.org/overview/', 'https://support.google.com/a/answer/2466580'],
    },
  },
  'dmarc-none': {
    key: 'dmarc-none',
    title: 'DMARC policy is monitoring-only',
    execSummary: 'A DMARC record exists but does nothing to stop spoofed mail (p=none / no reporting address). The remaining work is small and mostly automated reporting setup.',
    generic: {
      owner: 'DNS / email administrator',
      effort: 'S',
      steps: [
        { title: 'Add a rua= reporting address if missing.' },
        { title: 'After 2–4 weeks of clean reports (all legitimate senders aligned), move to p=quarantine then p=reject.' },
        { title: 'Consider spf1/fo flags for easier report triage.' },
      ],
      verify: ['dig +short TXT _dmarc.<domain> shows p=quarantine/reject and a rua.'],
      refs: ['https://dmarc.org/overview/'],
    },
  },
  'spf-missing': {
    key: 'spf-missing',
    title: 'No SPF record published',
    execSummary: 'Without SPF, receiving mail servers cannot tell which hosts are allowed to send as your domain — enabling spoofing and hurting deliverability.',
    generic: {
      owner: 'DNS / email administrator',
      effort: 'S',
      steps: [
        {
          title: 'List every legitimate sender',
          detail: 'Include web hosts, marketing platforms (Mailchimp/SendGrid…), and internal mail.',
          commands: ['# TXT record at <domain>:', '<domain>. TXT "v=spf1 ip4:<mail-ip> include:_spf.<provider> -all"'],
        },
        { title: 'Check the record is under 10 DNS lookups (use RFC 4408 checker tools).' },
      ],
      verify: ['dig +short TXT <domain> shows one SPF record ending in -all.'],
      refs: ['https://www.cloudflare.com/learning/email-security/what-is-spf/'],
    },
  },
  'spf-permissive': {
    key: 'spf-permissive',
    title: 'SPF record allows any sender',
    execSummary: 'A trailing +all/?all in SPF means any IP on the internet can pass SPF checks for your domain — the record exists in name only.',
    generic: {
      owner: 'DNS / email administrator',
      effort: 'S',
      steps: [
        { title: 'Replace the end qualifier with -all.' },
        { title: 'Before hard-failing, verify with your mail provider that all senders are already listed.' },
      ],
      verify: ['dig +short TXT <domain> shows "… -all".'],
      refs: ['https://datatracker.ietf.org/doc/html/rfc7208'],
    },
  },
  'mx-starttls': {
    key: 'mx-starttls',
    title: 'Mail server does not advertise STARTTLS',
    execSummary: 'Inbound mail to your domain can be relayed in clear text because your mail server does not offer encryption. Most providers can enable this in a setting or two.',
    generic: {
      owner: 'Email / Microsoft 365 or Google Workspace admin',
      effort: 'S',
      steps: [
        { title: 'Install/enable a valid certificate on the SMTP endpoint (port 25).' },
        { title: 'If the MX is a hosted service, confirm TLS is enforced in its admin console or open a ticket.' },
      ],
      verify: ['openssl s_client -starttls smtp -connect <mx-host> 25 succeeds.'],
      refs: ['https://datatracker.ietf.org/doc/html/rfc8461'],
    },
  },
  'mta-sts': {
    key: 'mta-sts',
    title: 'No MTA-STS / TLS reporting published',
    execSummary: 'MTA-STS and TLS-RPT are how big mail providers enforce encrypted delivery to your domain and tell you when that fails. Low-effort, DNS-and-file-level work.',
    generic: {
      owner: 'Email / DNS administrator',
      effort: 'S',
      steps: [
        {
          title: 'Publish the policy TXT records',
          commands: ['# MTA-STS policy id (rotate on policy change):', '_mta-sts.<domain>. TXT "v=STSv1; id:20260101000000"', '# TLS reporting:', '_smtp._tls.<domain>. TXT "v=TLSRPTv1; rua=mailto:tls-reports@<domain>"'],
        },
        {
          title: 'Serve the policy file',
          detail: 'HTTPS, port 443, path must match:',
          commands: ['https://mta-sts.<domain>/.well-known/mta-sts.txt'],
        },
      ],
      verify: ['openssl/smtp probes show TLS enforced; reports arrive at rua mailbox.'],
      refs: ['https://datatracker.ietf.org/doc/html/rfc8461'],
    },
  },
};
