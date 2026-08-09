'use strict';
// Stub `retire` used by integration tests. Writes a fake JSON result.
const fs = require('node:fs');

function main() {
  const args = process.argv.slice(2);
  if (args.includes('--version')) {
    process.stdout.write('retire 4.4.1\n');
    process.exit(0);
  }
  const i = args.indexOf('--outputpath');
  const outFile = i === -1 ? null : args[i + 1];
  const result = {
    results: [
      {
        component: 'jquery',
        version: '2.2.4',
        vulnerabilities: [
          {
            identifiers: { CVE: ['CVE-2015-9251'], summary: 'jQuery before 3.0.0 is vulnerable to XSS.' },
            severity: 'medium',
          },
        ],
        detection: { evidence: 'js-0.js' },
      },
    ],
  };
  if (outFile) fs.writeFileSync(outFile, JSON.stringify(result, null, 2), 'utf8');
  process.stdout.write('retire stub completed\n');
  process.exit(0);
}
main();
