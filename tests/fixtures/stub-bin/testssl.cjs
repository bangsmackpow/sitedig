'use strict';
// Stub `testssl.sh` used by integration tests. Writes a fake JSON array file.
const fs = require('node:fs');

function main() {
  const args = process.argv.slice(2);
  const i = args.indexOf('--jsonfile');
  const outFile = i === -1 ? null : args[i + 1];
  const result = [
    { id: 'SSLv2', severity: 'CRITICAL', finding: 'SSLv2 is offered', vuln: true },
    { id: 'TLS1', severity: 'HIGH', finding: 'TLS 1.0 is offered', vuln: true },
    { id: 'cipher_rc4', severity: 'MEDIUM', finding: 'RC4 ciphers are enabled', vuln: true },
  ];
  if (outFile) fs.writeFileSync(outFile, JSON.stringify(result, null, 2), 'utf8');
  process.stdout.write('testssl.sh stub completed\n');
  process.exit(0);
}
main();
