'use strict';
// Stub `nuclei` used by integration tests. Writes a fake JSONL file.
const fs = require('node:fs');

function main() {
  const args = process.argv.slice(2);
  if (args.includes('-version')) {
    process.stdout.write('Current Version: v3.3.2\n');
    process.exit(0);
  }
  const i = args.indexOf('-o');
  const outFile = i === -1 ? null : args[i + 1];
  const lines = [
    JSON.stringify({
      'template-id': 'tech-detect:apache',
      info: { name: 'Apache version disclosure', severity: 'info', description: 'Apache server banner detected.' },
      'matched-at': 'https://example.com/',
      'matcher-status': true,
    }),
    JSON.stringify({
      'template-id': 'misconfig:server-header-leak',
      info: { name: 'Server header discloses version', severity: 'low', description: 'The Server header reveals the exact version.' },
      'matched-at': 'https://example.com/',
      'matcher-status': true,
    }),
  ].join('\n');
  if (outFile) fs.writeFileSync(outFile, lines + '\n', 'utf8');
  process.stdout.write('Nuclei stub completed\n');
  process.exit(0);
}
main();
