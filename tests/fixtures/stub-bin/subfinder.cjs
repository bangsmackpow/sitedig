'use strict';
// Stub `subfinder` used by integration tests. Writes a fake JSONL file.
const fs = require('node:fs');

function main() {
  const args = process.argv.slice(2);
  if (args.includes('-version')) {
    process.stdout.write('Current Version: v2.6.7\n');
    process.exit(0);
  }
  const i = args.indexOf('-o');
  const outFile = i === -1 ? null : args[i + 1];
  const host = args[args.indexOf('-d') + 1] ?? 'example.com';
  const lines = [
    JSON.stringify({ host: `api.${host}`, source: 'crt.sh' }),
    JSON.stringify({ host: `www.${host}`, source: 'certspotter' }),
    JSON.stringify({ host: `mail.${host}`, source: 'crtsh' }),
  ].join('\n');
  if (outFile) fs.writeFileSync(outFile, lines + '\n', 'utf8');
  process.stdout.write('Subfinder stub completed\n');
  process.exit(0);
}
main();
