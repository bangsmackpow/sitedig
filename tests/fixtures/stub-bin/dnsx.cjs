'use strict';
// Stub `dnsx` used by integration tests. Writes a fake JSONL file.
const fs = require('node:fs');

function main() {
  const args = process.argv.slice(2);
  if (args.includes('-version')) {
    process.stdout.write('Current Version: v1.1.7\n');
    process.exit(0);
  }
  const i = args.indexOf('-o');
  const outFile = i === -1 ? null : args[i + 1];
  const host = args[args.indexOf('-d') + 1] ?? 'example.com';
  const lines = [
    JSON.stringify({ host, type: 'A', value: '93.184.216.34' }),
    JSON.stringify({ host, type: 'AAAA', value: '2606:2800:220:1::1' }),
    JSON.stringify({ host, type: 'MX', value: 'mail.' + host }),
    JSON.stringify({ host, type: 'NS', value: 'ns1.' + host }),
  ].join('\n');
  if (outFile) fs.writeFileSync(outFile, lines + '\n', 'utf8');
  process.stdout.write('dnsx stub completed\n');
  process.exit(0);
}
main();
