'use strict';
// Stub `feroxbuster` used by integration tests. Writes a fake JSONL file.
const fs = require('node:fs');

function main() {
  const args = process.argv.slice(2);
  if (args.includes('--version')) {
    process.stdout.write('feroxbuster 2.11.0\n');
    process.exit(0);
  }
  const i = args.indexOf('-o');
  const outFile = i === -1 ? null : args[i + 1];
  const lines = [
    JSON.stringify({ url: 'https://example.com/admin', status: 200, content_length: 512, content_type: 'text/html' }),
    JSON.stringify({ url: 'https://example.com/robots.txt', status: 200, content_length: 30, content_type: 'text/plain' }),
    JSON.stringify({ url: 'https://example.com/404', status: 404, content_length: 9 }),
  ].join('\n');
  if (outFile) fs.writeFileSync(outFile, lines + '\n', 'utf8');
  process.stdout.write('feroxbuster stub completed\n');
  process.exit(0);
}
main();
