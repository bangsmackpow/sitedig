'use strict';
// Stub `httpx` used by integration tests. Writes a fake JSONL file.
const fs = require('node:fs');

function main() {
  const args = process.argv.slice(2);
  if (args.includes('-version')) {
    process.stdout.write('Current Version: v1.6.9\n');
    process.exit(0);
  }
  const i = args.indexOf('-u');
  const url = i === -1 ? 'https://example.com/' : args[i + 1];
  const o = args.indexOf('-o');
  const outFile = o === -1 ? null : args[o + 1];
  const rec = {
    url,
    status_code: 200,
    webserver: 'nginx',
    headers: {
      Server: 'nginx',
      'Set-Cookie': ['sess=abc123; Path=/'],
    },
    tech: ['PHP', 'nginx'],
    content_length: 1234,
  };
  const lines = JSON.stringify(rec);
  if (outFile) fs.writeFileSync(outFile, lines + '\n', 'utf8');
  process.stdout.write(lines + '\n');
  process.exit(0);
}
main();
