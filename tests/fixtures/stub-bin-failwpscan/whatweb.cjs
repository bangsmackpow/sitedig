'use strict';
// Stub `whatweb` used by integration tests. Never scans anything.
// Writes a fake `--log-json` result for the target URL.
const fs = require('node:fs');

function main() {
  const args = process.argv.slice(2);
  if (args.includes('--version')) {
    process.stdout.write('WhatWeb stub 0.5.5\n');
    process.exit(0);
  }

  const i = args.indexOf('--log-json');
  const outFile = i === -1 ? null : args[i + 1];
  const target = args.filter((a) => a.startsWith('http')).pop() ?? 'http://example.com';

  const result = [
    {
      target,
      http_status: 200,
      plugins: {
        HTTPServer: { string: ['stub'] },
        WordPress: { version: ['6.4'] },
      },
    },
  ];

  const text = JSON.stringify(result, null, 2) + '\n';
  if (outFile) fs.writeFileSync(outFile, text, 'utf8');
  process.stdout.write('WhatWeb stub completed\n');
  process.exit(0);
}

main();
