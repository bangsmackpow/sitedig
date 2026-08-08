'use strict';
// Stub `wpscan` that writes valid JSON results but exits with a semantic
// non-zero code (3 = post-run exception). Simulates real-world wpscan behavior
// where findings are collected despite a non-zero exit.
const fs = require('node:fs');

function main() {
  const args = process.argv.slice(2);
  if (args.includes('--version')) {
    process.stdout.write('_______________________________________________________________\n');
    process.stdout.write('Version 3.8.25\n');
    process.exit(0);
  }

  const i = args.indexOf('--output');
  const outFile = i === -1 ? null : args[i + 1];

  const result = {
    version: '3.8.25',
    wordpress: { version: '6.4' },
    interesting_findings: [
      { to_s: 'example finding one' },
      { to_s: 'example finding two' },
    ],
    plugins: {},
    themes: {},
  };

  const text = JSON.stringify(result, null, 2) + '\n';
  if (outFile) fs.writeFileSync(outFile, text, 'utf8');
  process.stderr.write('(stub) post-run exception simulated\n');
  process.exit(3);
}

main();
