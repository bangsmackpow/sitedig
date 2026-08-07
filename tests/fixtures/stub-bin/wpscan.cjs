'use strict';
// Stub `wpscan` used by integration tests. Never scans anything.
// Writes a fake `--format json --output FILE` result.
const fs = require('node:fs');

function main() {
  const args = process.argv.slice(2);
  if (args.includes('--version')) {
    process.stdout.write('WPScan stub 3.8.25\n');
    process.exit(0);
  }

  const i = args.indexOf('--output');
  const outFile = i === -1 ? null : args[i + 1];

  const result = {
    version: '3.8.25',
    wordpress: { version: '6.4' },
    interesting_findings: [{ to_s: 'example' }],
    plugins: {},
    themes: {},
  };

  const text = JSON.stringify(result, null, 2) + '\n';
  if (outFile) fs.writeFileSync(outFile, text, 'utf8');
  process.stdout.write('WPScan stub completed\n');
  process.exit(0);
}

main();
