'use strict';
// Stub `nmap` used by integration tests. Never scans anything.
// Recognises `--top-ports N` / `-p <list>` and `-oG <file>`, then writes a
// fake grepable result for the target host (the last non-flag argument).
const fs = require('node:fs');

function findArg(args, name) {
  const i = args.indexOf(name);
  if (i === -1) return null;
  return args[i + 1];
}

function main() {
  const args = process.argv.slice(2);
  if (args.includes('--version')) {
    process.stdout.write('Nmap stub 7.94\n');
    process.exit(0);
  }

  const host = args.filter((a) => !a.startsWith('-')).pop() ?? 'example.com';
  const outFile = findArg(args, '-oG');

  const lines = [
    `# Nmap stub scan report for ${host}`,
    `Host: ${host}\tPorts: 80/open/tcp//http///, 443/open/tcp//https///\tIgnored State: filtered (998)`,
  ];
  const text = lines.join('\n') + '\n';
  if (outFile) fs.writeFileSync(outFile, text, 'utf8');
  process.stdout.write(`Nmap stub completed for ${host}\n`);
  process.exit(0);
}

main();
