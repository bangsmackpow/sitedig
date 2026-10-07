'use strict';
// Stub `waybackurls` used by integration tests. Prints fake archived URLs.
function main() {
  const args = process.argv.slice(2);
  if (args.includes('-version') || args.includes('-h')) {
    process.stdout.write('waybackurls stub\n');
    process.exit(0);
  }
  const lines = [
    'https://example.com/index.html',
    'https://example.com/wp-config.php.bak',
    'https://example.com/.git/config',
    'https://example.com/backup/dump.sql',
    'https://example.com/api/export?api_key=supersecretvalue123',
    'https://evil-sub.example.com/admin',
  ];
  process.stdout.write(lines.join('\n') + '\n');
  process.exit(0);
}
main();
