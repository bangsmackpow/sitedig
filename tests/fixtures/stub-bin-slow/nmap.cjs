'use strict';
// Slow `nmap` stub used to exercise timeouts. Sleeps then exits.
setTimeout(() => {
  process.stdout.write('Nmap stub (slow) completed\n');
  process.exit(0);
}, 3000);
