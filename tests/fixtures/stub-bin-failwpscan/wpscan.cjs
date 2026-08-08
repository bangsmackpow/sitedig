'use strict';
// Stub `wpscan` that always fails (simulates a broken local install).
process.stderr.write('wpscan: failed to load native extension (simulated)\n');
process.exit(1);
