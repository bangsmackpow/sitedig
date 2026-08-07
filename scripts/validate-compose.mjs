#!/usr/bin/env node
// Validates docker-compose.yml without requiring a Docker daemon:
// parses YAML and asserts the contract required for the SiteDig stack.
import fs from 'node:fs';
import path from 'node:path';
import yaml from 'js-yaml';

const root = path.resolve(new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
const composePath = path.join(root, 'docker-compose.yml');

if (!fs.existsSync(composePath)) {
  console.error('docker-compose.yml not found');
  process.exit(1);
}

const doc = yaml.load(fs.readFileSync(composePath, 'utf8'));
const services = doc.services ?? {};

const errors = [];

if (!services.web) errors.push('missing service: web');
if (!services.worker) errors.push('missing service: worker');

for (const name of ['web', 'worker']) {
  const svc = services[name];
  if (!svc) continue;
  if (!svc.image) errors.push(`${name}: missing image`);
  if (!Array.isArray(svc.command) || svc.command.length === 0) errors.push(`${name}: missing command`);
  if (!svc.healthcheck) errors.push(`${name}: missing healthcheck`);
  if (!svc.restart) errors.push(`${name}: missing restart policy`);
  if (!svc.deploy?.resources?.limits) errors.push(`${name}: missing resource limits`);
}

const networks = doc.networks ?? {};
if (!networks.backend || networks.backend.external !== true) {
  errors.push('network backend must be declared external: true');
}

// No host ports may be published (NPM proxies via the shared network).
for (const [name, svc] of Object.entries(services)) {
  if (svc.ports && svc.ports.length > 0) {
    errors.push(`${name}: publishes host ports; SiteDig must not expose host ports`);
  }
}

// No DB / Redis / proxy services in the MVP stack.
for (const name of Object.keys(services)) {
  if (['db', 'database', 'redis', 'postgres', 'mysql', 'nginx'].includes(name)) {
    errors.push(`unexpected service in MVP stack: ${name}`);
  }
}

if (errors.length > 0) {
  console.error('docker-compose.yml validation FAILED:');
  for (const e of errors) console.error(`  - ${e}`);
  process.exit(1);
}

console.log('docker-compose.yml validation OK');
