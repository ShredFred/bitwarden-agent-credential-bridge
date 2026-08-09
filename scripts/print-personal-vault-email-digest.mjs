#!/usr/bin/env node
/**
 * Print the SHA-256 digest for a personal account email (Phase 13 allowlist).
 * Does not write files or touch DPAPI. Never logs as a secret — email is identity.
 *
 * Usage: node scripts/print-personal-vault-email-digest.mjs you@example.com
 */
import process from 'node:process';
import { digestPersonalAccountEmail } from '../src/personal-bitwarden-allow-config.mjs';

const email = process.argv[2];
if (typeof email !== 'string' || email.length < 3) {
  process.stderr.write('usage: node scripts/print-personal-vault-email-digest.mjs <email>\n');
  process.exit(1);
}
try {
  const digest = digestPersonalAccountEmail(email);
  process.stdout.write(`${JSON.stringify({
    schema_version: 1,
    account_email_sha256: digest,
  })}\n`);
} catch {
  process.stderr.write('invalid_email\n');
  process.exit(1);
}
