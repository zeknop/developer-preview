// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zeknod OÜ
// The same run as ./sign-mock.test.mjs, against a REAL relay.
//
//   RELAY_URL=https://relay.example.org \
//   SIGNER_UUID=<an identity this relay holds> \
//   SIGNER_API_KEY=<its API key> \
//   SIGNER_FROM=<an address that identity may send as> \
//   node --test test/e2e-stack.mjs
//
// Without those four in the environment every test here is SKIPPED, so
// `node --test` is safe to run with no relay anywhere: this file then
// reports skipped and asks nothing of the network.
//
// `SIGNER_FROM` has to be an address the identity may send as — the exact
// address for a mailbox identity, any address at the domain for a domain one —
// or POST /v1/sign answers 403 and says so (../../../api/README.md, "Signing").
// Nothing here is written into the package: the credentials come from the
// environment and the messages are written to a temporary directory.

import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

import { VERDICT } from '../vendor/canonical/message.mjs';

const run = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));
const SIGN = resolve(HERE, '..', 'bin', 'sign.mjs');
const VERIFY = resolve(HERE, '..', 'bin', 'verify.mjs');

const CONFIGURED = {
  relay: process.env.RELAY_URL,
  uuid: process.env.SIGNER_UUID,
  apiKey: process.env.SIGNER_API_KEY,
  from: process.env.SIGNER_FROM,
};
const MISSING = Object.entries(CONFIGURED)
  .filter(([, value]) => !value)
  .map(([name]) => name);
const SKIP = MISSING.length
  ? `needs a relay and an identity in the environment; missing: ${MISSING.join(', ')}`
  : false;

const CRLF = '\r\n';
const PORTAL = process.env.VERIFY_PORTAL_URL || 'https://verify.example.org/v1';

function message() {
  return [
    `From: ${CONFIGURED.from}`,
    'To: recipient@example.com',
    'Subject: Invoice 2026-10',
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'Amount due: 100 EUR',
    'Please pay by Friday.',
    '',
  ].join(CRLF);
}

test('the relay answers /health', { skip: SKIP }, async () => {
  const response = await fetch(`${CONFIGURED.relay.replace(/\/+$/, '')}/health`);
  assert.equal(response.status, 200, 'a 503 names the datastore that is down');
});

test('sign, verify, change one character, verify again', { skip: SKIP }, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'zeknop-example-e2e-'));
  const source = join(dir, 'message.eml');
  const out = join(dir, 'signed.eml');
  await writeFile(source, message());

  const signed = await run(process.execPath, [
    SIGN, source,
    '--uuid', CONFIGURED.uuid,
    '--api-key', CONFIGURED.apiKey,
    '--relay', CONFIGURED.relay,
    '--portal', PORTAL,
    '--out', out,
    '--json',
  ]);
  const report = JSON.parse(signed.stderr);
  assert.match(report.envelope_id, /^[A-Za-z0-9]{8}$/);
  assert.equal(report.version, '1.5');

  const sound = await run(process.execPath, [VERIFY, out, '--relay', CONFIGURED.relay, '--json']);
  const verdict = JSON.parse(sound.stdout);
  assert.equal(verdict.verdict, VERDICT.VERIFIED);
  assert.equal(verdict.strict_hash_matches_header, true);

  // The same message a second time. A repeated question about the same triple is
  // answered and not refused: the relay verifies it again and says
  // "Previously verified" (../../../api/README.md, "Checking a signature").
  const again = await run(process.execPath, [VERIFY, out, '--relay', CONFIGURED.relay, '--json']);
  const second = JSON.parse(again.stdout);
  assert.equal(second.verdict, VERDICT.VERIFIED);

  const tampered = join(dir, 'tampered.eml');
  const delivered = await readFile(out, 'utf8');
  await writeFile(tampered, delivered.replace('Amount due: 100 EUR', 'Amount due: 900 EUR'));
  await assert.rejects(
    () => run(process.execPath, [VERIFY, tampered, '--relay', CONFIGURED.relay, '--json']),
    (err) => {
      assert.equal(err.code, 1);
      const changed = JSON.parse(err.stdout);
      assert.equal(changed.verdict, VERDICT.TAMPERED);
      assert.equal(changed.strict_hash_matches_header, false);
      return true;
    },
  );

  // And the same thing without the relay: the fingerprint of the delivered
  // message is the fingerprint the message carries.
  const offline = await run(process.execPath, [VERIFY, out, '--offline', '--json']);
  const local = JSON.parse(offline.stdout);
  assert.equal(local.recomputed.strict_hash, report.strict_hash);
  assert.equal(local.recomputed.free_hash, report.free_hash);
  assert.equal(local.strict_hash_matches_header, true);
});
