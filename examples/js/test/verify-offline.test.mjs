// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zeknod OÜ
// `verify --offline`: the fingerprints are recomputed from the delivered bytes,
// and compared with the one the message carries. No network, no relay, no key.
//
// The message is assembled here rather than read from a file, so the test says
// what it is testing: a delivered message is its headers, the visible envelope,
// and the sender's text inside it.

import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

import { canonicalizeRawMessage, VERDICT } from '../vendor/canonical/message.mjs';
import { buildNotVerified, buildPositive } from '../src/envelope-build.mjs';

const run = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));
const VERIFY = resolve(HERE, '..', 'bin', 'verify.mjs');

const CRLF = '\r\n';
const FROM = 'sender@example.org';
const TO = 'recipient@example.com';
const SUBJECT = 'Invoice 2026-10';
const BODY = 'Amount due: 100 EUR' + CRLF + 'Please pay by Friday.';
const TIMESTAMP = '2026-10-01T09:00:00.000Z';
const ENVELOPE_ID = 'Ab12Cd34';
const VERIFY_URL = 'https://verify.example.org/v1/eyJ2IjoyfQ';

/** A delivered message with the envelope around the body and `hash` in the header. */
function deliveredMessage({ hash, body = BODY }) {
  const headers = [
    `From: ${FROM}`,
    `To: ${TO}`,
    `Subject: ${SUBJECT}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'X-ZEKNOP-Version: 1.5',
    'X-ZEKNOP-Sig-Alg: ed25519',
    `X-ZEKNOP-Timestamp: ${TIMESTAMP}`,
    'X-ZEKNOP-UUID: 00000000-0000-4000-8000-000000000000',
    'X-ZEKNOP-Signature: AAAA',
    `X-ZEKNOP-Hash: ${hash}`,
    `X-ZEKNOP-Envelope-ID: ${ENVELOPE_ID}`,
  ];
  const envelope = buildPositive({
    inner: body,
    envelopeId: ENVELOPE_ID,
    verifyUrl: VERIFY_URL,
    eol: CRLF,
  });
  return headers.join(CRLF) + CRLF + CRLF + envelope;
}

/** The strict hash of the message whose delivered body is `body`. */
async function strictHashOf(body) {
  // Any value in the header will do to compute with: the hash is taken over the
  // canonical content, which the header is not part of.
  const analysis = await canonicalizeRawMessage(deliveredMessage({ hash: 'x', body }));
  return analysis.hash;
}

test('the envelope comes off again and the recomputed hash is the header hash', async () => {
  const hash = await strictHashOf(BODY);
  const analysis = await canonicalizeRawMessage(deliveredMessage({ hash }));
  assert.equal(analysis.hash, hash);
  assert.equal(analysis.zeknop.hash, hash);
  assert.equal(analysis.canonical.body, 'Amount due: 100 EUR\nPlease pay by Friday.');
  assert.equal(analysis.from, FROM);
  assert.equal(analysis.subject, SUBJECT);
  assert.notEqual(analysis.freeHash, null, 'a v1.5 message has the second fingerprint too');
});

test('one character of the body changed, and the hash no longer matches', async () => {
  const hash = await strictHashOf(BODY);
  const changed = BODY.replace('100 EUR', '900 EUR');
  const analysis = await canonicalizeRawMessage(deliveredMessage({ hash, body: changed }));
  assert.notEqual(analysis.hash, hash);
  assert.equal(analysis.zeknop.hash, hash);
});

test('the CLI reports the agreement, and the disagreement, without a network', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'zeknop-example-'));
  const hash = await strictHashOf(BODY);

  const good = join(dir, 'good.eml');
  await writeFile(good, deliveredMessage({ hash }));
  const sound = await run(process.execPath, [VERIFY, good, '--offline', '--json']);
  const soundResult = JSON.parse(sound.stdout);
  assert.equal(soundResult.mode, 'offline');
  assert.equal(soundResult.strict_hash_matches_header, true);
  assert.equal(soundResult.recomputed.strict_hash, hash);
  assert.equal(soundResult.verdict, 'not-checked');
  assert.notEqual(soundResult.recomputed.free_hash, null);

  const bad = join(dir, 'changed.eml');
  await writeFile(bad, deliveredMessage({ hash, body: BODY.replace('Friday', 'Monday') }));
  await assert.rejects(
    () => run(process.execPath, [VERIFY, bad, '--offline', '--json']),
    (err) => {
      // A message whose content does not match its own fingerprint is reported
      // as changed, and the exit code says so.
      assert.equal(err.code, 1);
      const result = JSON.parse(err.stdout);
      assert.equal(result.strict_hash_matches_header, false);
      assert.equal(result.verdict, VERDICT.TAMPERED);
      return true;
    },
  );
});

test('the not-verified block is not a green answer offline either', async () => {
  // A message carrying the §3.2 block says of itself that its sender was not
  // verified, and there is no fingerprint in it to compare with anything. 0
  // would tell a script reading the exit code that two readings agreed, and
  // nothing was read. The same message with a relay exits 1, and it does here.
  const dir = await mkdtemp(join(tmpdir(), 'zeknop-example-'));
  const file = join(dir, 'notice.eml');
  const headers = [
    `From: ${FROM}`,
    `To: ${TO}`,
    `Subject: ${SUBJECT}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
  ].join(CRLF);
  const body = buildNotVerified({ inner: BODY, eol: CRLF });
  await writeFile(file, `${headers}${CRLF}${CRLF}${body}`);

  await assert.rejects(
    () => run(process.execPath, [VERIFY, file, '--offline', '--json']),
    (err) => {
      assert.equal(err.code, 1);
      const result = JSON.parse(err.stdout);
      assert.equal(result.verdict, VERDICT.NOTICE);
      assert.equal(
        result.strict_hash_matches_header,
        null,
        'there was no fingerprint in the message, so nothing was compared',
      );
      return true;
    },
  );
});

test('--offline makes no request, and without it a relay is required', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'zeknop-example-'));
  const file = join(dir, 'message.eml');
  await writeFile(file, deliveredMessage({ hash: await strictHashOf(BODY) }));
  await assert.rejects(
    () => run(process.execPath, [VERIFY, file]),
    (err) => {
      assert.equal(err.code, 2);
      assert.match(err.stderr, /give --relay URL, or --offline/);
      return true;
    },
  );
});
