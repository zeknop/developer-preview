// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zeknod OÜ
// sign → verify → one character changed → invalid, against the stand-in relay
// of ./support/mock-relay.mjs: a real ed25519 signature over the bytes of
// ../../../spec/signature-input.md §2, on 127.0.0.1, with no container and no
// credential of anybody's.
//
// Nothing is mocked about the verdict. The stand-in checks the signature over
// the fingerprints the request names, so the tamper case fails for the reason a
// tamper case fails anywhere: the delivered content is not the content that was
// signed, so the fingerprint is not the one the signature was made over.

import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

import { VERDICT } from '../vendor/canonical/message.mjs';
import { startMockRelay } from './support/mock-relay.mjs';

const run = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));
const SIGN = resolve(HERE, '..', 'bin', 'sign.mjs');
const VERIFY = resolve(HERE, '..', 'bin', 'verify.mjs');

const CRLF = '\r\n';
const UUID = '00000000-0000-4000-8000-000000000000';
const FROM = 'sender@example.org';
const PORTAL = 'https://verify.example.org/v1';

const PLAIN = [
  `From: ${FROM}`,
  'To: recipient@example.com',
  'Subject: Invoice 2026-10',
  'MIME-Version: 1.0',
  'Content-Type: text/plain; charset=utf-8',
  '',
  'Amount due: 100 EUR',
  'Please pay by Friday.',
  '',
].join(CRLF);

const BOUNDARY = 'EXAMPLEBOUNDARY';
const ALTERNATIVE = [
  `From: ${FROM}`,
  'To: recipient@example.com',
  'Subject: Invoice 2026-10',
  'MIME-Version: 1.0',
  `Content-Type: multipart/alternative; boundary="${BOUNDARY}"`,
  '',
  `--${BOUNDARY}`,
  'Content-Type: text/plain; charset=utf-8',
  '',
  'Amount due: 100 EUR',
  `--${BOUNDARY}`,
  'Content-Type: text/html; charset=utf-8',
  '',
  '<!DOCTYPE html>',
  '<html><body><p>Amount due: 100 EUR</p></body></html>',
  `--${BOUNDARY}--`,
  '',
].join(CRLF);

async function withRelay(body, relayOptions = {}) {
  const relay = await startMockRelay(relayOptions);
  const dir = await mkdtemp(join(tmpdir(), 'zeknop-example-'));
  const source = join(dir, 'message.eml');
  await writeFile(source, body);
  return { relay, dir, source };
}

async function signIt({ relay, dir, source }) {
  const out = join(dir, 'signed.eml');
  const result = await run(process.execPath, [
    SIGN, source,
    '--uuid', UUID,
    '--api-key', relay.apiKey,
    '--relay', relay.url,
    '--portal', PORTAL,
    '--out', out,
    '--json',
  ]);
  return { out, report: JSON.parse(result.stderr) };
}

async function verifyIt(relay, file) {
  const result = await run(process.execPath, [VERIFY, file, '--relay', relay.url, '--json']);
  return JSON.parse(result.stdout);
}

test('a plain message: signed, then verified as sound', async () => {
  const context = await withRelay(PLAIN);
  try {
    const { out, report } = await signIt(context);
    assert.equal(report.shape, 'A');
    assert.equal(report.version, '1.5', 'the newest version both sides can build');
    assert.equal(report.algorithm, 'ed25519');
    assert.deepEqual(report.envelopes_written, ['plain']);
    assert.match(report.envelope_id, /^[A-Za-z0-9]{8}$/);
    assert.equal(report.verify_url.startsWith(`${PORTAL}/`), true);

    const delivered = await readFile(out, 'utf8');
    assert.match(delivered, /^X-ZEKNOP-Version: 1\.5$/m);
    assert.match(delivered, /^X-ZEKNOP-Sig-Alg: ed25519$/m);
    assert.match(delivered, /======= ZEKNOP =======/);
    assert.match(delivered, new RegExp(`Message ID: ${report.envelope_id}`));
    assert.match(delivered, /======= END ZEKNOP =======/);
    assert.match(delivered, /Amount due: 100 EUR/);

    const verdict = await verifyIt(context.relay, out);
    assert.equal(verdict.verdict, VERDICT.VERIFIED);
    assert.equal(verdict.strict_hash_matches_header, true);
    assert.equal(verdict.recomputed.strict_hash, report.strict_hash);
    assert.equal(verdict.recomputed.free_hash, report.free_hash);
    assert.deepEqual(verdict.identity, { kind: 'mailbox', value: FROM });

    // The relay was asked about the fingerprints and the identity, and about the
    // version the MESSAGE announces — never about this client's own newest one,
    // which is the other field.
    const asked = context.relay.state.verifyRequests.at(-1);
    assert.equal(asked.message_hash, report.strict_hash);
    assert.equal(asked.free_hash, report.free_hash);
    assert.equal(asked.version, '1.5');
    assert.equal(asked.understands, '1.5');
    assert.equal(asked.source, undefined, 'a third-party caller leaves `source` unset');
    assert.equal(asked.proxy_secret, undefined);
    // The message itself is not in the request.
    assert.equal(JSON.stringify(asked).includes('Amount due'), false);
  } finally {
    await context.relay.close();
  }
});

test('one character of the delivered body changed: invalid', async () => {
  const context = await withRelay(PLAIN);
  try {
    const { out } = await signIt(context);
    const tampered = join(context.dir, 'tampered.eml');
    const delivered = await readFile(out, 'utf8');
    assert.equal(delivered.includes('Amount due: 100 EUR'), true);
    await writeFile(tampered, delivered.replace('Amount due: 100 EUR', 'Amount due: 900 EUR'));

    await assert.rejects(
      () => verifyIt(context.relay, tampered),
      (err) => {
        assert.equal(err.code, 1);
        const verdict = JSON.parse(err.stdout);
        assert.equal(verdict.verdict, VERDICT.TAMPERED);
        assert.equal(verdict.strict_hash_matches_header, false);
        assert.equal(verdict.relay_reason, 'signature-mismatch');
        return true;
      },
    );
  } finally {
    await context.relay.close();
  }
});

test('a plain and an HTML part: both get the envelope, and it still verifies', async () => {
  const context = await withRelay(ALTERNATIVE);
  try {
    const { out, report } = await signIt(context);
    assert.equal(report.shape, 'B');
    assert.deepEqual(report.envelopes_written, ['plain', 'html']);

    const delivered = await readFile(out, 'utf8');
    // §3.3.1: the head block stands after the leading DOCTYPE, so the sender's
    // document keeps the parsing mode it had.
    assert.match(delivered, /<!DOCTYPE html>\r\n<!-- ======= ZEKNOP ======= -->/);
    assert.match(delivered, /<!-- ======= END ZEKNOP ======= -->/);
    assert.match(delivered, /<p>Amount due: 100 EUR<\/p>/);

    const verdict = await verifyIt(context.relay, out);
    assert.equal(verdict.verdict, VERDICT.VERIFIED);
  } finally {
    await context.relay.close();
  }
});

test('the wrong API key is refused, and nothing is written', async () => {
  const context = await withRelay(PLAIN);
  try {
    await assert.rejects(
      () => run(process.execPath, [
        SIGN, context.source,
        '--uuid', UUID,
        '--api-key', 'not-the-key',
        '--relay', context.relay.url,
        '--portal', PORTAL,
        '--out', join(context.dir, 'never.eml'),
      ]),
      (err) => {
        assert.equal(err.code, 1);
        assert.match(err.stderr, /POST \/v1\/sign answered 401/);
        return true;
      },
    );
    await assert.rejects(() => readFile(join(context.dir, 'never.eml')));
  } finally {
    await context.relay.close();
  }
});

test('a 409 is a refusal, and the exit code does not call it a verdict', async () => {
  // The message is signed by a relay that answers normally, and then asked
  // about by one that refuses the question. Nothing about the message changed
  // between the two, which is the whole point: a caller deciding by exit code
  // must not read the refusal as "this message is bad". 3 is the code for "no
  // verdict was obtained", where the outages are; 1 would be a verdict.
  const context = await withRelay(PLAIN, { refuseCallersBelow: '9.0' });
  try {
    const { out } = await signIt(context);
    await assert.rejects(
      () => verifyIt(context.relay, out),
      (err) => {
        assert.equal(err.code, 3, 'a refusal exits 3, with the outages, and not 1');
        const verdict = JSON.parse(err.stdout);
        assert.equal(verdict.verdict, VERDICT.UNSUPPORTED_VERSION);
        // The refusal is reported, with the relay's own sentence — which is how
        // it is told apart from an outage, where there is no result at all.
        assert.match(verdict.relay_detail || '', /did not say it can build/);
        assert.equal(verdict.identity, null);
        return true;
      },
    );
  } finally {
    await context.relay.close();
  }
});

test('without --portal nothing is signed: the link line has no default', async () => {
  // The portal goes into the delivered message (§3.4), so an example that
  // defaulted it would write a documentation address in front of the person who
  // receives the mail. 2 is "the command was asked wrongly", and the relay is
  // never asked anything.
  const context = await withRelay(PLAIN);
  try {
    await assert.rejects(
      () => run(process.execPath, [
        SIGN, context.source,
        '--uuid', UUID,
        '--api-key', context.relay.apiKey,
        '--relay', context.relay.url,
        '--out', join(context.dir, 'never.eml'),
      ]),
      (err) => {
        assert.equal(err.code, 2);
        assert.match(err.stderr, /--portal is required and has no default/);
        assert.match(err.stderr, /§3\.4/);
        return true;
      },
    );
    await assert.rejects(() => readFile(join(context.dir, 'never.eml')));
    assert.equal(context.relay.state.signRequests.length, 0);
  } finally {
    await context.relay.close();
  }
});

test('a relay that cannot say which version it signs is not a yes', async () => {
  const context = await withRelay(PLAIN);
  try {
    // A port nothing listens on: the capabilities question gets no answer, and a
    // signer that writes a version anyway writes a message no verifier can read.
    await assert.rejects(
      () => run(process.execPath, [
        SIGN, context.source,
        '--uuid', UUID,
        '--api-key', context.relay.apiKey,
        '--relay', 'http://127.0.0.1:1',
        '--portal', PORTAL,
        '--out', join(context.dir, 'never.eml'),
      ]),
      (err) => {
        assert.equal(err.code, 3);
        assert.match(err.stderr, /GET \/v1\/capabilities/);
        return true;
      },
    );
    assert.equal(context.relay.state.signRequests.length, 0);
  } finally {
    await context.relay.close();
  }
});
