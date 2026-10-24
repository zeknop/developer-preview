// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zeknod OÜ
// ─────────────────────────────────────────────────────────────────────────────
// A relay stand-in for the tests of this example: the answers of
// ../../../../api/openapi-public.json, on 127.0.0.1, with a real signature.
//
// It is NOT a relay and it is not a model of one. It holds no identity store, no
// rate limit, no replay mark and no registration; what it does hold is the one
// thing a test of a CLIENT needs to be worth running: an ed25519 key pair, so
// the signature it answers with is a signature over the bytes of
// ../../../../spec/signature-input.md §2 and `valid` is the result of checking it.
//
// That is why a message with one character changed comes back `valid: false`
// here, and why that is evidence rather than a canned answer: the client
// recomputes a different fingerprint, the fingerprint goes into a different
// signature input, and the signature does not hold over it.
//
// The key pair is generated when the server starts and is thrown away with it.
// There is no secret here to leak and nothing here to deploy.
// ─────────────────────────────────────────────────────────────────────────────

import { createServer } from 'node:http';
import { generateKeyPairSync, randomBytes, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';

import { signatureInput } from '../../src/signature-input.mjs';

const CONTRACT = '1.8';
const VERSIONS = ['1.4', '1.5'];

function envelopeId() {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const bytes = randomBytes(8);
  let out = '';
  for (const byte of bytes) out += alphabet[byte % alphabet.length];
  return out;
}

async function readJson(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  if (chunks.length === 0) return null;
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    return undefined;
  }
}

/** `1.5` is at least `1.4`; a caller that named no version is at least nothing. */
function atLeast(given, wanted) {
  if (!given) return false;
  const a = String(given).split('.').map(Number);
  const b = String(wanted).split('.').map(Number);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const left = a[i] || 0;
    const right = b[i] || 0;
    if (left !== right) return left > right;
  }
  return true;
}

/**
 * Start the stand-in. Resolves to { url, close, state } — `state` carries what
 * it was asked to sign, so a test can assert on the request as well as on the
 * answer.
 *
 * `refuseCallersBelow` makes POST /v1/verify answer 409 to a caller whose
 * `understands` is older than that version, which is the refusal of
 * ../../../../api/README.md, "A verifier older than the message is refused, not
 * answered". It is here so a test can see what a CLIENT does with a refusal; it
 * is not a model of when a relay issues one.
 */
export async function startMockRelay({
  apiKey = 'example-api-key',
  relayId = 'mock-relay',
  refuseCallersBelow = null,
} = {}) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const state = { signed: [], verifyRequests: [], signRequests: [] };

  const server = createServer(async (request, response) => {
    const url = new URL(request.url, 'http://127.0.0.1');
    const send = (status, body) => {
      const text = JSON.stringify(body);
      response.writeHead(status, { 'Content-Type': 'application/json' });
      response.end(text);
    };

    if (request.method === 'GET' && url.pathname === '/health') {
      send(200, { status: 'ok' });
      return;
    }

    if (request.method === 'GET' && url.pathname === '/v1/capabilities') {
      send(200, {
        contract: CONTRACT,
        relay_id: relayId,
        signs: VERSIONS,
        verifies: VERSIONS,
        signature_input_version: VERSIONS[VERSIONS.length - 1],
      });
      return;
    }

    if (request.method === 'POST' && url.pathname === '/v1/sign') {
      const body = await readJson(request);
      if (body === undefined || body === null) {
        send(422, { detail: 'the request body is not JSON' });
        return;
      }
      state.signRequests.push({ body, headers: { ...request.headers } });
      if (request.headers['x-api-key'] !== apiKey) {
        send(401, { detail: 'the API key is not one this relay holds for that identity' });
        return;
      }
      let input;
      try {
        input = signatureInput({
          version: body.version || 'legacy',
          algorithm: body.alg,
          strictHashB64: body.content_hash,
          freeHashB64: body.free_hash,
        });
      } catch (err) {
        send(422, { detail: err.message });
        return;
      }
      const signature = cryptoSign(null, input, privateKey).toString('base64');
      const record = {
        uuid: body.uuid,
        signature,
        version: body.version || null,
        alg: body.alg || 'ed25519',
        envelope_id: envelopeId(),
        from_address: body.from_address,
        timestamp: body.timestamp,
      };
      state.signed.push(record);
      send(200, {
        signature,
        envelope_id: record.envelope_id,
        relay_id: relayId,
        relay_timestamp: new Date().toISOString(),
        version: record.version,
        alg: record.alg,
      });
      return;
    }

    if (request.method === 'POST' && url.pathname === '/v1/verify') {
      const body = await readJson(request);
      if (body === undefined || body === null) {
        send(422, { detail: 'the request body is not JSON' });
        return;
      }
      state.verifyRequests.push(body);
      if (refuseCallersBelow && !atLeast(body.understands, refuseCallersBelow)) {
        send(409, {
          detail:
            `the signature was recorded under version ${refuseCallersBelow}, ` +
            `which this caller did not say it can build`,
        });
        return;
      }
      const record = state.signed.find((entry) => entry.uuid === body.uuid);
      if (!record) {
        send(200, { valid: false, uuid: body.uuid, reason: 'unknown-identity' });
        return;
      }
      let holds = false;
      try {
        const input = signatureInput({
          version: body.version || 'legacy',
          algorithm: body.alg || 'ed25519',
          strictHashB64: body.message_hash,
          freeHashB64: body.free_hash,
        });
        holds = cryptoVerify(null, input, publicKey, Buffer.from(body.signature, 'base64'));
      } catch {
        holds = false;
      }
      if (!holds) {
        send(200, { valid: false, uuid: body.uuid, reason: 'signature-mismatch' });
        return;
      }
      send(200, {
        valid: true,
        uuid: body.uuid,
        email: record.from_address,
        verification_level: 'user',
        verification_type: 'mailbox',
        status: 'active',
        alg: record.alg,
      });
      return;
    }

    const lookup = /^\/v1\/signature\/([A-Za-z0-9]{8})$/.exec(url.pathname);
    if (request.method === 'GET' && lookup) {
      const record = state.signed.find((entry) => entry.envelope_id === lookup[1]);
      if (!record) {
        send(404, { detail: 'no record of that envelope id' });
        return;
      }
      // Who signed and when, and no fingerprint of anything.
      send(200, {
        uuid: record.uuid,
        email: record.from_address,
        timestamp: record.timestamp,
        relay_id: relayId,
        verification_level: 'user',
        verification_type: 'mailbox',
        status: 'active',
      });
      return;
    }

    send(404, { detail: 'not a path of this stand-in' });
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}`,
    state,
    apiKey,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}
