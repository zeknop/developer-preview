// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zeknod OÜ
// ─────────────────────────────────────────────────────────────────────────────
// The three relay calls this example makes, over the built-in fetch.
//
// Nothing here interprets an answer: the verdict is read where it is reported,
// so that this file stays the shape of the request and the status code and
// nothing else. The semantics of each answer are in ../../../api/README.md.
// ─────────────────────────────────────────────────────────────────────────────

const DEFAULT_TIMEOUT_MS = 10_000;

/** A request that did not come back as a JSON body the caller can read. */
export class RelayError extends Error {
  constructor(message, { status = null, body = null } = {}) {
    super(message);
    this.name = 'RelayError';
    this.status = status;
    this.body = body;
  }
}

function joinUrl(base, path) {
  return String(base).replace(/\/+$/, '') + path;
}

async function call(url, { method = 'GET', headers = {}, body = null, timeoutMs } = {}) {
  let response;
  try {
    response = await fetch(url, {
      method,
      headers: body === null ? headers : { 'Content-Type': 'application/json', ...headers },
      body: body === null ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs || DEFAULT_TIMEOUT_MS),
    });
  } catch (err) {
    // No connection and a timeout are the same kind of thing to a caller: the
    // relay said nothing, so nothing is known (../../../api/README.md, "Which
    // answers are an outage and which are not").
    throw new RelayError(`${method} ${url}: ${err.message}`);
  }
  const text = await response.text();
  let parsed = null;
  if (text !== '') {
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new RelayError(`${method} ${url}: the answer is not JSON`, {
        status: response.status,
        body: text.slice(0, 200),
      });
    }
  }
  return { status: response.status, body: parsed };
}

/**
 * GET /v1/capabilities — which versions of the signature input this relay can
 * sign and can verify. A signer asks before it writes a version; a relay that
 * answers anything but 200 has not said yes.
 */
export async function getCapabilities(relayUrl, options = {}) {
  return call(joinUrl(relayUrl, '/v1/capabilities'), options);
}

/** POST /v1/sign — needs the identity's API key. */
export async function postSign(relayUrl, apiKey, payload, { idempotencyKey = null, ...options } = {}) {
  const headers = { 'X-API-Key': apiKey };
  if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;
  return call(joinUrl(relayUrl, '/v1/sign'), { method: 'POST', headers, body: payload, ...options });
}

/** POST /v1/verify — asks for no credential. */
export async function postVerify(relayUrl, payload, options = {}) {
  return call(joinUrl(relayUrl, '/v1/verify'), { method: 'POST', body: payload, ...options });
}
