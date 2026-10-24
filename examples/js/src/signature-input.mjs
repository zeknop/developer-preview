// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zeknod OÜ
// ─────────────────────────────────────────────────────────────────────────────
// The bytes a ZEKNOP signature is made over — ../../../spec/signature-input.md §2.
//
// A client that only asks a relay about a signature never assembles these bytes
// itself: the relay builds the input from the version, the algorithm and the two
// hashes, and signs that (../../../api/README.md, "Signing"). They are here because
// an implementation has to be able to show that it reads §2 the same way, and
// ../../../vectors/signature-input-vectors.json is the file that asks.
//
// Written from §2, not copied from a signer.
// ─────────────────────────────────────────────────────────────────────────────

import { base64ToBytes } from '../vendor/canonical/digest.mjs';

/** §2: ten fixed bytes, no length prefix. */
export const SEPARATOR = 'ZEKNOP-SIG';

/** The marker ../../../vectors/signature-input-vectors.json uses for a pre-v1.4 message. */
export const LEGACY = 'legacy';

function asciiBytes(text) {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
  return out;
}

function utf8(text) {
  return new TextEncoder().encode(text);
}

function lengthPrefixed(bytes) {
  if (bytes.length > 255) {
    // §2: a field longer than 255 bytes cannot be expressed, and the signature
    // is refused rather than truncated.
    throw new Error(`a field of ${bytes.length} bytes cannot carry a one-byte length`);
  }
  const out = new Uint8Array(bytes.length + 1);
  out[0] = bytes.length;
  out.set(bytes, 1);
  return out;
}

function concat(chunks) {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.length;
  }
  return out;
}

/**
 * The signature input for a message announcing `version` and `algorithm`, whose
 * two hashes are the base64 values the headers carry.
 *
 * `version` `legacy` — a message from before v1.4, or one that announces a
 * version outside the registry (§4) — is the strict hash on its own: thirty-two
 * bytes, with nothing around them. Every other version is the form of §2, in
 * the fixed order separator, version, algorithm, strict hash, free hash, each
 * field after the separator carrying its own length as one unsigned byte.
 *
 * The algorithm name is measured in BYTES and may be any UTF-8 text; the hashes
 * enter as the raw 32 bytes of SHA-256, decoded from the base64 the headers and
 * the API carry them in.
 */
export function signatureInput({ version, algorithm, strictHashB64, freeHashB64 }) {
  const strict = base64ToBytes(strictHashB64);
  if (version === LEGACY) return strict;
  if (freeHashB64 === null || freeHashB64 === undefined) {
    throw new Error(`version ${version} needs a free hash (§2); only ${LEGACY} has none`);
  }
  return concat([
    asciiBytes(SEPARATOR),
    lengthPrefixed(utf8(String(version))),
    lengthPrefixed(utf8(String(algorithm))),
    lengthPrefixed(strict),
    lengthPrefixed(base64ToBytes(freeHashB64)),
  ]);
}

/** Lowercase hex of a byte string, which is how the vectors print the input. */
export function hex(bytes) {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}
