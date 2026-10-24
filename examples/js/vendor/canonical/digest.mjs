// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zeknod OÜ
//
// A copy of the ZEKNOP reference implementation of the canonical content
// specification, carried by the JavaScript example so that the example counts
// the same bytes as the service that signed the message. Apart from this header
// and the substitutions recorded with the copy, nothing in this file was changed.

// ─────────────────────────────────────────────────────────────────────────────
// SHA-256 over WebCrypto, plus the byte/base64 helpers the walker needs.
//
// WebCrypto (crypto.subtle) is the ONLY hash implementation here, on purpose: the
// verdict rests on this digest, so it is the runtime's own and never a hand-rolled
// copy. crypto.subtle exists only in a SECURE CONTEXT (https, or
// http://localhost) — where it is missing a reader must say so and refuse to
// answer rather than guess (see ./message.mjs, SecureContextError).
//
// Node 18+ exposes the same global, so the identical code runs outside a browser.
// ─────────────────────────────────────────────────────────────────────────────

export class SecureContextError extends Error {
  constructor() {
    super('WebCrypto (crypto.subtle) is unavailable — a secure connection is required');
    this.name = 'SecureContextError';
  }
}

export function subtleCrypto() {
  const c = globalThis.crypto;
  if (!c || !c.subtle || typeof c.subtle.digest !== 'function') throw new SecureContextError();
  return c.subtle;
}

export function hasSubtleCrypto() {
  const c = globalThis.crypto;
  return !!(c && c.subtle && typeof c.subtle.digest === 'function');
}

const encoder = new TextEncoder();

export function utf8Bytes(text) {
  return encoder.encode(text);
}

export function bytesToBase64(bytes) {
  const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = bytes[i + 1];
    const b2 = bytes[i + 2];
    out += ALPHABET[b0 >> 2];
    out += ALPHABET[((b0 & 0x03) << 4) | ((b1 === undefined ? 0 : b1) >> 4)];
    out += b1 === undefined ? '=' : ALPHABET[((b1 & 0x0f) << 2) | ((b2 === undefined ? 0 : b2) >> 6)];
    out += b2 === undefined ? '=' : ALPHABET[b2 & 0x3f];
  }
  return out;
}

/** Decode standard base64. Throws on a length that cannot be base64. */
export function base64ToBytes(text) {
  const clean = String(text).replace(/[^A-Za-z0-9+/=]/g, '').replace(/=+$/, '');
  if (clean.length % 4 === 1) throw new Error('invalid base64 length');
  const LOOKUP = new Map();
  const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  for (let i = 0; i < ALPHABET.length; i++) LOOKUP.set(ALPHABET[i], i);
  const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
  let o = 0;
  let buffer = 0;
  let bits = 0;
  for (const ch of clean) {
    const v = LOOKUP.get(ch);
    if (v === undefined) throw new Error('invalid base64 character');
    buffer = (buffer << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (buffer >> bits) & 0xff;
    }
  }
  return out.subarray(0, o);
}

/** base64url (the X-ZEKNOP-Verify token alphabet) → bytes. */
export function base64UrlToBytes(text) {
  let s = String(text).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4 !== 0) s += '=';
  return base64ToBytes(s);
}

/** spec §7: base64(SHA-256(bytes)). */
export async function sha256Base64(data) {
  const bytes = typeof data === 'string' ? utf8Bytes(data) : data;
  const digest = await subtleCrypto().digest('SHA-256', bytes);
  return bytesToBase64(new Uint8Array(digest));
}
