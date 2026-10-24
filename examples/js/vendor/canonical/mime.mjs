// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zeknod OÜ
//
// A copy of the ZEKNOP reference implementation of the canonical content
// specification, carried by the JavaScript example so that the example counts
// the same bytes as the service that signed the message. Apart from this header
// and the substitutions recorded with the copy, nothing in this file was changed.

// ─────────────────────────────────────────────────────────────────────────────
// Offset-based MIME walker over RAW BYTES (canonical-content.md §9).
//
// Why bytes and not a MIME object model: the v1.3 manifest binds
// `message/rfc822` as an OPAQUE LEAF whose hash covers the attached message's
// WIRE bytes exactly as delivered, and every binary leaf's hash covers its
// exact decoded payload. A parser that re-serialises an object tree changes
// line endings and header folding, so its hash diverges from the signer's.
// This walker therefore splits the raw bytes itself: multipart boundaries by
// offset, headers parsed only from the header block (./headers.mjs), payloads
// kept as exact wire slices, and message/rfc822 never descended into.
//
// Every rule below has its counterpart in the readers written in other languages,
// and the vectors are what holds them together: vectors.json, rendered to raw bytes
// and walked here, is the same question put to each of them.
// ─────────────────────────────────────────────────────────────────────────────

import { parseHeaderBlock, partHeaders, decodeBytesWithCharset } from './headers.mjs';
import { base64ToBytes, sha256Base64, utf8Bytes } from './digest.mjs';
import { canonicalTextPartInput } from './base.mjs';

function indexOfBytes(haystack, needle, from) {
  outer: for (let i = from; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

/** `[ \t]*(\r?\n|end of body)` at `pos` → the length matched, or -1. */
function matchTerminator(bytes, pos) {
  let i = pos;
  while (i < bytes.length && (bytes[i] === 0x20 || bytes[i] === 0x09)) i++;
  if (i >= bytes.length) return i - pos;
  if (bytes[i] === 0x0d && bytes[i + 1] === 0x0a) return i + 2 - pos;
  if (bytes[i] === 0x0a) return i + 1 - pos;
  return -1;
}

/**
 * RFC 2046 §5.1.1 boundary split. The line break preceding a delimiter belongs
 * to the DELIMITER, so each chunk is the exact wire slice of one part.
 * `--B1` and `--B--1` are NOT delimiters of `B` (spec §9.3 "Boundary matching").
 */
export function splitMultipart(body, boundaryText) {
  const delim = utf8Bytes('--' + boundaryText);
  const chunks = [];
  let pos = 0;
  let start = null;
  let closed = false;
  for (;;) {
    const idx = indexOfBytes(body, delim, pos);
    if (idx === -1) break;
    if (idx > 0 && body[idx - 1] !== 0x0a) {
      pos = idx + delim.length;
      continue;
    }
    const after = idx + delim.length;
    const isClose = body[after] === 0x2d && body[after + 1] === 0x2d && matchTerminator(body, after + 2) !== -1;
    const isPart = matchTerminator(body, after) !== -1;
    if (!isClose && !isPart) {
      pos = after;
      continue;
    }
    if (start !== null) {
      let end = idx;
      if (body[end - 1] === 0x0a) {
        end -= 1;
        if (body[end - 1] === 0x0d) end -= 1;
      }
      chunks.push(body.subarray(start, end));
      start = null;
    }
    if (isClose) {
      closed = true;
      break;
    }
    // Skip transport padding and the line break after the delimiter.
    let skip = after;
    while (body[skip] === 0x20 || body[skip] === 0x09) skip++;
    if (body[skip] === 0x0d && body[skip + 1] === 0x0a) skip += 2;
    else if (body[skip] === 0x0a) skip += 1;
    start = skip;
    pos = start;
  }
  if (start !== null && !closed) {
    // Unterminated multipart: the rest is the final part. Every byte still
    // lands in some leaf's hash, so tampering cannot hide here.
    chunks.push(body.subarray(start));
  }
  return chunks;
}

const isHex = (b) => (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x46) || (b >= 0x61 && b <= 0x66);
const unhex = (a, b) => parseInt(String.fromCharCode(a, b), 16);

/**
 * quoted-printable, byte-for-byte as Python's `quopri.decodestring` decodes it
 * (that is `binascii.a2b_qp`, which the readers written in Python call). The two
 * MUST agree byte for byte: one reader takes a message through the Python one and
 * another takes the SAME message through this one, and a leaf they decode
 * differently is a leaf they hash differently — one of them green and the other
 * red over one untouched attachment.
 *
 * The rules, in the order a2b_qp applies them:
 *   "=" then LF, or "=" then anything up to and including the next LF → a SOFT
 *        line break: the whole run disappears;
 *   "=" at the very end of the data                                   → dropped;
 *   "=="                                                              → one "=";
 *   "=" then two hex digits (either case)                             → that byte;
 *   "=" then anything else                                            → a literal
 *        "=", and the bytes after it are read again as ordinary content;
 *   every other byte, CR and LF included, is copied VERBATIM.
 *
 * The last rule is the one that matters here: a hard line break stays CRLF, and
 * trailing whitespace before it is NOT stripped. §9.3 binds a raw-bytes leaf as
 * the bytes AS DELIVERED, so a CRLF that survives decoding is part of the leaf.
 */
export function decodeQuotedPrintable(bytes) {
  const out = [];
  let i = 0;
  const n = bytes.length;
  while (i < n) {
    const c = bytes[i];
    if (c !== 0x3d) { out.push(c); i++; continue; }
    i++;                                                    // consume the '='
    if (i >= n) break;                                      // '=' at end of data
    if (bytes[i] === 0x0a) { i++; continue; }               // soft break "=LF"
    if (bytes[i] === 0x0d) {                                // soft break "=CR…LF"
      while (i < n && bytes[i] !== 0x0a) i++;
      if (i < n) i++;
      continue;
    }
    if (bytes[i] === 0x3d) { out.push(0x3d); i++; continue; }
    if (i + 1 < n && isHex(bytes[i]) && isHex(bytes[i + 1])) {
      out.push(unhex(bytes[i], bytes[i + 1]));
      i += 2;
      continue;
    }
    out.push(0x3d);                                         // a '=' that begins nothing
  }
  return Uint8Array.from(out);
}

/** Remove the Content-Transfer-Encoding. Unknown/broken encodings fall back to
 *  identity — the bytes still get hashed, nothing is silently dropped. */
export function decodeCte(bodyRaw, cte) {
  const enc = (cte || '').trim().toLowerCase();
  if (enc === 'base64') {
    try {
      let text = '';
      for (let i = 0; i < bodyRaw.length; i++) text += String.fromCharCode(bodyRaw[i]);
      return base64ToBytes(text);
    } catch {
      return bodyRaw;
    }
  }
  if (enc === 'quoted-printable') {
    try {
      return decodeQuotedPrintable(bodyRaw);
    } catch {
      return bodyRaw;
    }
  }
  return bodyRaw;
}

/**
 * A text part's bytes → its text, through the charset it declares
 * (spec/canonical-content.md §2 — one rule, shared with the encoded words of
 * §5). The tables pinned in this repository decide, never the runtime's own
 * TextDecoder: its reading of bytes 0x80-0x9F depends on the JavaScript engine
 * (Node reads iso-8859-1 0x96 as U+0096, Chromium as U+2013), and for the
 * multi-byte encodings it is ICU rather than the WHATWG Encoding Standard.
 */
export function decodeText(bytes, charset) {
  return decodeBytesWithCharset(bytes, charset);
}

/** Parse one MIME part from its exact wire slice. Never touches a payload. */
export function parsePart(raw) {
  const { headers, bodyStart } = parseHeaderBlock(raw);
  const h = partHeaders(headers);
  const part = {
    headers,
    contentType: h.contentType,
    disposition: h.disposition,
    filename: h.filename,
    contentId: h.contentId,
    charset: h.charset,
    cte: h.cte,
    bodyRaw: raw.subarray(bodyStart),
    children: [],
  };
  // message/rfc822 is an OPAQUE LEAF (§9.2) — never descend.
  if (part.contentType === 'message/rfc822') return part;
  if (part.contentType.startsWith('multipart/')) {
    if (h.boundary) {
      for (const chunk of splitMultipart(part.bodyRaw, h.boundary)) {
        part.children.push(parsePart(chunk));
      }
    }
    // A multipart without a usable boundary keeps NO children; the manifest
    // binds its raw body as one opaque leaf (§9.2 fail-closed).
  }
  return part;
}

const normName = (s) => s.trim().toLowerCase();

async function textLeafHash(text) {
  return sha256Base64(utf8Bytes(canonicalTextPartInput(text)));
}

/**
 * spec §9.1–§9.4: depth-first pre-order; every leaf contributes exactly one
 * `{k[,n],h}` entry, in document order, never sorted.
 *
 * plainTransform: optional str→str applied to decoded text/plain leaves before
 * normalization — a verifier passes stripZeknopEnvelope so the recomputed hash
 * covers the ORIGINAL text the signer hashed, not the delivered envelope.
 */
export async function extractPartsManifest(root, plainTransform, collect, htmlTransform) {
  const parts = [];
  let rfc822Ordinal = 0;

  async function visit(p) {
    if (p.contentType === 'message/rfc822') {
      const h = await sha256Base64(decodeCte(p.bodyRaw, p.cte));
      parts.push({ k: 'rfc822', n: `rfc822[${rfc822Ordinal++}]`, h });
      return;
    }
    if (p.contentType.startsWith('multipart/')) {
      if (!p.children.length) {
        // Malformed multipart with no usable boundary → fail CLOSED (§9.2):
        // the container's raw body becomes one opaque leaf, so the manifest is
        // never empty and the body stays cryptographically bound.
        parts.push({ k: 'opaque', h: await sha256Base64(p.bodyRaw) });
        return;
      }
      for (const child of p.children) await visit(child);
      return;
    }
    // §9.3 leaf classification — first match wins.
    if (p.disposition === 'attachment' || (p.filename && p.disposition !== 'inline')) {
      const entry = { k: 'attachment' };
      if (p.filename) entry.n = normName(p.filename);
      entry.h = await sha256Base64(decodeCte(p.bodyRaw, p.cte));
      parts.push(entry);
      return;
    }
    if (p.contentType === 'text/plain' && !p.filename) {
      let text = decodeText(decodeCte(p.bodyRaw, p.cte), p.charset);
      if (plainTransform) text = plainTransform(text);
      if (collect) collect('plain', text);
      parts.push({ k: 'plain', h: await textLeafHash(text) });
      return;
    }
    if (p.contentType === 'text/html' && !p.filename) {
      // As for a plain leaf: the delivered bytes with our own blocks taken off
      // again at the two ends of the part (spec/delivered-envelope.md §6.1), so
      // what is hashed here is what the signer hashed.
      let text = decodeText(decodeCte(p.bodyRaw, p.cte), p.charset);
      if (htmlTransform) text = htmlTransform(text);
      if (collect) collect('html', text);
      parts.push({ k: 'html', h: await textLeafHash(text) });
      return;
    }
    if (p.disposition === 'inline' || (!p.disposition && p.contentId)) {
      const entry = { k: 'inline' };
      if (p.filename) {
        entry.n = normName(p.filename);
      } else if (p.contentId) {
        let value = p.contentId.trim();
        if (value.startsWith('<') && value.endsWith('>')) value = value.slice(1, -1);
        entry.n = 'cid:' + normName(value);
      }
      entry.h = await sha256Base64(decodeCte(p.bodyRaw, p.cte));
      parts.push(entry);
      return;
    }
    // §9.3 rule 6 — the catch-all keeps the manifest total.
    const entry = { k: 'attachment' };
    if (p.filename) entry.n = normName(p.filename);
    entry.h = await sha256Base64(decodeCte(p.bodyRaw, p.cte));
    parts.push(entry);
  }

  await visit(root);
  return parts;
}

/** §1.1: Shape A iff a single non-multipart text/plain part with no filename. */
export function isShapeA(root) {
  return (
    !root.contentType.startsWith('multipart/') &&
    root.contentType === 'text/plain' &&
    !root.filename
  );
}

/** The Shape A body: the root's decoded text (§1.1). */
export function shapeABody(root) {
  return decodeText(decodeCte(root.bodyRaw, root.cte), root.charset);
}

/**
 * Which text the FREE hash is taken from (spec/canonical-content.md §2b.1), as
 * { text, isHtml }.
 *
 * One message has exactly one free hash, so the part is chosen by STRUCTURE and never by what
 * a reader happens to be shown: the first displayed text/plain leaf in document order with our
 * envelope removed, and only when the message has none, the first displayed text/html leaf. A
 * message with neither has the empty text — a defined answer rather than a missing one.
 *
 * `strip` is the plain-text envelope remover and `htmlStrip` the HTML one, both passed in so
 * this module keeps no dependency on the envelope.
 */
export async function freeFormSource(root, strip, htmlStrip) {
  let plain = null;
  let html = null;
  await extractPartsManifest(root, strip, (kind, text) => {
    if (kind === 'plain' && plain === null) plain = text;
    if (kind === 'html' && html === null) html = text;
  }, htmlStrip);
  if (plain !== null) return { text: plain, isHtml: false };
  // `htmlStrip` has already run in the walk; `strip` is the plain-text remover and is applied
  // for the shapes it knows (a part without the HTML blocks that carries the plain envelope
  // as its text).
  if (html !== null) return { text: strip ? strip(html) : html, isHtml: true };
  return { text: '', isHtml: false };
}
