// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zeknod OÜ
// ─────────────────────────────────────────────────────────────────────────────
// A vector of ../../../vectors/vectors.json → the raw RFC 5322 bytes of a message.
//
// Why this file exists. `vectors.json` describes a message declaratively: the
// address fields, and then either a body or a `mime_tree`. A client that reads
// delivered mail never sees that description — it sees the wire bytes a mail
// client hands a person ("Show original", "Save as"). So the way to measure
// such a client against the vectors is to render each one to those bytes and
// read them back with the same code path the client uses for real mail. A
// harness that handed the walker a synthetic part object would prove nothing
// about the walker.
//
// The field names are the ones ../../../vectors/CONFORMANCE.md §2 lists for
// `vectors.json`; the rendering rules that are not a matter of taste are the two
// below, from ../../../spec/canonical-content.md §9.3 and RFC 2046 §5.1.1:
//
//   - a part's payload is followed by the line break that belongs to the NEXT
//     `--boundary` delimiter, so each part is the exact wire slice it was,
//   - a `message/rfc822` payload is written verbatim: its own trailing break is
//     part of the attached message and is hashed with it.
//
// Everything else here is scaffolding. It is not part of the specification and
// an implementation is free to feed itself the vectors some other way.
// ─────────────────────────────────────────────────────────────────────────────

import { multiByteEncoding } from '../vendor/canonical/multi-byte.mjs';
import { singleByteEncoding } from '../vendor/canonical/single-byte.mjs';

const CRLF = '\r\n';

function utf8(text) {
  return new TextEncoder().encode(text);
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

function base64ToBytes(text) {
  // Scaffolding only: the vectors carry their binary payloads as base64, and
  // this never touches a hash. The canonicalisation has its own decoder.
  const binary = atob(String(text).replace(/\s+/g, ''));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function wrapBase64(text) {
  return (String(text).match(/.{1,76}/g) || []).join(CRLF);
}

function hexToBytes(text) {
  const clean = String(text).trim();
  if (clean.length % 2 !== 0) throw new Error(`body_bytes_hex has an odd length: ${clean.length}`);
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

/**
 * A vector's `body_encoding` → the charset label a part on the wire declares.
 *
 * The vector files name the encoding the way the generator's own runtime spells
 * it (`utf-16-le`). The label a MIME part carries, and the only thing a reader
 * of delivered mail is given, is the WHATWG Encoding Standard label
 * (`utf-16le`). The two differ for exactly these names, so the translation is
 * written out here instead of guessed — and a name that comes out as no
 * encoding at all throws, because a part declaring an unknown charset is read
 * as UTF-8 (../../../spec/canonical-content.md §2) and the vector would then be
 * measured over bytes nobody asked about.
 */
const CHARSET_LABEL = {
  'utf-16-le': 'utf-16le',
  'utf-16-be': 'utf-16be',
};

/** The labels §2 reads as UTF-8 by name rather than through a table. */
const UTF8_LABELS = new Set(['utf-8', 'utf8']);

function charsetLabel(encoding) {
  const name = String(encoding || '')
    .trim()
    .toLowerCase();
  if (!name) throw new Error('a vector with body_bytes_hex carries no body_encoding');
  const label = CHARSET_LABEL[name] || name;
  if (!UTF8_LABELS.has(label) && !singleByteEncoding(label) && !multiByteEncoding(label)) {
    throw new Error(`body_encoding ${name} names no encoding of this build (as ${label})`);
  }
  return label;
}

/** One node of a `mime_tree` → its wire bytes, without any delimiter. */
function renderNode(node, boundaryPrefix) {
  const contentType = node.content_type || 'text/plain';
  const lowered = contentType.toLowerCase();
  const headers = [];

  if (lowered.startsWith('multipart/')) {
    const boundary = `${boundaryPrefix}x`;
    headers.push(`Content-Type: ${contentType}; boundary="${boundary}"`);
    const body = [];
    (node.children || []).forEach((child, index) => {
      body.push(utf8(`--${boundary}${CRLF}`));
      body.push(renderNode(child, `${boundary}_${index}_`));
      body.push(utf8(CRLF));
    });
    body.push(utf8(`--${boundary}--${CRLF}`));
    return concat([utf8(headers.join(CRLF) + CRLF + CRLF), ...body]);
  }

  const params = [];
  if (lowered.startsWith('text/')) params.push(`charset=${node.charset || 'utf-8'}`);
  if (node.filename && !node.disposition) params.push(`name="${node.filename}"`);
  headers.push(`Content-Type: ${contentType}${params.length ? '; ' + params.join('; ') : ''}`);
  if (node.disposition) {
    headers.push(
      `Content-Disposition: ${node.disposition}` +
        (node.filename ? `; filename="${node.filename}"` : ''),
    );
  }
  if (node.content_id) headers.push(`Content-ID: ${node.content_id}`);

  let payload;
  if (node.payload_base64 !== undefined) {
    // The exact wire payload of a text leaf in a declared charset, already in
    // the transfer encoding the node names.
    headers.push(`Content-Transfer-Encoding: ${node.transfer_encoding}`);
    payload = base64ToBytes(node.payload_base64);
  } else if (node.content_base64 !== undefined) {
    headers.push('Content-Transfer-Encoding: base64');
    payload = utf8(wrapBase64(node.content_base64));
  } else if (node.raw !== undefined) {
    payload = utf8(node.raw);
  } else {
    payload = utf8(node.text || '');
  }
  return concat([utf8(headers.join(CRLF) + CRLF + CRLF), payload]);
}

/**
 * A vector → the raw bytes of the message it describes.
 *
 * The signing timestamp is written where a delivered message carries it,
 * `X-ZEKNOP-Timestamp`, because that is where a reader of delivered mail takes
 * it from (../../../spec/canonical-content.md §6). With `timestampHeader: false`
 * the message carries none, which is the shape a reader must answer about
 * without guessing one.
 */
export function renderVector(vector, { timestampHeader = true } = {}) {
  const input = vector.input;
  const lines = [];
  const named = new Set();

  // `raw_headers` is the wire form: one [name, value] pair per header line, in
  // order, repeats included. A vector that carries it has it instead of the
  // single-value fields for those names.
  for (const [name, value] of input.raw_headers || []) {
    lines.push(`${name}: ${value}`);
    named.add(String(name).toLowerCase());
  }
  if (!named.has('from') && input.from !== undefined) lines.push(`From: ${input.from}`);
  if (!named.has('to')) {
    if (input.raw_to_header !== undefined) lines.push(`To: ${input.raw_to_header}`);
    else if (input.to_header !== undefined) lines.push(`To: ${input.to_header}`);
    else if (Array.isArray(input.to) && input.to.length) lines.push(`To: ${input.to.join(', ')}`);
  }
  if (!named.has('cc')) {
    if (input.cc_header !== undefined) lines.push(`Cc: ${input.cc_header}`);
    else if (Array.isArray(input.cc) && input.cc.length) lines.push(`Cc: ${input.cc.join(', ')}`);
  }
  if (!named.has('subject')) {
    const subject = input.subject_raw_mime !== undefined ? input.subject_raw_mime : input.subject;
    if (subject !== undefined) lines.push(`Subject: ${subject}`);
  }
  lines.push('MIME-Version: 1.0');
  if (timestampHeader && input.timestamp) lines.push(`X-ZEKNOP-Timestamp: ${input.timestamp}`);

  if (input.mime_tree) {
    return concat([utf8(lines.join(CRLF) + CRLF), renderNode(input.mime_tree, 'zb_')]);
  }

  // A vector carrying `body_bytes_hex` describes its body at BYTE level: the
  // octets on the wire, and the charset the part declares them in. Such a
  // vector also carries the already decoded text in `body`, and rendering THAT
  // would quietly measure an ASCII body instead of the rule the vector exists
  // for (a byte order mark detected before any decoding, §2 step 0). So the
  // bytes are written as they are and the part says what they are.
  if (input.body_bytes_hex !== undefined) {
    lines.push(`Content-Type: text/plain; charset=${charsetLabel(input.body_encoding)}`);
    return concat([
      utf8(lines.join(CRLF) + CRLF + CRLF),
      hexToBytes(input.body_bytes_hex),
    ]);
  }

  // A single text/plain part: the body as given, or — for the one vector that
  // describes a body too large to store — the characters it names.
  const body =
    typeof input.body === 'string'
      ? input.body
      : typeof input.body_length === 'number'
        ? 'A'.repeat(input.body_length)
        : '';
  lines.push('Content-Type: text/plain; charset=utf-8');
  return concat([utf8(lines.join(CRLF) + CRLF + CRLF), utf8(body)]);
}
