// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zeknod OÜ
// ─────────────────────────────────────────────────────────────────────────────
// Turning a composed message into a signed one, at the byte level.
//
// Two things happen to the bytes of a message when it is signed: the
// `X-ZEKNOP-*` fields are added to the header block, and the visible envelope
// goes around the sender's text in every displayed part
// (../../../spec/delivered-envelope.md §4). Neither may change anything else, so
// nothing here re-serialises a parsed message: every part is spliced in place,
// by offset, and the bytes outside the splices are the bytes that came in.
//
// That matters for the fingerprint and not for tidiness. A leaf of the parts
// manifest is bound as the bytes AS DELIVERED (../../../spec/canonical-content.md
// §9.3), so a writer that rebuilt the message from an object model — refolding a
// header, changing a line ending, re-encoding a payload — would hand the relay
// one message to sign and the recipient another.
//
// What this example does NOT do, and refuses rather than doing badly:
//
//   - a displayed part in a transfer encoding other than identity (base64,
//     quoted-printable). A signer has to write the block in the part's own
//     encoding, and for quoted-printable it has to place the soft line breaks
//     while the link line is still a placeholder of the final length (§3.4).
//     Both are real work and neither is what an example is for.
//   - a displayed part whose charset does not read ASCII as ASCII (UTF-16,
//     UTF-32, ISO-2022). §3.3 gives the rule for a plain part in such a charset
//     and §3.3.1 forbids an HTML one; writing US-ASCII block bytes into one is
//     simply wrong.
//   - a message with no displayed part to write into, and a malformed multipart
//     the walk binds as one opaque leaf (§9.2 fail-closed): there is no text to
//     put a block around.
//
// Each of those is reported with the condition it met, so a refusal says what to
// change about the message rather than that something went wrong.
// ─────────────────────────────────────────────────────────────────────────────

import { singleByteEncoding } from '../vendor/canonical/single-byte.mjs';
import { parsePart } from '../vendor/canonical/mime.mjs';
import { positiveAround, positiveHtmlAround, splitDoctype } from './envelope-build.mjs';

const utf8 = (text) => new TextEncoder().encode(text);
/** One byte per character: the ASCII prefix of a part, read without a charset. */
const latin1 = (bytes) => {
  let out = '';
  for (const byte of bytes) out += String.fromCharCode(byte);
  return out;
};
const latin1Bytes = (text) => {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
  return out;
};

/** A condition of the message that stops this example from signing it. */
export class Unsignable extends Error {
  constructor(message) {
    super(message);
    this.name = 'Unsignable';
  }
}

const IDENTITY_ENCODINGS = new Set(['', '7bit', '8bit', 'binary']);
const UNICODE_ASCII_CHARSETS = new Set(['', 'utf-8', 'utf8', 'us-ascii', 'ascii']);

function identityEncoded(cte) {
  return IDENTITY_ENCODINGS.has(String(cte || '').trim().toLowerCase());
}

/** §3.3.1, "Which parts get one": a charset that reads ASCII as ASCII. */
function asciiCompatible(charset) {
  const label = String(charset || '').trim().toLowerCase();
  if (UNICODE_ASCII_CHARSETS.has(label)) return true;
  // Every single-byte encoding of the standard agrees with ASCII below 0x80.
  return Boolean(singleByteEncoding(label));
}

/** The line ending of a part: CRLF on the wire, LF for a part that uses bare LF. */
export function partEol(payload) {
  for (let i = 0; i < payload.length; i++) {
    if (payload[i] !== 0x0a) continue;
    return i > 0 && payload[i - 1] === 0x0d ? '\r\n' : '\n';
  }
  return '\r\n';
}

/** { sepStart, bodyStart } of the header block separator, or null for no body. */
export function headerSeparator(raw) {
  for (let i = 0; i < raw.length; i++) {
    let j = i;
    if (raw[j] === 0x0d) j++;
    if (raw[j] !== 0x0a) continue;
    j++;
    if (raw[j] === 0x0d) j++;
    if (raw[j] !== 0x0a) continue;
    return { sepStart: i, bodyStart: j + 1 };
  }
  return null;
}

/** The range of `part.bodyRaw` inside `raw`, both views of one buffer. */
function payloadRange(raw, part) {
  return {
    start: part.bodyRaw.byteOffset - raw.byteOffset,
    end: part.bodyRaw.byteOffset - raw.byteOffset + part.bodyRaw.length,
  };
}

/**
 * The displayed parts an envelope goes into, in document order (§4): each
 * `text/plain` leaf with no file name, and each `text/html` leaf with no file
 * name. A `message/rfc822` part is an opaque leaf and is never entered.
 *
 * Returns [{ kind, start, end, cte, charset }]. Throws `Unsignable` for a part
 * this example will not write into, naming the condition.
 */
export function displayedParts(raw, root) {
  const found = [];
  const visit = (part) => {
    if (part.contentType === 'message/rfc822') return;
    if (part.contentType.startsWith('multipart/')) {
      if (!part.children.length) {
        throw new Unsignable(
          'the message has a multipart container with no usable boundary, which the walk ' +
            'binds as one opaque leaf (canonical-content.md §9.2): there is no displayed ' +
            'text to put a block around',
        );
      }
      for (const child of part.children) visit(child);
      return;
    }
    const isPlain = part.contentType === 'text/plain' && !part.filename;
    const isHtml = part.contentType === 'text/html' && !part.filename;
    if (!isPlain && !isHtml) return;
    if (part.disposition === 'attachment') return;
    if (!identityEncoded(part.cte)) {
      throw new Unsignable(
        `a displayed ${part.contentType} part is in the transfer encoding ` +
          `"${part.cte}"; this example writes the envelope only into a part in an identity ` +
          'encoding (7bit, 8bit, binary or none)',
      );
    }
    if (!asciiCompatible(part.charset)) {
      throw new Unsignable(
        `a displayed ${part.contentType} part declares the charset ` +
          `"${part.charset}", which does not read ASCII as ASCII; delivered-envelope.md ` +
          '§3.3.1 gives that case its own rules and this example does not write it',
      );
    }
    found.push({ kind: isPlain ? 'plain' : 'html', ...payloadRange(raw, part), charset: part.charset });
  };
  visit(root);
  return found;
}

/** Replace the given byte ranges of `raw`, in order, with new bytes. */
function splice(raw, replacements) {
  const sorted = [...replacements].sort((a, b) => a.start - b.start);
  const chunks = [];
  let at = 0;
  for (const replacement of sorted) {
    chunks.push(raw.subarray(at, replacement.start));
    chunks.push(replacement.bytes);
    at = replacement.end;
  }
  chunks.push(raw.subarray(at));
  const total = chunks.reduce((n, chunk) => n + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/**
 * Add header fields to the header block, in the line ending the block uses.
 *
 * They go at the END of the block, after the fields that are there, which is
 * where a mail server adds its own and is what keeps the sender's fields and
 * their order exactly as they came.
 */
export function addHeaders(raw, fields) {
  const separator = headerSeparator(raw);
  if (!separator) throw new Unsignable('the message has no header block and body separated by a blank line');
  const eol = raw[separator.sepStart] === 0x0d ? '\r\n' : '\n';
  // `sepStart` is where the line terminator of the LAST header field begins, so
  // the new fields start with one of their own and end without one: the blank
  // line that follows is the separator and stays exactly where it was.
  const lines = fields.map(([name, value]) => `${name}: ${value}`).join(eol);
  const text = separator.sepStart === 0 ? lines : eol + lines;
  return splice(raw, [
    { start: separator.sepStart, end: separator.sepStart, bytes: utf8(text) },
  ]);
}

/**
 * Write the positive envelope into every displayed part of `raw` (§4).
 *
 * A plain part keeps its bytes and gets the block around them; its trailing line
 * breaks are dropped first, because the removal of §6.1 drops them again on the
 * way back and a round trip has to end where it started. Neither the strict form
 * nor the free text form is affected either way: §2 trims the ends.
 *
 * An HTML part gets the head block after a leading DOCTYPE and the tail block
 * after its last byte, with nothing inserted between a block and the sender's
 * markup (§3.3.1).
 */
export function writeEnvelopes(raw, { envelopeId, verifyUrl }) {
  const root = parsePart(raw);
  const parts = displayedParts(raw, root);
  if (parts.length === 0) {
    throw new Unsignable(
      'the message has no displayed text/plain or text/html part this example can write ' +
        'the envelope into',
    );
  }
  const replacements = parts.map((part) => {
    const payload = raw.subarray(part.start, part.end);
    const eol = partEol(payload);
    if (part.kind === 'plain') {
      const { before, after } = positiveAround({ envelopeId, verifyUrl, eol });
      let end = payload.length;
      while (end > 0 && (payload[end - 1] === 0x0a || payload[end - 1] === 0x0d)) end -= 1;
      return {
        start: part.start,
        end: part.end,
        bytes: concatBytes([latin1Bytes(before), payload.subarray(0, end), latin1Bytes(after)]),
      };
    }
    const { head, tail } = positiveHtmlAround({ envelopeId, verifyUrl, eol });
    // The DOCTYPE is ASCII and is read as bytes, so a part in any charset that
    // reads ASCII as ASCII is split at the same place its text would be.
    const [doctype] = splitDoctype(latin1(payload.subarray(0, Math.min(payload.length, 1024))));
    return {
      start: part.start,
      end: part.end,
      bytes: concatBytes([
        payload.subarray(0, doctype.length),
        latin1Bytes(head),
        payload.subarray(doctype.length),
        latin1Bytes(tail),
      ]),
    };
  });
  return { bytes: splice(raw, replacements), parts };
}

function concatBytes(chunks) {
  const total = chunks.reduce((n, chunk) => n + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/** True when the message already carries a signature of ours. */
export function alreadySigned(raw) {
  const separator = headerSeparator(raw);
  const block = latin1(raw.subarray(0, separator ? separator.bodyStart : raw.length));
  return /^x-zeknop-signature:/im.test(block);
}
