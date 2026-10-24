// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zeknod OÜ
//
// A copy of the ZEKNOP reference implementation of the canonical content
// specification, carried by the JavaScript example so that the example counts
// the same bytes as the service that signed the message. Apart from this header
// and the substitutions recorded with the copy, nothing in this file was changed.

// ─────────────────────────────────────────────────────────────────────────────
// ZEKNOP canonical content — the parts that do not need a hash function.
//
// SINGLE SOURCE OF TRUTH for the canonicalisation contract of spec
// v1.3 (spec/canonical-content.md): §2 body normalization, §3 sender, §4
// recipients, §5 subject, §1.1 shape assembly and the §7 JSON serialisation.
//
// Every reader that imports this module MUST NOT reimplement any of it, in a
// browser and on the Node side alike.
//
// The digest itself lives in ./digest.mjs (WebCrypto, async). Everything here is
// synchronous and pure so the node-side consumer can keep its synchronous API.
// ─────────────────────────────────────────────────────────────────────────────

export const MAX_BODY_HASH = 1024 * 1024; // 1 MB (spec §2 "Body Size Limit")

/** spec §2: BOM strip → CRLF→LF → lone CR→LF → trailing WS per line → trim. */
export function normalizeBody(text) {
  if (!text) return '';
  let t = text;
  if (t.charCodeAt(0) === 0xfeff) t = t.slice(1);
  return t
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .replace(/[ \t]+$/gm, '')
    .trim();
}

/** spec §3: `"foo bar"@example.com` → `foo bar@example.com`. */
export function stripLocalQuotes(addr) {
  const atIdx = addr.lastIndexOf('@');
  if (atIdx <= 0) return addr;
  let local = addr.substring(0, atIdx);
  const domain = addr.substring(atIdx + 1);
  if (local.startsWith('"') && local.endsWith('"') && local.length > 2) local = local.slice(1, -1);
  return local + '@' + domain;
}

/**
 * Drop RFC 5322 comments — `(...)` outside quoted strings — from an address
 * that carries no angle brackets (`user@example.com (Comment)`). Quoted local
 * parts keep their parentheses: `"foo (bar)"@example.com` is one mailbox.
 */
function stripComments(str) {
  let out = '';
  let depth = 0;
  let inQuote = false;
  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    if (c === '"' && (i === 0 || str[i - 1] !== '\\')) {
      inQuote = !inQuote;
      if (!depth) out += c;
      continue;
    }
    if (!inQuote && c === '(') { depth++; continue; }
    if (!inQuote && c === ')') { if (depth) depth--; continue; }
    if (!depth) out += c;
  }
  return out;
}

/** spec §3/§4: one mailbox → bare lowercase addr-spec, local-part unquoted. */
export function extractBareAddress(addr) {
  const match = addr.match(/<([^>]*)>/);
  if (match) return stripLocalQuotes(match[1].trim().toLowerCase());
  return stripLocalQuotes(stripComments(addr).trim().toLowerCase());
}

/** Split an address list on commas that are outside quotes and angle brackets. */
export function rfc5322SplitAddressList(str) {
  const parts = [];
  let depth = 0;
  let inQuote = false;
  let start = 0;
  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    if (c === '"' && (i === 0 || str[i - 1] !== '\\')) inQuote = !inQuote;
    else if (!inQuote && c === '<') depth++;
    else if (!inQuote && c === '>') depth--;
    else if (!inQuote && depth === 0 && c === ',') {
      parts.push(str.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(str.slice(start));
  return parts;
}

/**
 * spec §4: every To header value first, then every Cc value; each address bare
 * and lowercase, original order, joined with ", ". (ALL header instances
 * contribute: every other reader of this protocol includes them too, so reading
 * one instance per name would hash a different message.)
 */
export function parseRecipients(addressList) {
  return addressList
    .flatMap((h) => rfc5322SplitAddressList(h))
    .map((a) => extractBareAddress(a))
    .filter((a) => a)
    .join(', ');
}

/**
 * spec §3: the FIRST mailbox of a From header value wins, however the reader's own
 * address parser would take it. A multi-mailbox From (`a@x.com, b@y.com`)
 * canonicalises to `a@x.com`; that case is the vector
 * `from-002-multi-mailbox-from` of vectors.json.
 */
export function parseFirstMailbox(headerValue) {
  const first = rfc5322SplitAddressList(headerValue || '')[0] || '';
  return extractBareAddress(first);
}

// ── BEGIN SHARED cutCodePoints (spec §2 "Body Size Limit") ───────────────────
// The first `max` Unicode CODE POINTS of `text`, which is what §2 says, and not
// the first `max` UTF-16 code units, which is what `substring` gives. A body over
// the limit with a character outside the BMP in front of the cut (an emoji, a rare
// ideograph, a musical sign) ended here in HALF of a surrogate pair — encoded as
// U+FFFD — and in a whole code point in the Python readers, so the two sides
// hashed two different bodies.
// Allocates nothing and walks no further than it must: a body under the limit pays
// one comparison, and a body over it is scanned for its first surrogate by the
// engine itself — the code units before that one are code points, so the walk
// starts there. `Array.from(text).slice(0, max).join('')` is the same answer and,
// measured over 25 MB, 60 times the cost of the walk.
// The text between these markers is ONE function, carried byte for byte by every
// reader of this protocol that is written in JavaScript: a cut that differs by a
// single code point is a body that hashes differently.
function cutCodePoints(text, max) {
  if (text.length <= max) return text;        // code points are never more than code units
  const head = text.slice(0, max);
  const first = head.search(/[\ud800-\udfff]/);
  if (first === -1) return head;              // no surrogate: these units ARE code points
  let i = first;                              // and so are the ones before the first
  let n = first;
  while (i < text.length && n < max) {
    const c = text.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < text.length) {
      const d = text.charCodeAt(i + 1);
      i += d >= 0xdc00 && d <= 0xdfff ? 2 : 1; // only a valid pair is ONE code point
    } else {
      i += 1;
    }
    n += 1;
  }
  return text.slice(0, i);
}
// ── END SHARED cutCodePoints ─────────────────────────────────────────────────
export { cutCodePoints };

/** spec §9.3 text-leaf input: §2-normalized, cut to the §2 limit. Hashed by ./digest.mjs. */
export function canonicalTextPartInput(text) {
  return cutCodePoints(normalizeBody(text || ''), MAX_BODY_HASH);
}

/**
 * spec §1.1 — exactly two shapes, chosen by the CALLER from message structure:
 *   Shape A (pass `body`):  { from, to, subject, body, timestamp }
 *   Shape B (pass `parts`): { from, to, subject, timestamp, parts }  (§9 manifest,
 *                           used VERBATIM — document order, never sorted)
 *
 * `from` may already be canonical (the raw-source path resolves the first
 * mailbox per §3 before calling); it is passed through extractBareAddress
 * either way, which is idempotent on a bare address.
 */
export function buildCanonicalContent(
  { from, to, cc, subject, body, parts, canonicalFrom, canonicalTo },
  timestamp,
) {
  const head = {
    // canonicalFrom/canonicalTo: already normalized by the caller (the
    // raw-source path resolves §3 first-mailbox and the §4 To+Cc join over the
    // real header instances). Re-parsing a joined list would split a quoted
    // local part that contains a comma, so it is passed through verbatim.
    from: canonicalFrom !== undefined ? canonicalFrom : extractBareAddress(from || ''),
    to: canonicalTo !== undefined ? canonicalTo : parseRecipients([...(to || []), ...(cc || [])]),
    subject: (subject || '').trim(),
  };
  if (parts) {
    return { ...head, timestamp, parts };
  }
  return { ...head, body: canonicalTextPartInput(body), timestamp };
}

/** spec §7: JSON with no spaces after separators, UTF-8, no trailing newline. */
export function canonicalJson(canonicalObject) {
  return JSON.stringify(canonicalObject);
}
