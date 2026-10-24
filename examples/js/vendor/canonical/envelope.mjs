// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zeknod OÜ
//
// A copy of the ZEKNOP reference implementation of the canonical content
// specification, carried by the JavaScript example so that the example counts
// the same bytes as the service that signed the message. Apart from this header
// and the substitutions recorded with the copy, nothing in this file was changed.

// ─────────────────────────────────────────────────────────────────────────────
// The visible ZEKNOP envelope a signer wraps a delivered plain-text body in
// sits OUTSIDE the hash on both sides: the signer hashes the ORIGINAL text,
// the verifier has to recover it from the delivered text before hashing.
//
// delivered-envelope.md §6.1, byte for byte the removal every other reader of
// this protocol performs: the kind whose start marker
// occurs first — the positive envelope, the legacy positive envelope of
// messages signed before v1.4, or the not-verified envelope — is the outer one;
// its content runs from the first blank line after the start marker to the end
// marker of the same kind. Returns the body unchanged when no envelope is
// present — and when the outer one is the not-verified envelope, which is
// recognised (deliveredEnvelopeKind) but never taken off before hashing.
// delivered-envelope-vectors.json holds every verifier to the same answers.
// ─────────────────────────────────────────────────────────────────────────────

const LEGACY_START_RE = /[═=]{7} ZEKNOP VERIFIED MESSAGE [═=]{7}/;
const LEGACY_END_RE = /[═=]{7} END ZEKNOP VERIFIED [═=]{7,}/;

const KINDS = [
  { kind: 'positive', start: '======= ZEKNOP =======', end: '======= END ZEKNOP =======' },
  { kind: 'legacy-positive', start: LEGACY_START_RE, end: LEGACY_END_RE },
  { kind: 'not-verified', start: '------- ZEKNOP NOTICE: SENDER NOT VERIFIED -------', end: '------- END ZEKNOP NOTICE -------' },
];

function atLineStart(body, index) {
  return index === 0 || body[index - 1] === '\n';
}

/** (0, length) when the marker is the very start of the part, else null. */
function markerAtHead(body, marker) {
  if (typeof marker === 'string') {
    return body.startsWith(marker) ? { index: 0, length: marker.length } : null;
  }
  const m = marker.exec(body);
  return m && m.index === 0 ? { index: 0, length: m[0].length } : null;
}

/**
 * The LAST occurrence of the marker that begins a line, else null.
 *
 * The LAST one, so that content carrying an end marker cannot truncate the
 * envelope; beginning a LINE, so that a quoted or indented end marker is
 * content. The closing lines an envelope writes below its end marker differ
 * per kind (the legacy one carries a token in its URL), so what follows the
 * marker is not pinned here; text appended below the closing lines is outside
 * the markers, which is what the closing sentence says.
 */
function markerAtTail(body, marker, after) {
  if (typeof marker === 'string') {
    let index = body.lastIndexOf(marker);
    while (index >= after) {
      if (atLineStart(body, index)) return { index, length: marker.length };
      index = body.lastIndexOf(marker, index - 1);
      if (index < 0) break;
    }
    return null;
  }
  const re = new RegExp(marker.source, marker.flags.includes('g') ? marker.flags : marker.flags + 'g');
  let found = null;
  let m;
  while ((m = re.exec(body)) !== null) {
    if (m.index >= after && atLineStart(body, m.index)) found = { index: m.index, length: m[0].length };
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return found;
}

/**
 * The markers are read ONLY at the head and the tail of the part, never
 * searched for inside it. An envelope quoted in the content — indented, behind
 * `>`, or at a line start with nothing in front of it — is the sender's text
 * and stays in the hash, so a signed reply that quotes one is green.
 */
function outerEnvelope(body) {
  let outer = null;
  for (const k of KINDS) {
    const start = markerAtHead(body, k.start);
    if (start) { outer = { kind: k.kind, start, end: k.end }; break; }
  }
  if (!outer) return null;
  const end = markerAtTail(body, outer.end, outer.start.index + outer.start.length);
  if (!end || end.index <= outer.start.index) return null;

  const afterStartAt = outer.start.index + outer.start.length;
  const afterStart = body.slice(afterStartAt);
  // Content begins after the identifier or notice lines and the blank line that follows.
  let idx = afterStart.indexOf('\n\n');
  let blankLen = 2;
  if (idx === -1) {
    idx = afterStart.indexOf('\r\n\r\n');
    blankLen = 4;
  }
  if (idx === -1) return null;

  const content = body.slice(afterStartAt + idx + blankLen, end.index);
  // Drop the trailing newline(s) the signer inserts before the END marker.
  return { kind: outer.kind, content: content.replace(/[\r\n]+$/, '') };
}

export function stripZeknopEnvelope(body) {
  if (!body) return body;
  const outer = outerEnvelope(body);
  // A not-verified envelope is recognised but never taken off: the text is
  // hashed as it is, so it can never recompute to a signature (spec §6.1).
  return outer && outer.kind !== 'not-verified' ? outer.content : body;
}

/**
 * Which envelope a delivered body carries outermost: 'positive',
 * 'legacy-positive', 'not-verified', or null when none is complete. A body
 * whose outer envelope is 'not-verified' is never shown as verified (spec §6).
 */
export function deliveredEnvelopeKind(body) {
  if (!body) return null;
  const outer = outerEnvelope(body);
  return outer ? outer.kind : null;
}

// ─── the same envelope in an HTML part (spec §3.3.1, §6.1) ───────────────────
//
// A signed HTML part carries the block twice: once at the head of the part and
// once at its tail, each between two marker comments carrying the same words as
// the plain-text markers. A verifier takes them off ONLY at those two ends and
// never searches for the comments inside the part — a block quoted in a reply or
// an inline forward is the sender's content and stays in the hash, exactly as a
// quoted plain-text marker does.
//
// Byte for byte the same removal on an HTML part, and
// delivered-envelope-vectors.json holds every verifier to the same answers.

const HTML_MARK_POSITIVE_START = '<!-- ======= ZEKNOP ======= -->';
const HTML_MARK_POSITIVE_END = '<!-- ======= END ZEKNOP ======= -->';
const HTML_MARK_NOT_VERIFIED_START = '<!-- ------- ZEKNOP NOTICE: SENDER NOT VERIFIED ------- -->';
const HTML_MARK_NOT_VERIFIED_END = '<!-- ------- END ZEKNOP NOTICE ------- -->';

const HTML_ENVELOPE_KINDS = [
  { kind: 'positive', start: HTML_MARK_POSITIVE_START, end: HTML_MARK_POSITIVE_END },
  { kind: 'not-verified', start: HTML_MARK_NOT_VERIFIED_START, end: HTML_MARK_NOT_VERIFIED_END },
];

// A leading DOCTYPE the head block is written AFTER (§3.3.1): written before it,
// the parser drops the DOCTYPE and the sender's document is parsed in quirks mode.
const HTML_DOCTYPE_RE = /^\s*<!DOCTYPE[^>]*>/i;

/** [the leading DOCTYPE declaration with its line break, the rest] (§3.3.1). */
function splitHtmlDoctype(document) {
  const m = HTML_DOCTYPE_RE.exec(document);
  if (!m || (m[0].split('"').length - 1) % 2 !== 0) return ['', document];
  let end = m[0].length;
  for (const brk of ['\r\n', '\n']) {
    if (document.startsWith(brk, end)) { end += brk.length; break; }
  }
  return [document.slice(0, end), document.slice(end)];
}

/** The length of the line break at `at`, or 0. */
function eolLength(text, at) {
  if (text.startsWith('\r\n', at)) return 2;
  if (text.startsWith('\n', at)) return 1;
  return 0;
}

/**
 * Take the outer HTML envelope off an HTML part (spec §6.1, the HTML rule), as
 * { text, kind }: the sender's markup with the DOCTYPE back in front, and which
 * kind was outermost. A not-verified envelope is recognised and NEVER taken off,
 * so such a part can never recompute to a signature.
 */
export function stripHtmlDeliveredEnvelope(body) {
  const text = String(body == null ? '' : body);
  const [doctype, rest] = splitHtmlDoctype(text);
  const k = HTML_ENVELOPE_KINDS.find((candidate) => rest.startsWith(candidate.start));
  if (!k) return { text, kind: null };
  if (k.kind === 'not-verified') return { text, kind: 'not-verified' };
  const second = rest.indexOf(k.start, k.start.length);
  if (second === -1) return { text, kind: null };
  const headEnd = second + k.start.length + eolLength(rest, second + k.start.length);
  const lastEnd = rest.lastIndexOf(k.end);
  if (lastEnd < headEnd) return { text, kind: null };
  // The tail block must be what ENDS the part: nothing but line breaks after it.
  if (rest.slice(lastEnd + k.end.length).replace(/[\r\n]/g, '') !== '') return { text, kind: null };
  const tailStart = rest.lastIndexOf(k.end, lastEnd - 1);
  if (tailStart < headEnd) return { text, kind: null };
  return { text: doctype + rest.slice(headEnd, tailStart), kind: k.kind };
}

/** Which HTML envelope is outermost in a part, or null (spec §6.1). */
export function htmlDeliveredEnvelopeKind(body) {
  return stripHtmlDeliveredEnvelope(body).kind;
}

/** True when a delivered body carries a complete envelope of any kind. */
export function hasZeknopEnvelope(body) {
  return deliveredEnvelopeKind(body) !== null;
}
