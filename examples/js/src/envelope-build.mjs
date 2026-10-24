// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zeknod OÜ
// ─────────────────────────────────────────────────────────────────────────────
// Writing the visible envelope — ../../../spec/delivered-envelope.md §3.3, §3.3.1.
//
// The removal of the envelope lives in the vendored canonicalisation
// (../vendor/canonical/envelope.mjs), because the hash rests on it. Writing one
// does not, and is not in that module, so this file assembles the two blocks
// from §3.3 and §3.3.1 and is held to
// ../../../vectors/delivered-envelope-vectors.json (`build`, `build_html`) by
// ../test/conformance.test.mjs.
//
// Both blocks are US-ASCII and are not localised (§3). Nothing in them is
// escaped and nothing needs escaping: the identifier is eight letters or digits
// and the link is a portal host followed by `/` and base64url characters only.
// A caller that would have to write any other character into a block is refused
// here rather than writing a block no verifier will take off again.
// ─────────────────────────────────────────────────────────────────────────────

/** §3.1 / §3.2, the marker lines and the fixed sentences. */
export const POSITIVE_START = '======= ZEKNOP =======';
export const POSITIVE_END = '======= END ZEKNOP =======';
export const POSITIVE_CLOSING =
  'Text outside these markers is not covered by the signature. ZEKNOP never confirms authenticity by text inside a message.';
export const NOT_VERIFIED_START = '------- ZEKNOP NOTICE: SENDER NOT VERIFIED -------';
export const NOT_VERIFIED_END = '------- END ZEKNOP NOTICE -------';
export const NOT_VERIFIED_LINES = [
  'This message passed through a ZEKNOP signing service but could not be signed.',
  'Treat it as ordinary, unverified e-mail. To check any ZEKNOP message, open verify.zeknop.org yourself and paste the message.',
];

/** §3.3.2: one style attribute value, the same on every block. */
export const HTML_STYLE =
  'display:block !important;visibility:visible !important;opacity:1 !important;' +
  'position:static !important;transform:none !important;filter:none !important;' +
  'clip:auto !important;clip-path:none !important;content-visibility:visible !important;' +
  'font-size:13px !important;line-height:1.4 !important;color:#000000 !important;' +
  'background:#ffffff !important;width:auto !important;height:auto !important;' +
  'max-height:none !important;overflow:visible !important;margin:8px 0 !important;' +
  'padding:8px !important;text-indent:0 !important;z-index:auto !important;' +
  'white-space:pre-wrap !important;font-family:monospace !important';

const ENVELOPE_ID_RE = /^[A-Za-z0-9]{8}$/;
const VERIFY_URL_RE = /^[A-Za-z0-9:/._~%+-]+$/;

function checkIdentifiers(envelopeId, verifyUrl) {
  if (!ENVELOPE_ID_RE.test(String(envelopeId))) {
    throw new Error(`the envelope id ${JSON.stringify(envelopeId)} is not eight letters or digits (§3.1)`);
  }
  if (!VERIFY_URL_RE.test(String(verifyUrl))) {
    throw new Error('the verification link carries a character a block may not contain (§3.3.1)');
  }
}

/**
 * §3.3, what goes before and after the sender's text in a plain part.
 *
 * The two pieces are separate because a signer writes them around the sender's
 * BYTES, whose charset and transfer encoding it does not touch, while the
 * vectors ask for the whole block as one string. Both come from here, so there
 * is one definition of these bytes and not two.
 *
 * `eol` is the line ending of the part — CRLF on the wire, LF for a part whose
 * payload demonstrably uses bare LF.
 */
export function positiveAround({ envelopeId, verifyUrl, eol = '\r\n' }) {
  checkIdentifiers(envelopeId, verifyUrl);
  return {
    before:
      POSITIVE_START + eol +
      'Message ID: ' + envelopeId + eol +
      'Verify: ' + verifyUrl + eol + eol,
    after: eol + eol + POSITIVE_END + eol + POSITIVE_CLOSING + eol,
  };
}

/** §3.3, the same for the not-verified envelope. It carries no link. */
export function notVerifiedAround({ eol = '\r\n' }) {
  return {
    before:
      NOT_VERIFIED_START + eol +
      NOT_VERIFIED_LINES[0] + eol +
      NOT_VERIFIED_LINES[1] + eol + eol,
    after: eol + eol + NOT_VERIFIED_END + eol,
  };
}

/** §3.3, the positive envelope of a plain part: the text with the block around it. */
export function buildPositive({ inner, envelopeId, verifyUrl, eol = '\r\n' }) {
  const { before, after } = positiveAround({ envelopeId, verifyUrl, eol });
  return before + inner + after;
}

/** §3.3, the not-verified envelope of a plain part. */
export function buildNotVerified({ inner, eol = '\r\n' }) {
  const { before, after } = notVerifiedAround({ eol });
  return before + inner + after;
}

/** §3.3.1: `<!-- marker -->` EOL `<div style>lines</div>` EOL `<!-- marker -->` EOL. */
function htmlBlock(marker, lines, eol) {
  const comment = `<!-- ${marker} -->`;
  return (
    comment + eol +
    `<div style="${HTML_STYLE}">` + lines.join(eol) + '</div>' + eol +
    comment + eol
  );
}

/**
 * §3.3.1: a leading DOCTYPE declaration with its line break, and the rest.
 *
 * The head block goes AFTER a leading DOCTYPE, so the sender's document keeps
 * the parsing mode it had. The declaration is recognised at the very start of
 * the part, leading white space allowed, the name read case-insensitively, and
 * only when the quotation marks inside it are balanced; anything else counts as
 * the sender's first byte.
 */
export function splitDoctype(document) {
  const m = /^\s*<!DOCTYPE[^>]*>/i.exec(document);
  if (!m || (m[0].split('"').length - 1) % 2 !== 0) return ['', document];
  let end = m[0].length;
  for (const brk of ['\r\n', '\n']) {
    if (document.startsWith(brk, end)) {
      end += brk.length;
      break;
    }
  }
  return [document.slice(0, end), document.slice(end)];
}

/**
 * §3.3.1, an HTML display part: the head block at the start of the part (after
 * a leading DOCTYPE when there is one), the sender's markup untouched between
 * the blocks, the tail block appended after the sender's last byte.
 */
export function positiveHtmlAround({ envelopeId, verifyUrl, eol = '\r\n' }) {
  checkIdentifiers(envelopeId, verifyUrl);
  return {
    head: htmlBlock(POSITIVE_START, [
      POSITIVE_START,
      'Message ID: ' + envelopeId,
      'Verify: ' + verifyUrl,
    ], eol),
    tail: htmlBlock(POSITIVE_END, [POSITIVE_END, POSITIVE_CLOSING], eol),
  };
}

/** §3.3.1, the not-verified blocks of an HTML display part. No link. */
export function notVerifiedHtmlAround({ eol = '\r\n' }) {
  return {
    head: htmlBlock(NOT_VERIFIED_START, [NOT_VERIFIED_START, ...NOT_VERIFIED_LINES], eol),
    tail: htmlBlock(NOT_VERIFIED_END, [NOT_VERIFIED_END], eol),
  };
}

export function buildPositiveHtml({ inner, envelopeId, verifyUrl, eol = '\r\n' }) {
  const [doctype, rest] = splitDoctype(inner);
  const { head, tail } = positiveHtmlAround({ envelopeId, verifyUrl, eol });
  return doctype + head + rest + tail;
}

export function buildNotVerifiedHtml({ inner, eol = '\r\n' }) {
  const [doctype, rest] = splitDoctype(inner);
  const { head, tail } = notVerifiedHtmlAround({ eol });
  return doctype + head + rest + tail;
}

/** The builder a vector of `delivered-envelope-vectors.json` asks for. */
export function buildForVector(array, kind, input) {
  const args = { inner: input.inner, envelopeId: input.envelope_id, verifyUrl: input.verify_url, eol: input.eol };
  if (array === 'build') return kind === 'positive' ? buildPositive(args) : buildNotVerified(args);
  return kind === 'positive' ? buildPositiveHtml(args) : buildNotVerifiedHtml(args);
}
