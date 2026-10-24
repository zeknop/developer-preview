// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zeknod OÜ
//
// A copy of the ZEKNOP reference implementation of the canonical content
// specification, carried by the JavaScript example so that the example counts
// the same bytes as the service that signed the message. Apart from this header
// and the substitutions recorded with the copy, nothing in this file was changed.

// ─────────────────────────────────────────────────────────────────────────────
// From a raw RFC 5322 message to a canonical object, its hash, and the verdict a
// reader is allowed to show.
//
// The same canonicalisation every other reader of this protocol applies, run over
// the message SOURCE the person supplies. The relay is asked about the identity,
// the signature, the two fingerprints and the values that name the input they were
// taken over, and never about the message itself (signature-input.md §6).
// ─────────────────────────────────────────────────────────────────────────────

import { buildCanonicalContent, canonicalJson, parseFirstMailbox, parseRecipients } from './base.mjs';
import { sha256Base64, utf8Bytes } from './digest.mjs';
import { decodeEncodedWords, headerValue, headerValues } from './headers.mjs';
import { extractPartsManifest, freeFormSource, isShapeA, parsePart, shapeABody } from './mime.mjs';
import { deliveredEnvelopeKind, stripZeknopEnvelope, stripHtmlDeliveredEnvelope } from './envelope.mjs';
import { freeFormText } from './free-form.mjs';
import { UNSUPPORTED, acceptedVersion, headerAlgorithm, versionState } from './sig-alg.mjs';

/** spec §8: a signature dated further ahead than the clock-skew tolerance. */
export const FUTURE_TOLERANCE_MS = 30 * 1000;

export const VERDICT = {
  VERIFIED: 'verified',
  TAMPERED: 'tampered',
  MISMATCH: 'mismatch',
  FUTURE: 'future',
  UNSIGNED: 'unsigned',
  INVALID: 'invalid',
  // spec/delivered-envelope.md §6: the displayed text carries the not-verified
  // envelope — a signer could not sign the message; there is nothing to verify.
  NOTICE: 'notice',
  // The signature is valid, but for a mailbox or domain that is not the From address.
  SENDER_MISMATCH: 'sender-mismatch',
  // spec/signature-input.md §3: the message names an algorithm this build cannot check — one
  // the registry reserves for later, or one it does not know. Never green, and never a crash.
  UNSUPPORTED_ALG: 'unsupported-algorithm',
  // spec/signature-input.md §4: the message announces a version this build has never
  // heard of — it comes from a signer NEWER than this page. Nothing here can read it, which is
  // a fact about this reader and not about the message: it is never reported as content that
  // somebody may have changed. Decided from the headers alone, before the fingerprints are
  // compared.
  UNKNOWN_VERSION: 'unknown-version',
  // spec/signature-input.md §6a (contract 1.8): the relay has
  // no record of the identity the message names, so nothing was checked against anything.
  // NOT the red card. Until 1.8 this arrived as the same `valid: false` a signature that
  // does not hold arrives as, and this page showed "Verification Failed" for it — a sound
  // message reported as changed, for no reason but that the relay had never been told who
  // the sender is. A local hash that does not match still wins: that is this page's own
  // measurement and it needs nobody's record.
  UNKNOWN_IDENTITY: 'unknown-identity',
  // spec/signature-input.md §6a.1 (contract 1.8): the relay HAS the
  // identity and its record is not active. Not the red card either, and for the plainest of
  // reasons: these are the bytes that were signed, so nothing about the message was changed.
  // What a reader may say about the SENDER is another matter; what it may not say is "this
  // message was changed".
  IDENTITY_NOT_ACTIVE: 'identity-not-active',
  // spec/signature-input.md §4a, §6a.1: the relay refused the question with 409,
  // because the signature was made under a version this page did not say it can build. One
  // sentence for a reader, the same one UNKNOWN_VERSION carries — the fact is the same to the
  // person: nobody in the chain could read it, and the message is not at fault. Which of the
  // two it is belongs in the Details, and it used to land on the grey error screen with the
  // relay's `detail` text, which reads like an outage.
  UNSUPPORTED_VERSION: 'unsupported-version',
};

/** The relay's word for "I have no record of that identity" (spec §6a). */
export const UNKNOWN_IDENTITY_REASON = 'unknown-identity';
/** ... and for "I have the identity, and its record is not active" (spec §6a, contract 1.8). */
export const IDENTITY_NOT_ACTIVE_REASON = 'identity-not-active';

/**
 * The signature material the signer wrote onto the message.
 *
 * Result-claim headers (X-ZEKNOP-Verified / -Status) are deliberately NOT read:
 * they are sender-forgeable and say nothing this module has not recomputed
 * itself; no verifier of this protocol reads them.
 */
export function extractZeknopHeaders(headers) {
  return {
    version: headerValue(headers, 'X-ZEKNOP-Version'),
    signature: headerValue(headers, 'X-ZEKNOP-Signature'),
    hash: headerValue(headers, 'X-ZEKNOP-Hash'),
    uuid: headerValue(headers, 'X-ZEKNOP-UUID'),
    timestamp: headerValue(headers, 'X-ZEKNOP-Timestamp'),
    level: headerValue(headers, 'X-ZEKNOP-Level'),
    envelopeId: headerValue(headers, 'X-ZEKNOP-Envelope-ID'),
    verify: headerValue(headers, 'X-ZEKNOP-Verify'),
    // Every instance, not the first: two of them name no one algorithm, and a message that
    // names no one algorithm cannot be verified (spec/signature-input.md §1).
    sigAlgValues: headerValues(headers, 'X-ZEKNOP-Sig-Alg'),
  };
}

/** Accepts a string (pasted source) or bytes (an uploaded .eml). */
function toBytes(source) {
  if (typeof source === 'string') return utf8Bytes(source);
  if (source instanceof Uint8Array) return source;
  return new Uint8Array(source);
}

/**
 * Recompute the canonical content object and its hash from a raw message.
 *
 * The SHAPE comes from the message STRUCTURE only (§1.1), never from a header,
 * so it cannot be downgraded: a single non-multipart text/plain part is Shape A;
 * anything else is Shape B with the §9 manifest.
 */
export async function canonicalizeRawMessage(source) {
  const raw = toBytes(source);
  const root = parsePart(raw);
  const headers = root.headers;

  const fromHeader = headerValue(headers, 'From') || '';
  const from = parseFirstMailbox(fromHeader);
  const to = parseRecipients([...headerValues(headers, 'To'), ...headerValues(headers, 'Cc')]);
  const subject = decodeEncodedWords(headerValue(headers, 'Subject') || '').trim();
  const zeknop = extractZeknopHeaders(headers);
  const timestamp = zeknop.timestamp || '';

  const shape = isShapeA(root) ? 'A' : 'B';
  // The outer envelope of every displayed text — the texts the envelope is taken
  // off before hashing (the Shape A body, the text/plain leaves of the manifest).
  const envelopeKinds = [];
  const takeOff = (text) => {
    envelopeKinds.push(deliveredEnvelopeKind(text));
    return stripZeknopEnvelope(text);
  };
  // The same for an HTML leaf (spec/delivered-envelope.md §6.1): the blocks come off at the
  // two ends of the part, and a part whose outer block is the not-verified one is recorded
  // exactly as a plain part is — it is never taken off and the message is never green.
  const takeOffHtml = (text) => {
    const stripped = stripHtmlDeliveredEnvelope(text);
    envelopeKinds.push(stripped.kind);
    return stripped.text;
  };
  let canonical;
  if (shape === 'A') {
    // CANON-01: the delivered body carries the visible ZEKNOP envelope; the
    // signer hashed the body WITHOUT it.
    const body = takeOff(shapeABody(root));
    canonical = buildCanonicalContent({ canonicalFrom: from, canonicalTo: to, subject, body }, timestamp);
  } else {
    const parts = await extractPartsManifest(root, takeOff, undefined, takeOffHtml);
    canonical = buildCanonicalContent({ canonicalFrom: from, canonicalTo: to, subject, parts }, timestamp);
  }
  const json = canonicalJson(canonical);
  const hash = await sha256Base64(utf8Bytes(json));
  // What the message says made its signature, and — for a v1.4 message — the second hash
  // that is under it (spec/signature-input.md §2, canonical-content.md §2b). Both are
  // recomputed here, in the browser, for the same reason as the strict hash: the relay is
  // asked about what THIS message says, never about what a link claims it says.
  const { algorithm, problem } = headerAlgorithm(zeknop.version, zeknop.sigAlgValues);
  let freeHash = null;
  if (algorithm && !problem) {
    const source = await freeFormSource(root, stripZeknopEnvelope,
                                        (text) => stripHtmlDeliveredEnvelope(text).text);
    freeHash = await sha256Base64(utf8Bytes(freeFormText(source.text, source.isHtml)));
  }
  // spec §6: a displayed text whose outer envelope is the not-verified envelope.
  const notVerifiedEnvelope = envelopeKinds.includes('not-verified');
  return { shape, canonical, canonicalJson: json, hash, from, to, subject, timestamp, zeknop,
    headers, notVerifiedEnvelope, algorithm, algorithmProblem: problem || null, freeHash,
    // The version the MESSAGE announces, as the registry accepted it — never this build's
    // own newest one. The version is inside the signed bytes, so naming a different value
    // makes the relay rebuild a different input and a message signed under an older version
    // comes back invalid (spec/signature-input.md §2, §3).
    signatureVersion: algorithm ? acceptedVersion(zeknop.version) : null };
}

/**
 * What a verifier may conclude BEFORE it asks the relay about the signature.
 *
 * `token` is what the verification link carried; where there is no link (the
 * message was supplied on its own) it is null and only the message's own headers
 * are used. A v2 token carries no signature — the link then pins the identity and
 * the fingerprint, and
 * the signature is read from the message, where alone it means anything.
 *
 * Returns { state, ok } — ok:true means "nothing local disqualifies it; ask the
 * relay about the RECOMPUTED hash". Every other state is final and not green.
 */
export function localVerdict(analysis, token, now = Date.now()) {
  const z = analysis.zeknop;
  // spec §6: never green, whatever signing headers the message carries — decided
  // before the headers, the link or the relay are looked at.
  if (analysis.notVerifiedEnvelope) {
    return { state: VERDICT.NOTICE, ok: false };
  }
  if (!z.signature || !z.hash || !z.uuid || !z.timestamp) {
    return { state: VERDICT.UNSIGNED, ok: false };
  }
  // §4: a version this build has never heard of is read by NOBODY here — not over the
  // new input, which this build cannot construct for it, and not over the old one either.
  // Decided before the fingerprints are compared, so the verdict cannot be about the content.
  if (versionState(z.version) === 'unknown') {
    return { state: VERDICT.UNKNOWN_VERSION, ok: false };
  }
  // §3: an algorithm nothing here can check, or a message that names none or names two.
  // Decided before the link, the timestamp or the relay are looked at; never green.
  if (analysis.algorithmProblem === UNSUPPORTED) {
    return { state: VERDICT.UNSUPPORTED_ALG, ok: false };
  }
  if (analysis.algorithmProblem) {
    return { state: VERDICT.INVALID, ok: false };
  }
  // The link and the message must name the same message. A v2 token has no
  // signature to compare — the fingerprint and the identity are what say which
  // message the link was made for, and the signature is checked against the
  // RECOMPUTED fingerprint by the relay a moment later either way.
  if (token && (token.messageHash !== z.hash || token.uuid !== z.uuid)) {
    return { state: VERDICT.MISMATCH, ok: false };
  }
  if (token && token.signature && token.signature !== z.signature) {
    return { state: VERDICT.MISMATCH, ok: false };
  }
  const signedAt = Date.parse(z.timestamp);
  if (Number.isNaN(signedAt)) {
    // A timestamp that cannot be read cannot be judged — fail closed (§8:
    // timestamp validation happens BEFORE cryptographic verification).
    return { state: VERDICT.INVALID, ok: false };
  }
  if (signedAt > now + FUTURE_TOLERANCE_MS) {
    return { state: VERDICT.FUTURE, ok: false };
  }
  if (analysis.hash !== z.hash) {
    // The content that was delivered is not the content that was signed.
    return { state: VERDICT.TAMPERED, ok: true };
  }
  return { state: null, ok: true };
}

/**
 * The final verdict, once the relay has answered about the RECOMPUTED hash.
 * GREEN requires BOTH: the relay says the signature is valid over the hash we
 * recomputed from this message, AND that hash is the one the message carries.
 */
export function finalVerdict(local, analysis, relayResponse) {
  if (local.state === VERDICT.NOTICE || analysis.notVerifiedEnvelope) return VERDICT.NOTICE;
  if (local.state === VERDICT.UNKNOWN_VERSION) return VERDICT.UNKNOWN_VERSION;
  if (local.state === VERDICT.UNSUPPORTED_ALG) return VERDICT.UNSUPPORTED_ALG;
  const hashMatches = analysis.hash === analysis.zeknop.hash;
  if (!relayResponse || !relayResponse.valid) {
    if (local.state === VERDICT.TAMPERED) return VERDICT.TAMPERED;
    // §6a: an identity the relay does not know is not a verdict about the message. A relay
    // older than 1.8 sends no `reason` at all, and such an answer is read as it always was.
    if (relayResponse && relayResponse.reason === UNKNOWN_IDENTITY_REASON) {
      return VERDICT.UNKNOWN_IDENTITY;
    }
    // §6a.1: the relay has the identity and its record is not active. The bytes are the bytes
    // that were signed, so this is not the red card.
    if (relayResponse && relayResponse.reason === IDENTITY_NOT_ACTIVE_REASON) {
      return VERDICT.IDENTITY_NOT_ACTIVE;
    }
    return VERDICT.INVALID;
  }
  if (!hashMatches) return VERDICT.TAMPERED;
  // Green says what was verified (spec §8) — so there is no green without a
  // mailbox or a domain the relay names, and none for one that is not the From.
  if (!relayResponse.email && !relayResponse.domain) return VERDICT.INVALID;
  if (!verifiedOrigin(analysis, relayResponse)) return VERDICT.SENDER_MISMATCH;
  return VERDICT.VERIFIED;
}

/**
 * What a green verdict says was verified (spec/delivered-envelope.md §8): the
 * mailbox the message was sent from — when the identity is a mailbox — or the
 * domain, and that the content is unchanged. Null when the identity the relay
 * names is not the message's From address — the sender check every verifier of
 * this protocol makes. Never the sender's authority or the legitimacy of the
 * content.
 */
export function verifiedOrigin(analysis, relayResponse) {
  const from = (analysis.from || '').toLowerCase();
  const email = (relayResponse && relayResponse.email || '').toLowerCase();
  const domain = (relayResponse && relayResponse.domain || '').toLowerCase();
  if (email) return from === email ? { kind: 'mailbox', value: email } : null;
  if (domain) {
    const at = from.indexOf('@');
    return at !== -1 && from.slice(at + 1) === domain ? { kind: 'domain', value: domain } : null;
  }
  return null;
}
