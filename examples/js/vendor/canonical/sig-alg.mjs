// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zeknod OÜ
//
// A copy of the ZEKNOP reference implementation of the canonical content
// specification, carried by the JavaScript example so that the example counts
// the same bytes as the service that signed the message. Apart from this header
// and the substitutions recorded with the copy, nothing in this file was changed.

// The algorithm a message says its signature was made with (signature-input.md §1, §3).
//
// The registry is normative: §3 is the list, and every name a sender can write falls
// into one of its three states.
//
// A verifier reads the value off a header, so nothing here throws on anything: a name it cannot
// check is a verdict, not an exception.

export const VERSION_HEADER = 'X-ZEKNOP-Version';
export const ALGORITHM_HEADER = 'X-ZEKNOP-Sig-Alg';

// Every version of the signature input this build can BUILD, oldest first (spec §4). A message
// announcing one of them is read over the length-prefixed input of §2 with ITS OWN version
// inside, so mail signed under an older one goes on verifying exactly as it was signed. The
// last entry is what a signer of this build writes; anything outside this list, and outside
// the legacy versions, is a version this build has never heard of.
export const INPUT_VERSIONS = ['1.4', '1.5'];

// What a SIGNER of this build writes into X-ZEKNOP-Version: the newest version it can
// build. Anything outside INPUT_VERSIONS — including no version at all — is not read
// over §2.
export const SIGNATURE_INPUT_VERSION = '1.5';

// The versions from before the algorithm identifier, which this build still reads the old way
// (spec/signature-input.md §4). A version that is neither this one nor one of these comes from a
// signer NEWER than this reader: §4 forbids falling back to the old input for it — naming a
// version that does not exist would otherwise be a way of asking for the weaker check — so there
// is nothing to check and the reader says so about ITSELF.
export const LEGACY_VERSIONS = ['1.0'];
export const UNKNOWN_VERSION = 'unknown version';

export const SIGNED_ALGORITHMS = ['ed25519'];
export const RESERVED_ALGORITHMS = ['ml-dsa-44', 'ml-dsa-65', 'slh-dsa-sha2-128s', 'ed25519+ml-dsa-65'];
export const LEGACY_ALGORITHM = 'ed25519';

// Why a v1.4 message cannot be verified, in the words the verifier reports.
export const MISSING = 'the message announces a signature version and names no algorithm';
export const DUPLICATE = 'the message names more than one algorithm';
export const UNSUPPORTED = 'unsupported algorithm';

/**
 * One of 'current', 'legacy', 'unknown' for the value of X-ZEKNOP-Version. Never throws: the
 * value came off a header a sender can write. Trimmed here for the same reason headerAlgorithm
 * trims it — the readers get it from different parsers, and a message must not be read as one
 * version by one of them and as another by the next.
 */
export function versionState(version) {
  const text = String(version == null ? '' : version).trim();
  if (INPUT_VERSIONS.includes(text)) return 'current';
  if (text === '' || LEGACY_VERSIONS.includes(text)) return 'legacy';
  return 'unknown';
}

/**
 * The version a VERIFIER names to the relay: the one the MESSAGE announces, trimmed, when
 * this build can build its input — and null otherwise (spec §2, §4).
 *
 * Never this build's own newest version. The version is INSIDE the signed bytes, so naming
 * any other value makes the relay rebuild a different input and the signature cannot match:
 * a message signed under an older version would come back invalid, about a message nobody
 * touched. What the CALLER can build is a different field entirely (`understands`, §4a) and
 * that one IS a constant of this build.
 */
export function acceptedVersion(version) {
  const text = String(version == null ? '' : version).trim();
  return INPUT_VERSIONS.includes(text) ? text : null;
}

/** One of 'signed', 'reserved', 'unknown'. Never throws. */
export function algorithmState(name) {
  if (SIGNED_ALGORITHMS.includes(name)) return 'signed';
  if (RESERVED_ALGORITHMS.includes(name)) return 'reserved';
  return 'unknown';
}

/**
 * { algorithm, problem } for a message whose version header is `version` and whose
 * X-ZEKNOP-Sig-Alg instances are `values`.
 *
 * A version outside INPUT_VERSIONS, or none: { algorithm: null, problem: null } — the old
 * input and ed25519 (§4). A version in it: exactly one instance, naming an algorithm this build can check,
 * or a problem. BOTH values are the field body with the whitespace around it removed and are
 * then compared byte for byte and with regard to case: 'Ed25519' is not 'ed25519'. The version
 * is trimmed HERE and not at the call sites, because readers get it from different
 * header parsers — one keeps a trailing space, another keeps the line feed — and a
 * message must not be read as a current version by one of them and as an older one
 * by another.
 */
export function headerAlgorithm(version, values) {
  if (!INPUT_VERSIONS.includes(String(version == null ? '' : version).trim())) {
    return { algorithm: null, problem: null };
  }
  const names = (values || []).map((v) => String(v).trim());
  if (names.length === 0) return { algorithm: null, problem: MISSING };
  if (names.length > 1) return { algorithm: null, problem: DUPLICATE };
  const name = names[0];
  if (algorithmState(name) !== 'signed') return { algorithm: name, problem: UNSUPPORTED };
  return { algorithm: name, problem: null };
}
