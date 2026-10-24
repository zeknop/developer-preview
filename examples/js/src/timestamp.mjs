// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zeknod OÜ
// ─────────────────────────────────────────────────────────────────────────────
// The timestamp decision — ../../../spec/canonical-content.md §8.
//
// Two rules and no third. A future timestamp beyond the clock-skew tolerance is
// rejected, in every context. Age is NOT a reason to reject on the way in: a
// signature stays verifiable, and what protects a reader is the fingerprint and
// revocation, not the age of the message. Only an outbound mail transfer agent
// has a maximum age, and it is 24 hours.
//
// The decision is made BEFORE any signature is checked (§8, "Validation
// order"), which is why it is a function of its own and not a branch inside a
// verifier. `now` is a parameter: a reader that took it from the system clock
// could not be measured against
// ../../../vectors/timestamp-vectors.json, whose answers are fixed against the
// moment the file names.
// ─────────────────────────────────────────────────────────────────────────────

/** §8: the tolerance for a timestamp ahead of the reader's clock. */
export const FUTURE_TOLERANCE_MS = 30 * 1000;

/** §8, "Age Windows": the one maximum age there is, and it is outbound only. */
export const OUTBOUND_MAX_AGE_MS = 24 * 60 * 60 * 1000;

/**
 * { decision, reason } for a signature timestamp, as
 * ../../../vectors/timestamp-vectors.json asks it.
 *
 * `context` is `inbound` — every reader of delivered mail — or the outbound mail
 * transfer agent, which is the one context with a maximum age. `now` is the
 * moment to judge against, in milliseconds.
 *
 * A timestamp that cannot be read at all is rejected: a moment that is not a
 * moment cannot be inside a window, and a reader that let it through would be
 * checking a signature it could not date.
 */
export function timestampDecision(timestamp, { context = 'inbound', now } = {}) {
  const at = Date.parse(timestamp);
  if (Number.isNaN(at)) return { decision: 'reject', reason: 'unparseable_timestamp' };
  if (at > now + FUTURE_TOLERANCE_MS) {
    return { decision: 'reject', reason: 'future_skew_exceeded' };
  }
  if (context !== 'inbound' && now - at > OUTBOUND_MAX_AGE_MS) {
    return { decision: 'reject', reason: 'outbound_stale' };
  }
  if (context !== 'inbound') return { decision: 'accept', reason: 'within_outbound_window' };
  if (at > now) return { decision: 'accept', reason: 'within_clock_skew' };
  return { decision: 'accept', reason: 'permanent_verifiability' };
}
