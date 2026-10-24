#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zeknod OÜ
// ─────────────────────────────────────────────────────────────────────────────
// verify — read a delivered message, recompute its two fingerprints, and say
// what can be concluded about it.
//
//   node bin/verify.mjs <file.eml> [--relay URL] [--offline] [--json]
//
// With a relay it asks POST /v1/verify about the RECOMPUTED fingerprint and
// prints the verdict, the identity the relay names and, on a negative answer,
// the reason. With --offline it touches no network at all: it prints the two
// fingerprints it computed, compares the strict one with the one the message
// carries, and says what that alone does and does not establish.
//
// The message itself never leaves this process. What the relay is asked about is
// the identity, the signature, the two fingerprints and the values that name the
// input they were taken over — the timestamp, the version, the algorithm and the
// newest version this build can build — and never the message
// (../../../api/README.md, "Checking a signature"; ../../../spec/signature-input.md §6).
// ─────────────────────────────────────────────────────────────────────────────

import { readFile } from 'node:fs/promises';

import {
  canonicalizeRawMessage,
  finalVerdict,
  localVerdict,
  verifiedOrigin,
  VERDICT,
} from '../vendor/canonical/message.mjs';
import { SIGNATURE_INPUT_VERSION } from '../vendor/canonical/sig-alg.mjs';
import { postVerify, RelayError } from '../src/relay.mjs';

const USAGE = `verify — check a ZEKNOP signature on a delivered message

  node bin/verify.mjs <file.eml> [--relay URL] [--offline] [--json]

  --relay URL   the relay to ask about the signature (example: https://relay.example.org)
  --offline     compute and compare locally; make no request
  --json        print the result as JSON instead of as text

Without --offline a relay is required: a signature cannot be checked without
one. What can be done without a relay is in the --offline output.
`;

/** What each verdict means, in one sentence, for a reader of the output. */
const VERDICT_TEXT = {
  [VERDICT.VERIFIED]: 'the signature holds over the content as delivered',
  [VERDICT.TAMPERED]: 'the content delivered is not the content that was signed',
  [VERDICT.MISMATCH]: 'the message and the link it was opened with name different messages',
  [VERDICT.FUTURE]: 'the signature is dated further ahead than the clock-skew tolerance',
  [VERDICT.UNSIGNED]: 'the message carries no ZEKNOP signature',
  [VERDICT.INVALID]: 'the signature does not hold',
  [VERDICT.NOTICE]: 'the message carries the not-verified block: there is nothing to verify',
  [VERDICT.SENDER_MISMATCH]: 'the signature holds, for an identity that is not the From address',
  [VERDICT.UNSUPPORTED_ALG]: 'the message names an algorithm this build cannot check',
  [VERDICT.UNKNOWN_VERSION]: 'the message announces a version this build has never heard of',
  [VERDICT.UNKNOWN_IDENTITY]: 'the relay has no record of that identity, so nothing was checked',
  [VERDICT.IDENTITY_NOT_ACTIVE]:
    'the signature holds and the identity is not active — the bytes are the bytes that were signed',
  [VERDICT.UNSUPPORTED_VERSION]:
    'the relay refused the question: the signature was made under a version this caller did not say it can build',
};

function parseArguments(argv) {
  const options = { file: null, relay: null, offline: false, json: false };
  for (let i = 0; i < argv.length; i++) {
    const argument = argv[i];
    if (argument === '--relay') options.relay = argv[++i];
    else if (argument === '--offline') options.offline = true;
    else if (argument === '--json') options.json = true;
    else if (argument === '--help' || argument === '-h') options.help = true;
    else if (argument.startsWith('--')) {
      process.stderr.write(`verify: unknown argument ${argument}\n`);
      process.exit(2);
    } else if (options.file === null) options.file = argument;
    else {
      process.stderr.write('verify: more than one file given\n');
      process.exit(2);
    }
  }
  return options;
}

/**
 * The question POST /v1/verify is asked (contract 1.8).
 *
 * `version` is the version the MESSAGE announces, as the registry accepted it,
 * and never this build's newest one: the version is inside the signed bytes, so
 * naming another value makes the relay rebuild a different input and a message
 * signed under an older version comes back invalid. `understands` is the other
 * field, and that one IS this build's own newest: it is how a relay tells a
 * caller written before v1.4 from this one asking about a message whose version
 * field was taken off, and it is what earns a 409 instead of a false verdict.
 */
export function verifyRequest(analysis) {
  return {
    uuid: analysis.zeknop.uuid.trim(),
    signature: analysis.zeknop.signature.trim(),
    message_hash: analysis.hash,
    timestamp: analysis.zeknop.timestamp.trim(),
    version: analysis.signatureVersion,
    alg: analysis.algorithm,
    free_hash: analysis.freeHash,
    understands: SIGNATURE_INPUT_VERSION,
  };
}

function report(analysis, verdict, relayAnswer, options) {
  const z = analysis.zeknop;
  const origin = relayAnswer ? verifiedOrigin(analysis, relayAnswer) : null;
  const result = {
    file: options.file,
    mode: options.offline ? 'offline' : 'relay',
    shape: analysis.shape,
    from: analysis.from,
    subject: analysis.subject,
    announced: {
      version: z.version,
      algorithm: analysis.algorithm,
      uuid: z.uuid,
      timestamp: z.timestamp,
      envelope_id: z.envelopeId,
      strict_hash: z.hash,
    },
    recomputed: {
      strict_hash: analysis.hash,
      free_hash: analysis.freeHash,
    },
    // Null, not false, when the message carries no fingerprint to compare with:
    // "they differ" would be a statement about a message that made none.
    strict_hash_matches_header: z.hash ? analysis.hash === z.hash : null,
    verdict,
    verdict_means: VERDICT_TEXT[verdict] || null,
    identity: origin,
    relay_reason: relayAnswer ? relayAnswer.reason || null : null,
    relay_message: relayAnswer ? relayAnswer.message || null : null,
    // A refusal says why in `detail` and in nothing else
    // (../../../api/README.md, "So read `detail`"). Without this field the one
    // sentence that distinguishes a refusal from a verdict would be dropped.
    relay_detail: relayAnswer ? relayAnswer.detail || null : null,
  };

  if (options.json) return `${JSON.stringify(result, null, 2)}\n`;

  const lines = [];
  lines.push(`file             ${options.file}`);
  lines.push(`shape            ${analysis.shape}`);
  lines.push(`from             ${analysis.from || '(none)'}`);
  lines.push(`subject          ${analysis.subject || '(none)'}`);
  lines.push(`version          ${z.version || '(none announced)'}`);
  lines.push(`algorithm        ${analysis.algorithm || '(none announced)'}`);
  lines.push(`identity (uuid)  ${z.uuid || '(none)'}`);
  lines.push(`signed at        ${z.timestamp || '(none)'}`);
  lines.push(`envelope id      ${z.envelopeId || '(none)'}`);
  lines.push('');
  lines.push(`strict hash  header     ${z.hash || '(none)'}`);
  lines.push(`strict hash  recomputed ${analysis.hash}`);
  const agreement = z.hash ? (analysis.hash === z.hash ? 'same' : 'DIFFERENT') : 'nothing to compare with';
  lines.push(`             agreement  ${agreement}`);
  lines.push(`free hash    recomputed ${analysis.freeHash || '(not computed: no version or algorithm)'}`);
  lines.push('');
  lines.push(`verdict          ${verdict}`);
  if (VERDICT_TEXT[verdict]) lines.push(`                 ${VERDICT_TEXT[verdict]}`);
  if (origin) lines.push(`verified         ${origin.kind} ${origin.value}`);
  if (relayAnswer && relayAnswer.reason) lines.push(`relay reason     ${relayAnswer.reason}`);
  if (relayAnswer && relayAnswer.message) lines.push(`relay message    ${relayAnswer.message}`);
  if (relayAnswer && relayAnswer.detail) lines.push(`relay detail     ${relayAnswer.detail}`);
  if (options.offline) {
    lines.push('');
    lines.push('No signature was checked: --offline asks no relay. A strict hash that');
    lines.push('agrees with the header says the delivered content is the content the');
    lines.push('header names, and nothing about who signed it or whether the signature');
    lines.push('holds. A hash that differs says the content changed, and that alone is');
    lines.push('established without anybody.');
  }
  return `${lines.join('\n')}\n`;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.help || options.file === null) {
    process.stdout.write(USAGE);
    return options.help ? 0 : 2;
  }
  if (!options.offline && !options.relay) {
    process.stderr.write('verify: give --relay URL, or --offline to compute without one\n');
    return 2;
  }

  const analysis = await canonicalizeRawMessage(await readFile(options.file));
  const local = localVerdict(analysis, null);

  if (options.offline) {
    // Offline, the local verdict is the whole answer. A message whose strict
    // hash disagrees with its header is reported as changed — that is this
    // reader's own measurement and it needs nobody's record; everything else
    // that would be green is reported as what it is: not checked.
    const verdict = local.state === null
      ? analysis.hash === analysis.zeknop.hash
        ? 'not-checked'
        : VERDICT.TAMPERED
      : local.state;
    process.stdout.write(report(analysis, verdict, null, options));
    // 0 is for the one thing this mode can establish: the two fingerprints
    // agree. Everything else is 1, the not-verified block included — a message
    // that says of itself that its sender was not verified compared nothing,
    // and it is the same answer here as with a relay.
    return verdict === 'not-checked' ? 0 : 1;
  }

  if (!local.ok) {
    // Nothing local allows the question to be asked at all (§3, §4, §6).
    process.stdout.write(report(analysis, local.state, null, options));
    return 1;
  }

  let answer;
  try {
    answer = await postVerify(options.relay, verifyRequest(analysis));
  } catch (err) {
    if (err instanceof RelayError) {
      process.stderr.write(`verify: the relay said nothing usable — ${err.message}\n`);
      // An outage is not a verdict (../../../api/README.md).
      return 3;
    }
    throw err;
  }

  if (answer.status === 409) {
    // A refusal, not a verdict: the relay declined to answer because this
    // caller did not say it can build the version the signature was made
    // under. Nothing was measured about the message, so this exits 3 with the
    // outages and never 1 — a caller reading the exit code must not read a
    // refusal as "the message is bad" (../../../api/README.md).
    process.stdout.write(report(analysis, VERDICT.UNSUPPORTED_VERSION, answer.body, options));
    return 3;
  }
  if (answer.status !== 200 || !answer.body || typeof answer.body.valid !== 'boolean') {
    process.stderr.write(
      `verify: the relay answered ${answer.status} without a verdict — ` +
        `${JSON.stringify(answer.body)}\n`,
    );
    return 3;
  }

  const verdict = finalVerdict(local, analysis, answer.body);
  process.stdout.write(report(analysis, verdict, answer.body, options));
  return verdict === VERDICT.VERIFIED ? 0 : 1;
}

process.exitCode = await main();
