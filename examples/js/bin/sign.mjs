#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zeknod OÜ
// ─────────────────────────────────────────────────────────────────────────────
// sign — have a relay sign a composed message, and write the delivered form.
//
//   node bin/sign.mjs <file.eml> --uuid U --api-key K --relay URL --portal URL
//                     [--out signed.eml] [--no-idempotency-key]
//
// The relay and the portal are both given and neither has a default. The portal
// is written into the delivered message — the link line of the visible envelope
// is `<portal>/<token>`, and `<portal>` is the portal of the deployment the
// message was signed on (../../../spec/delivered-envelope.md §3.4). A default
// would put a documentation address into real mail, where a link nobody serves
// is worse than no example at all.
//
// The order is the one the specification requires and not a convenience:
//
//   1. GET /v1/capabilities, and take the newest version BOTH this build and
//      the relay can build. A relay that does not answer 200 naming it has not
//      said yes, and nothing is written: a message announcing a version its
//      signature was not made over is invalid to every verifier for ever, about
//      a message nobody touched (../../../spec/signature-input.md §6).
//   2. Write the three fields that are INPUTS to the fingerprint — the version,
//      the algorithm and the timestamp — and compute the two fingerprints over
//      the message with them in it.
//   3. POST /v1/sign. The relay builds the signed bytes itself from the version,
//      the algorithm and the two hashes; it is never handed bytes to sign.
//   4. Write the signature, the identity, the fingerprint and the envelope id,
//      and put the visible envelope around the sender's text — which can only
//      happen now, because the link in it carries the fingerprint and the
//      envelope id the relay has just answered with. The whole block sits
//      outside the fingerprint (../../../spec/delivered-envelope.md §6.1).
//
// The example addresses used here are example.org and example.com. The API key
// is taken from --api-key, goes into the X-API-Key header of POST /v1/sign, and
// is written nowhere else: not into the message, not onto a stream.
// ─────────────────────────────────────────────────────────────────────────────

import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';

import { canonicalizeRawMessage } from '../vendor/canonical/message.mjs';
import { INPUT_VERSIONS, SIGNED_ALGORITHMS } from '../vendor/canonical/sig-alg.mjs';
import { getCapabilities, postSign, RelayError } from '../src/relay.mjs';
import { addHeaders, alreadySigned, Unsignable, writeEnvelopes } from '../src/sign-message.mjs';

const USAGE = `sign — have a relay sign a message and write the delivered form

  node bin/sign.mjs <file.eml> --uuid U --api-key K --relay URL --portal URL
                    [--out signed.eml] [--no-idempotency-key] [--json]

  Required, and with no default:

  --uuid U        the identity to sign as
  --api-key K     its API key (POST /v1/sign needs it; nothing else here does)
  --relay URL     the relay that signs (example: https://relay.example.org)
  --portal URL    the verification portal of the deployment this message is
                  signed on, which the visible envelope's link line names
                  (delivered-envelope.md §3.4). It goes into the delivered
                  message, so there is no default: a documentation address
                  would be a link that leads nowhere for the reader of real
                  mail (example: https://verify.example.org/v1)

  Optional:

  --out PATH      where to write the signed message; "-" writes to standard
                  output. Default: the input path with .signed.eml
  --no-idempotency-key   send no Idempotency-Key header
  --json          print the result as JSON instead of as text
`;

function parseArguments(argv) {
  const options = {
    file: null,
    uuid: null,
    apiKey: null,
    relay: null,
    portal: null,
    out: null,
    idempotency: true,
    json: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const argument = argv[i];
    if (argument === '--uuid') options.uuid = argv[++i];
    else if (argument === '--api-key') options.apiKey = argv[++i];
    else if (argument === '--relay') options.relay = argv[++i];
    else if (argument === '--portal') options.portal = argv[++i];
    else if (argument === '--out') options.out = argv[++i];
    else if (argument === '--no-idempotency-key') options.idempotency = false;
    else if (argument === '--json') options.json = true;
    else if (argument === '--help' || argument === '-h') options.help = true;
    else if (argument.startsWith('--')) {
      process.stderr.write(`sign: unknown argument ${argument}\n`);
      process.exit(2);
    } else if (options.file === null) options.file = argument;
    else {
      process.stderr.write('sign: more than one file given\n');
      process.exit(2);
    }
  }
  return options;
}

/**
 * The newest version both this build and the relay can build, or null.
 *
 * `signs` is the relay's list, oldest first; `INPUT_VERSIONS` is this build's.
 * The intersection is taken from the newest end, because that is the version a
 * signer wants, and the whole point of asking is that the answer may be shorter
 * than this build's own list.
 */
export function chooseVersion(signs) {
  const theirs = new Set(Array.isArray(signs) ? signs : []);
  for (let i = INPUT_VERSIONS.length - 1; i >= 0; i--) {
    if (theirs.has(INPUT_VERSIONS[i])) return INPUT_VERSIONS[i];
  }
  return null;
}

/** §3.1: base64url, unpadded, of the link's token — which carries no signature. */
export function verifyToken(uuid, contentHash) {
  return Buffer.from(JSON.stringify({ v: 2, uuid, hash: contentHash })).toString('base64url');
}

/**
 * The name of THIS request: 64 lowercase hex characters over what the request
 * asks for. A repeat under the same name inside the relay's idempotency window
 * is answered with the same signature and the same envelope id, so a retry after
 * a lost answer cannot sign one message twice.
 */
export function idempotencyKey({ uuid, version, alg, contentHash, freeHash }) {
  return createHash('sha256')
    .update([uuid, version, alg, contentHash, freeHash].join('\u0000'), 'utf8')
    .digest('hex');
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.help || options.file === null) {
    process.stdout.write(USAGE);
    return options.help ? 0 : 2;
  }
  // None of the four has a default. The portal is the one worth a sentence: it
  // is written into the delivered message, so a default would mean this example
  // putting a documentation address in front of the person who receives the mail
  // (delivered-envelope.md §3.4).
  const required = [
    ['--uuid', options.uuid, 'the identity to sign as'],
    ['--api-key', options.apiKey, "that identity's own key"],
    ['--relay', options.relay, 'the relay that signs, e.g. https://relay.example.org'],
    [
      '--portal',
      options.portal,
      'the verification portal of the deployment this message is signed on, which the ' +
        "envelope's link line names (delivered-envelope.md §3.4), " +
        'e.g. https://verify.example.org/v1',
    ],
  ];
  for (const [name, value, what] of required) {
    if (!value) {
      process.stderr.write(`sign: ${name} is required and has no default — ${what}\n`);
      return 2;
    }
  }

  const raw = new Uint8Array(await readFile(options.file));
  if (alreadySigned(raw)) {
    process.stderr.write(
      'sign: the message already carries X-ZEKNOP-Signature. Signing a signed message is ' +
        'a signer concern (delivered-envelope.md §6.2) and this example does not do it.\n',
    );
    return 2;
  }

  // 1. What can this relay sign?
  let capabilities;
  try {
    capabilities = await getCapabilities(options.relay);
  } catch (err) {
    if (err instanceof RelayError) {
      process.stderr.write(`sign: GET /v1/capabilities — ${err.message}\n`);
      return 3;
    }
    throw err;
  }
  if (capabilities.status !== 200) {
    process.stderr.write(
      `sign: GET /v1/capabilities answered ${capabilities.status}. That is not a yes, so ` +
        'nothing is written: a relay that cannot say which version it signs may sign an ' +
        'older input than the message would announce.\n',
    );
    return 3;
  }
  const version = chooseVersion(capabilities.body && capabilities.body.signs);
  if (version === null) {
    process.stderr.write(
      `sign: this relay signs ${JSON.stringify((capabilities.body || {}).signs)} and this ` +
        `example can build ${JSON.stringify(INPUT_VERSIONS)}; there is no version in common.\n`,
    );
    return 3;
  }
  const alg = SIGNED_ALGORITHMS[0];

  // 2. The fields that are inputs to the fingerprint go in BEFORE it is taken.
  const timestamp = new Date().toISOString();
  const prepared = addHeaders(raw, [
    ['X-ZEKNOP-Version', version],
    ['X-ZEKNOP-Sig-Alg', alg],
    ['X-ZEKNOP-Timestamp', timestamp],
  ]);
  const analysis = await canonicalizeRawMessage(prepared);
  if (!analysis.from) {
    process.stderr.write('sign: the message has no From address to sign for\n');
    return 2;
  }
  if (analysis.freeHash === null) {
    process.stderr.write(
      `sign: the free text form could not be computed for version ${version} ` +
        `(${analysis.algorithmProblem || 'no algorithm'})\n`,
    );
    return 2;
  }

  // 3. Ask the relay to sign. It builds the signed bytes from these fields.
  const payload = {
    uuid: options.uuid,
    content_hash: analysis.hash,
    free_hash: analysis.freeHash,
    timestamp,
    from_address: analysis.from,
    version,
    alg,
  };
  let signed;
  try {
    signed = await postSign(options.relay, options.apiKey, payload, {
      idempotencyKey: options.idempotency
        ? idempotencyKey({
            uuid: options.uuid,
            version,
            alg,
            contentHash: analysis.hash,
            freeHash: analysis.freeHash,
          })
        : null,
    });
  } catch (err) {
    if (err instanceof RelayError) {
      process.stderr.write(`sign: POST /v1/sign — ${err.message}\n`);
      return 3;
    }
    throw err;
  }
  if (signed.status !== 200) {
    const detail = signed.body && signed.body.detail ? signed.body.detail : JSON.stringify(signed.body);
    process.stderr.write(`sign: POST /v1/sign answered ${signed.status} — ${detail}\n`);
    return signed.status >= 500 || signed.status === 429 ? 3 : 1;
  }
  const answer = signed.body || {};
  if (typeof answer.signature !== 'string' || answer.signature === '') {
    process.stderr.write('sign: the relay answered without a signature\n');
    return 3;
  }
  if (typeof answer.envelope_id !== 'string' || !/^[A-Za-z0-9]{8}$/.test(answer.envelope_id)) {
    // A positive envelope that names no message is not the positive envelope
    // (delivered-envelope.md §2, §3.1).
    process.stderr.write('sign: the relay answered without an envelope id of eight letters or digits\n');
    return 3;
  }
  // The relay echoes what it signed under. A value other than the one asked for
  // would mean the header above the signature names a version the signature was
  // not made over — the one failure this whole order exists to prevent.
  if (answer.version != null && answer.version !== version) {
    process.stderr.write(
      `sign: asked for version ${version} and the relay signed ${answer.version}; nothing written\n`,
    );
    return 3;
  }
  if (answer.alg != null && answer.alg !== alg) {
    process.stderr.write(
      `sign: asked for algorithm ${alg} and the relay signed ${answer.alg}; nothing written\n`,
    );
    return 3;
  }

  // 4. The signature, and then the visible envelope around the sender's text.
  const verifyUrl = `${String(options.portal).replace(/\/+$/, '')}/${verifyToken(options.uuid, analysis.hash)}`;
  const withHeaders = addHeaders(prepared, [
    ['X-ZEKNOP-Signature', answer.signature],
    ['X-ZEKNOP-Hash', analysis.hash],
    ['X-ZEKNOP-UUID', options.uuid],
    ['X-ZEKNOP-Relay', answer.relay_id || ''],
    ['X-ZEKNOP-Envelope-ID', answer.envelope_id],
    ['X-ZEKNOP-Verify', verifyUrl],
  ]);

  let delivered;
  try {
    delivered = writeEnvelopes(withHeaders, {
      envelopeId: answer.envelope_id,
      verifyUrl,
    });
  } catch (err) {
    if (err instanceof Unsignable) {
      process.stderr.write(`sign: ${err.message}\n`);
      return 2;
    }
    throw err;
  }

  const out = options.out || `${options.file.replace(/\.eml$/i, '')}.signed.eml`;
  if (out === '-') process.stdout.write(Buffer.from(delivered.bytes));
  else await writeFile(out, delivered.bytes);

  const result = {
    out: out === '-' ? '(standard output)' : out,
    shape: analysis.shape,
    from: analysis.from,
    version,
    algorithm: alg,
    timestamp,
    strict_hash: analysis.hash,
    free_hash: analysis.freeHash,
    envelope_id: answer.envelope_id,
    relay_id: answer.relay_id || null,
    verify_url: verifyUrl,
    envelopes_written: delivered.parts.map((part) => part.kind),
  };
  if (options.json) {
    process.stderr.write(`${JSON.stringify(result, null, 2)}\n`);
  } else if (out !== '-') {
    process.stdout.write(
      [
        `wrote            ${result.out}`,
        `shape            ${result.shape}`,
        `from             ${result.from}`,
        `version          ${result.version}`,
        `algorithm        ${result.algorithm}`,
        `signed at        ${result.timestamp}`,
        `strict hash      ${result.strict_hash}`,
        `free hash        ${result.free_hash}`,
        `envelope id      ${result.envelope_id}`,
        `verify link      ${result.verify_url}`,
        `envelopes into   ${result.envelopes_written.join(', ')}`,
        '',
      ].join('\n'),
    );
  }
  return 0;
}

process.exitCode = await main();
