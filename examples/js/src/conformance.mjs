// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zeknod OÜ
// ─────────────────────────────────────────────────────────────────────────────
// Running every published vector file, and reporting the result in the one
// format ../../../vectors/CONFORMANCE.md fixes.
//
// Everything that decides an answer here comes from the vendored
// canonicalisation (../vendor/canonical/), from ./envelope-build.mjs for the
// two blocks a signer writes, from ./signature-input.mjs for the bytes under a
// signature and from ./timestamp.mjs for the §8 decision. This file only asks
// the questions and counts.
//
// A mismatch is kept with the case id, the field, the value that was computed
// and the value that was expected, because that is what CONFORMANCE.md says a
// report needs in order to be reproducible.
// ─────────────────────────────────────────────────────────────────────────────

import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import { canonicalTextPartInput } from '../vendor/canonical/base.mjs';
import { sha256Base64, utf8Bytes } from '../vendor/canonical/digest.mjs';
import {
  deliveredEnvelopeKind,
  stripHtmlDeliveredEnvelope,
  stripZeknopEnvelope,
} from '../vendor/canonical/envelope.mjs';
import { freeFormText } from '../vendor/canonical/free-form.mjs';
import {
  decodeBytesWithCharset,
  decodeEncodedWords,
  headerValue,
  parseHeaderBlock,
  usableBoundary,
} from '../vendor/canonical/headers.mjs';
import { canonicalizeRawMessage } from '../vendor/canonical/message.mjs';
import { extractPartsManifest, parsePart } from '../vendor/canonical/mime.mjs';

import { buildForVector } from './envelope-build.mjs';
import { hex, signatureInput } from './signature-input.mjs';
import { timestampDecision } from './timestamp.mjs';
import { renderVector } from './vector-render.mjs';

/** The vector files, in the order CONFORMANCE.md §1 prints them. */
export const VECTOR_FILES = [
  'vectors.json',
  'free-form-vectors.json',
  'charset-vectors.json',
  'parts-manifest-vectors.json',
  'signature-input-vectors.json',
  'timestamp-vectors.json',
  'delivered-envelope-vectors.json',
  'differential/cases.json',
];

function hexToBytes(text) {
  const clean = String(text).trim();
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

/** A counter with the mismatches CONFORMANCE.md asks a report to name. */
class Tally {
  constructor() {
    this.compared = 0;
    this.matched = 0;
    this.skipped = [];
    this.mismatches = [];
  }

  compare(id, field, got, expected) {
    this.compared += 1;
    if (got === expected) {
      this.matched += 1;
      return true;
    }
    this.mismatches.push({ id, field, got, expected });
    return false;
  }

  /** One vector counted once, over however many fields it asks about. */
  vector(id, pairs) {
    this.compared += 1;
    const wrong = pairs.filter(([, got, expected]) => got !== expected);
    if (wrong.length === 0) {
      this.matched += 1;
      return true;
    }
    for (const [field, got, expected] of wrong) this.mismatches.push({ id, field, got, expected });
    return false;
  }

  skip(id, why) {
    this.skipped.push({ id, why });
  }
}

const hashText = (text) => sha256Base64(utf8Bytes(text));

/**
 * A Subject field as it arrives → the text §5 reads out of it.
 *
 * A field arrives FOLDED, and it is unfolded before the encoded words are read:
 * the line break goes, the folding whitespace stays (RFC 5322 §2.2.3), and two
 * words that are then adjacent across whitespace join without it (§5). Doing
 * that by hand would be a second reading of a header, so the field is put back
 * into a one-header block and read with the same parser a message is read with.
 */
function subjectText(raw) {
  const block = utf8Bytes(`Subject: ${raw}\r\n\r\n`);
  const unfolded = headerValue(parseHeaderBlock(block).headers, 'Subject') || '';
  return decodeEncodedWords(unfolded);
}

// ── vectors.json ─────────────────────────────────────────────────────────────

async function runCanonicalContent(data) {
  const tally = new Tally();
  for (const vector of data.vectors) {
    const result = await canonicalizeRawMessage(renderVector(vector));
    const pairs = [['shape', result.shape, vector.expected.shape || 'A']];
    if (vector.expected.canonical_json != null) {
      pairs.push(['canonical_json', result.canonicalJson, vector.expected.canonical_json]);
    } else {
      // e2e-003: its body is a megabyte the file does not store, so the string
      // comparison is the one thing that cannot be made. The hash it was taken
      // over is reproducible from the described input and IS compared.
      tally.skip(vector.id, 'the canonical JSON is not stored in the file; compared on the hash');
    }
    pairs.push(['content_hash', result.hash, vector.expected.content_hash]);
    if (vector.expected.canonical_body != null) {
      pairs.push(['canonical_body', result.canonical.body, vector.expected.canonical_body]);
    }
    if (vector.expected.canonical_subject != null) {
      pairs.push(['canonical_subject', result.canonical.subject, vector.expected.canonical_subject]);
    }
    if (vector.expected.canonical_from != null) {
      pairs.push(['canonical_from', result.canonical.from, vector.expected.canonical_from]);
    }
    if (vector.expected.canonical_to != null) {
      pairs.push(['canonical_to', result.canonical.to, vector.expected.canonical_to]);
    }
    if (vector.expected.parts != null) {
      pairs.push([
        'parts',
        JSON.stringify(result.canonical.parts),
        JSON.stringify(vector.expected.parts),
      ]);
    }
    if (vector.expected.truncated_body_length != null) {
      pairs.push([
        'truncated_body_length',
        result.canonical.body.length,
        vector.expected.truncated_body_length,
      ]);
    }
    // `warning_logged` is about our readers saying something in a log, not about
    // the bytes (CONFORMANCE.md). It is not compared and not counted.
    tally.vector(vector.id, pairs);
  }
  return { tally, note: 'e2e-003 on the hash: no canonical JSON stored' };
}

// ── free-form-vectors.json ───────────────────────────────────────────────────

async function runFreeForm(data) {
  const tally = new Tally();
  for (const vector of data.vectors) {
    const text = freeFormText(vector.input, vector.kind === 'html');
    tally.vector(vector.id, [
      ['text', text, vector.text],
      ['hash', await hashText(text), vector.hash],
    ]);
  }
  return { tally, note: null };
}

// ── charset-vectors.json ─────────────────────────────────────────────────────

async function runCharset(data) {
  const tally = new Tally();
  for (const vector of data.text_parts) {
    const text = decodeBytesWithCharset(hexToBytes(vector.bytes_hex), vector.charset);
    tally.vector(vector.id, [
      ['text', text, vector.text],
      ['text_sha256_base64', await hashText(text), vector.text_sha256_base64],
    ]);
  }
  for (const vector of data.subjects) {
    const text = subjectText(vector.raw);
    tally.vector(vector.id, [
      ['text', text, vector.text],
      ['text_sha256_base64', await hashText(text), vector.text_sha256_base64],
    ]);
  }
  return {
    tally,
    note: `${data.text_parts.length} text parts, ${data.subjects.length} subjects`,
  };
}

// ── parts-manifest-vectors.json ──────────────────────────────────────────────

async function runPartsManifest(data) {
  const tally = new Tally();
  for (const vector of data.vectors) {
    const root = parsePart(hexToBytes(vector.message_hex));
    const manifest = (await extractPartsManifest(root)).map((part) => part.k);
    tally.vector(vector.id, [
      ['boundary', usableBoundary(vector.content_type) || '', vector.boundary],
      ['manifest', JSON.stringify(manifest), JSON.stringify(vector.manifest)],
    ]);
  }
  return { tally, note: null };
}

// ── signature-input-vectors.json ─────────────────────────────────────────────

async function runSignatureInput(data) {
  const tally = new Tally();
  for (const vector of data.vectors) {
    tally.vector(vector.id, [
      [
        'signature_input_hex',
        hex(
          signatureInput({
            version: vector.version,
            algorithm: vector.algorithm,
            strictHashB64: vector.strict_hash_b64,
            freeHashB64: vector.free_hash_b64,
          }),
        ),
        vector.signature_input_hex,
      ],
    ]);
  }
  return { tally, note: null };
}

// ── timestamp-vectors.json ───────────────────────────────────────────────────

async function runTimestamp(data) {
  const tally = new Tally();
  const now = Date.parse(data.reference_now);
  for (const vector of data.vectors) {
    const { decision, reason } = timestampDecision(vector.timestamp, {
      context: vector.context,
      now,
    });
    tally.vector(vector.id, [
      ['expected_decision', decision, vector.expected_decision],
      ['expected_reason_tag', reason, vector.expected_reason_tag],
    ]);
  }
  return { tally, note: `reference_now ${data.reference_now}` };
}

// ── delivered-envelope-vectors.json ──────────────────────────────────────────

async function runDeliveredEnvelope(data) {
  const tally = new Tally();
  for (const array of ['build', 'build_html']) {
    for (const vector of data[array]) {
      tally.vector(vector.id, [
        ['text', buildForVector(array, vector.kind, vector.input), vector.expected.text],
      ]);
    }
  }
  for (const vector of data.strip) {
    const stripped = stripZeknopEnvelope(vector.delivered);
    // The kind is read by the same rule the removal is: a body whose outer block
    // is the not-verified one is recognised and never taken off.
    const kind = deliveredEnvelopeKind(vector.delivered);
    tally.vector(vector.id, [
      ['expected', stripped, vector.expected],
      ['expected_kind', kind, vector.expected_kind],
    ]);
  }
  for (const vector of data.strip_html) {
    const stripped = stripHtmlDeliveredEnvelope(vector.delivered);
    tally.vector(vector.id, [
      ['expected', stripped.text, vector.expected],
      ['expected_kind', stripped.kind, vector.expected_kind],
    ]);
  }
  return {
    tally,
    note:
      `${data.build.length} build, ${data.build_html.length} build_html, ` +
      `${data.strip.length} strip, ${data.strip_html.length} strip_html`,
  };
}

// ── differential/cases.json ──────────────────────────────────────────────────

/** The forms this implementation computes for one case, by kind. */
async function formsFor(testCase) {
  const kind = testCase.kind;
  if (kind === 'manifest') {
    let manifest;
    try {
      const root = parsePart(hexToBytes(testCase.hex));
      manifest = (await extractPartsManifest(root)).map((part) => part.k).join('|');
    } catch (err) {
      manifest = `error:${err && err.constructor ? err.constructor.name : 'Error'}`;
    }
    return { manifest };
  }

  let text;
  let isHtml = false;
  let decoded = null;
  if (kind === 'text') {
    text = testCase.text;
  } else if (kind === 'bytes') {
    text = decodeBytesWithCharset(hexToBytes(testCase.hex), testCase.label);
    decoded = text;
  } else if (kind === 'subject') {
    text = subjectText(testCase.value);
    decoded = text;
  } else if (kind === 'html') {
    text = testCase.text;
    isHtml = true;
  } else if (kind === 'html-envelope') {
    text = stripHtmlDeliveredEnvelope(testCase.text).text;
    isHtml = true;
  } else {
    throw new Error(`unknown case kind ${kind}`);
  }

  const forms = { free: await hashText(freeFormText(text, isHtml)) };
  if (!isHtml) forms.strict = await hashText(canonicalTextPartInput(text));
  if (kind === 'html-envelope') {
    forms.html = await hashText(text);
    forms.unwrapped_text = text;
  }
  if (decoded !== null) forms.decoded_text_sha256_b64 = await hashText(decoded);
  return forms;
}

async function runDifferential(data) {
  const tally = new Tally();
  // `decoded_text_sha256_b64` and `unwrapped_text` are diagnostics and are not
  // in the 10 575 (CONFORMANCE.md §2). They are computed and compared, and
  // counted separately, so a mismatch there still names itself.
  const diagnostics = new Tally();
  for (const testCase of data.cases) {
    const mine = await formsFor(testCase);
    for (const [form, expected] of Object.entries(testCase.expected)) {
      if (expected === null) continue;
      const target = form === 'decoded_text_sha256_b64' || form === 'unwrapped_text' ? diagnostics : tally;
      if (!(form in mine)) {
        target.compared += 1;
        target.mismatches.push({ id: testCase.id, field: form, got: '(not computed)', expected });
        continue;
      }
      target.compare(testCase.id, form, mine[form], expected);
    }
  }
  return {
    tally,
    diagnostics,
    note: `${data.case_count} cases, seed ${data.seed}`,
  };
}

// ── the run ──────────────────────────────────────────────────────────────────

const RUNNERS = {
  'vectors.json': runCanonicalContent,
  'free-form-vectors.json': runFreeForm,
  'charset-vectors.json': runCharset,
  'parts-manifest-vectors.json': runPartsManifest,
  'signature-input-vectors.json': runSignatureInput,
  'timestamp-vectors.json': runTimestamp,
  'delivered-envelope-vectors.json': runDeliveredEnvelope,
  'differential/cases.json': runDifferential,
};

/**
 * Run every vector file in `dir` and return one result per file: the counts, the
 * mismatches, the SHA-256 of the file as it was read, and the note the report
 * prints beside the counts.
 */
export async function runConformance(dir) {
  const files = [];
  let diagnostics = null;
  for (const name of VECTOR_FILES) {
    const raw = await readFile(join(dir, name));
    const data = JSON.parse(raw.toString('utf8'));
    const result = await RUNNERS[name](data);
    files.push({
      name,
      sha256: createHash('sha256').update(raw).digest('hex'),
      compared: result.tally.compared,
      matched: result.tally.matched,
      note: result.note,
      skipped: result.tally.skipped,
      mismatches: result.tally.mismatches,
    });
    if (result.diagnostics) diagnostics = result.diagnostics;
  }
  return { files, diagnostics };
}

/** The specification versions the vector files themselves name. */
export async function specificationVersions(dir) {
  const cases = JSON.parse(await readFile(join(dir, 'differential', 'cases.json'), 'utf8'));
  return cases.specification;
}
