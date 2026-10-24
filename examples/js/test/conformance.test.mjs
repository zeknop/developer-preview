// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zeknod OÜ
// The conformance run, held to the counts the published vectors have.
//
//   node --test
//
// Two things are asserted and not one. That every comparison matched is the
// obvious one. That the NUMBER of comparisons is the number the files carry is
// the other, and it is the one that catches a harness which has quietly stopped
// asking: a run that compares nothing also mismatches nothing.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalizeRawMessage } from '../vendor/canonical/message.mjs';
import { runConformance } from '../src/conformance.mjs';
import { renderVector } from '../src/vector-render.mjs';

const VECTORS = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'vectors');

/** The comparisons each file asks for, as CONFORMANCE.md §1 counts them. */
const EXPECTED = [
  ['vectors.json', 72],
  ['free-form-vectors.json', 53],
  ['charset-vectors.json', 54],
  ['parts-manifest-vectors.json', 20],
  ['signature-input-vectors.json', 10],
  ['timestamp-vectors.json', 6],
  ['delivered-envelope-vectors.json', 38],
  ['differential/cases.json', 10575],
];

/**
 * The diagnostic fields of differential/cases.json that this implementation
 * answers differently from the reference, with the reason.
 *
 * CONFORMANCE.md §2 puts these fields outside the measured totals, and the
 * measured forms all match — but a difference in the READ step that no hash
 * shows is exactly the kind of thing that should be written down rather than
 * discovered later, so it is pinned here and will fail this test if it changes.
 *
 *   00752/00753/00754-bom-utf-8 — the bytes begin with a UTF-8 byte order mark.
 *     The reading used here removes it; the reference keeps it as U+FEFF. §2
 *     step 1 strips a leading byte order mark before anything is hashed, so
 *     `strict` and `free` are the same on both sides and no verdict about any
 *     message can differ.
 *   00861-encoded-words — the field value has white space at both ends. The
 *     reading used here is the one a message gets: the field is unfolded and
 *     trimmed by the header parser before the encoded words are read (which is
 *     what charset-vectors.json sj-013 requires), and §2 trims the ends again,
 *     so again `strict` and `free` agree.
 */
const KNOWN_DIAGNOSTIC_DIFFERENCES = [
  '00752-bom-utf-8 decoded_text_sha256_b64',
  '00753-bom-utf-8 decoded_text_sha256_b64',
  '00754-bom-utf-8 decoded_text_sha256_b64',
  '00861-encoded-words decoded_text_sha256_b64',
];

test('every published vector file is answered, and every answer matches', async () => {
  const { files, diagnostics } = await runConformance(VECTORS);

  assert.deepEqual(
    files.map((file) => [file.name, file.compared]),
    EXPECTED,
    'the number of comparisons per file is the number the files ask for',
  );

  for (const file of files) {
    assert.deepEqual(
      file.mismatches,
      [],
      `${file.name}: ${file.compared - file.matched} of ${file.compared} did not match`,
    );
    assert.equal(file.matched, file.compared, file.name);
  }

  assert.deepEqual(
    diagnostics.mismatches.map((mismatch) => `${mismatch.id} ${mismatch.field}`).sort(),
    [...KNOWN_DIAGNOSTIC_DIFFERENCES].sort(),
    'the diagnostic fields that differ are the ones written down above, and only those',
  );
});

/**
 * A vector whose body is described BYTE by byte is measured over those bytes.
 *
 * `body-012` and `body-013` carry both their wire bytes (`body_bytes_hex`, a
 * UTF-16 byte order mark and two characters) and the already decoded text
 * (`body`, "Hi"). A harness that rendered the decoded field would measure an
 * ASCII body, match the expected hash anyway — "Hi" is what the bytes decode to
 * — and report the two vectors as compared while never exercising the rule they
 * exist for. The totals cannot catch that, so it is asserted directly: the
 * rendered message must carry the raw bytes and declare the charset.
 */
test('a byte-level body vector is rendered as bytes, not as its decoded text', async () => {
  const data = JSON.parse(await readFile(join(VECTORS, 'vectors.json'), 'utf8'));
  const byteLevel = data.vectors.filter((vector) => vector.input.body_bytes_hex !== undefined);
  assert.deepEqual(
    byteLevel.map((vector) => vector.id),
    ['body-012-utf16-le-bom', 'body-013-utf16-be-bom'],
    'the vectors that describe their body at byte level are the two UTF-16 ones',
  );

  for (const vector of byteLevel) {
    const rendered = Buffer.from(renderVector(vector));
    const bytes = Buffer.from(vector.input.body_bytes_hex, 'hex');
    assert.equal(
      rendered.subarray(rendered.length - bytes.length).equals(bytes),
      true,
      `${vector.id}: the message ends in the wire bytes the vector names`,
    );
    const declared = /charset=(\S+)/.exec(rendered.toString('latin1'));
    assert.match(
      declared[1],
      /^utf-16(le|be)$/,
      `${vector.id}: the part declares the UTF-16 charset those bytes are in, not utf-8`,
    );
    // And the answer over that input is the published one: the byte order mark
    // is detected before any decoding and removed, and the hash is the file's.
    const analysis = await canonicalizeRawMessage(rendered);
    assert.equal(analysis.canonical.body, vector.expected.canonical_body);
    assert.equal(analysis.hash, vector.expected.content_hash);
  }
});

test('the one vector that cannot be compared as a string says so', async () => {
  const { files } = await runConformance(VECTORS);
  const canonical = files.find((file) => file.name === 'vectors.json');
  assert.deepEqual(
    canonical.skipped.map((entry) => entry.id),
    ['e2e-003-body-truncation'],
    'exactly one vector is reported as partly skipped, and it is the megabyte body',
  );
});
