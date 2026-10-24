#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zeknod OÜ
// ─────────────────────────────────────────────────────────────────────────────
// conformance — run every published vector file and print the report.
//
//   node bin/conformance.mjs [--vectors DIR] [--mismatches N] [--json]
//
// The report format is the one ../../../vectors/CONFORMANCE.md §1 fixes, so that
// this run can be put beside the run of an implementation nobody here has seen
// and read without a translation step. The digests printed are of the files
// THIS run read, which is the point of printing them.
//
// No network, no container, no credential. Exit code 0 when every file matched,
// 1 when any comparison did not.
// ─────────────────────────────────────────────────────────────────────────────

import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { runConformance, specificationVersions } from '../src/conformance.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT_VECTORS = resolve(HERE, '..', '..', '..', 'vectors');

function parseArguments(argv) {
  const options = { vectors: DEFAULT_VECTORS, mismatches: 10, json: false };
  for (let i = 0; i < argv.length; i++) {
    const argument = argv[i];
    if (argument === '--vectors') options.vectors = resolve(argv[++i]);
    else if (argument === '--mismatches') options.mismatches = Number(argv[++i]);
    else if (argument === '--json') options.json = true;
    else if (argument === '--help' || argument === '-h') options.help = true;
    else {
      process.stderr.write(`conformance: unknown argument ${argument}\n`);
      process.exit(2);
    }
  }
  return options;
}

const USAGE = `conformance — report how this implementation answers the published vectors

  node bin/conformance.mjs [--vectors DIR] [--mismatches N] [--json]

  --vectors DIR    the directory holding the vector files (default: the vectors/
                   directory of this package)
  --mismatches N   how many mismatches to print per file (default 10)
  --json           print the whole result as JSON instead of the report
`;

/** The one-line name of this implementation, as the report prints it. */
async function implementationName() {
  const manifest = JSON.parse(
    await readFile(resolve(HERE, '..', 'package.json'), 'utf8'),
  );
  return `${manifest.name} ${manifest.version} (Node ${process.versions.node})`;
}

function padLeft(text, width) {
  return String(text).padStart(width, ' ');
}

function padRight(text, width) {
  return String(text).padEnd(width, ' ');
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) {
    process.stdout.write(USAGE);
    return 0;
  }

  const { files, diagnostics } = await runConformance(options.vectors);
  const specification = await specificationVersions(options.vectors);

  if (options.json) {
    process.stdout.write(`${JSON.stringify({ files, specification }, null, 2)}\n`);
    return files.every((file) => file.matched === file.compared) ? 0 : 1;
  }

  const nameWidth = Math.max(...files.map((file) => file.name.length)) + 2;
  const countWidth = Math.max(
    ...files.map((file) => `${file.matched}/${file.compared}`.length),
  );

  const out = [];
  out.push('ZEKNOP conformance report');
  out.push(`  implementation   ${await implementationName()}`);
  out.push(`  date             ${new Date().toISOString().slice(0, 10)}`);
  out.push(
    `  specification    canonical-content.md ${specification['canonical-content.md']}, ` +
      `signature-input.md ${specification['signature-input.md'].replace(', ', '/')},`,
  );
  out.push(`                   delivered-envelope.md ${specification['delivered-envelope.md']}`);
  out.push('');
  for (const file of files) {
    const counts = padLeft(`${file.matched}/${file.compared}`, countWidth);
    const note = file.note ? `  (${file.note})` : '';
    out.push(`  ${padRight(file.name, nameWidth)}${counts}${note}`);
  }
  out.push('');
  out.push('  vector files as read, sha256:');
  for (const file of files) out.push(`    ${file.sha256}  ${file.name}`);

  const skipped = files.flatMap((file) =>
    file.skipped.map((entry) => `    ${file.name} ${entry.id}: ${entry.why}`),
  );
  if (skipped.length) {
    out.push('');
    out.push('  SKIP:');
    out.push(...skipped);
  }

  if (diagnostics) {
    // CONFORMANCE.md §2: `decoded_text_sha256_b64` and `unwrapped_text` are
    // diagnostics, not measured values, and are not in the 10 575. They are
    // computed and compared here anyway — a difference in the READ step that no
    // hash shows is worth knowing about — and reported apart, named, so the
    // report cannot be read as either a pass or a failure it is not.
    out.push('');
    out.push(
      '  diagnostics of differential/cases.json (CONFORMANCE.md §2: not measured, ' +
        `not in the totals above): ${diagnostics.matched}/${diagnostics.compared}`,
    );
    for (const mismatch of diagnostics.mismatches) {
      out.push(`    ${mismatch.id} ${mismatch.field} differs`);
    }
  }

  const failing = files.filter((file) => file.matched !== file.compared);
  if (failing.length) {
    out.push('');
    out.push('  MISMATCHES:');
    for (const file of failing) {
      out.push(`    ${file.name}: ${file.compared - file.matched} of ${file.compared}`);
      for (const mismatch of file.mismatches.slice(0, options.mismatches)) {
        out.push(`      ${mismatch.id} ${mismatch.field}`);
        out.push(`        expected ${JSON.stringify(mismatch.expected)}`);
        out.push(`        got      ${JSON.stringify(mismatch.got)}`);
      }
      if (file.mismatches.length > options.mismatches) {
        out.push(`      … ${file.mismatches.length - options.mismatches} more`);
      }
    }
  }

  process.stdout.write(`${out.join('\n')}\n`);
  return failing.length === 0 ? 0 : 1;
}

process.exitCode = await main();
