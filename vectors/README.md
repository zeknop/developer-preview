<!--
Licence: Creative Commons Attribution 4.0 International (CC BY 4.0)
          https://creativecommons.org/licenses/by/4.0/
Publisher: Zeknod OÜ
Part of: the ZEKNOP Signed Email specification, Developer Preview
Date: 2026-10-24
-->

# ZEKNOP test vectors

**Developer Preview — the protocol and the API may change; nothing on this page is a
security guarantee.**

This directory is the measurable part of the specification. Each file holds inputs and
the answers the specification requires for them, so an implementation can be held to the
specification without talking to anybody's server.

Nothing here needs a network, a key, or an account. Everything runs with Python 3.11 or
newer and the standard library alone.

## What is in here

| File | Cases | What it fixes |
|---|---|---|
| `vectors.json` | 73 | The canonical content object and its hash — `../spec/canonical-content.md` §2, §3, §4, §5, §9 |
| `free-form-vectors.json` | 53 | The free text form — `../spec/canonical-content.md` §2b |
| `charset-vectors.json` | 40 text parts + 14 subjects | Reading declared charsets (§2 step 0) and RFC 2047 encoded words (§5) |
| `parts-manifest-vectors.json` | 27 | The one reading of a boundary parameter and the parts manifest — §9.1, §9.2a |
| `signature-input-vectors.json` | 10 | The bytes a signature is made over — `../spec/signature-input.md` §2 |
| `timestamp-vectors.json` | 6 | The timestamp decisions — `../spec/canonical-content.md` §8 |
| `delivered-envelope-vectors.json` | 4 build + 5 build_html + 21 strip + 8 strip_html | Writing and removing the delivered block — `../spec/delivered-envelope.md` §3, §6, §7 |
| `differential/cases.json` | 5 341 | The same questions over seeded inputs, with reference answers — see `differential/` below |

Beside the JSON there is a script per file:

- `validate_vectors.py` — recomputes the hash of every vector in `vectors.json` from the
  canonical JSON string the file carries, and compares it to the stored hash.
- `charset_vectors.py`, `delivered_envelope_vectors.py`, `free_form_vectors.py`,
  `parts_manifest_vectors.py`, `signature_input_vectors.py` — each rebuilds its own JSON
  from the rules written in the script, and with `--check` exits 1 when the JSON beside
  it differs.

`timestamp-vectors.json` has no generator: its vectors are decisions, not derived values.
`vectors.json` has no generator either; `validate_vectors.py` is what holds it.

In every one of those scripts the inputs and the expected values are written out by hand
from the specification, and are not read out of an implementation. That is the point: an
implementation that drifts must not be able to move the vectors it is measured against.

## Running them

From the root of this package:

```sh
# every hash in vectors.json, recomputed
python3 vectors/validate_vectors.py
# => Results: 72 passed, 0 failed, 1 skipped out of 73 vectors

# each generator against the JSON beside it; exit 0 = no deviation
python3 vectors/charset_vectors.py --check
python3 vectors/delivered_envelope_vectors.py --check
python3 vectors/free_form_vectors.py --check
python3 vectors/parts_manifest_vectors.py --check
python3 vectors/signature_input_vectors.py --check
```

A generator run **without** `--check` rewrites the JSON next to it. Use `--check` unless
that is what you want.

Three details worth knowing before you read the output:

- `validate_vectors.py` skips one vector of the 73, `e2e-003-body-truncation`. It fixes
  the truncation of a body over 1 048 576 characters and carries the resulting hash, but
  not the megabyte of canonical JSON it was taken over, so this script has nothing to
  recompute from. 72 of 73 are recomputed; a skip is reported, never counted as a pass.
  Your own implementation is better off than the script here: it can build the body from
  the vector's `body_length` and check the hash. `CONFORMANCE.md` says how.
  `e2e-004-body-cut-code-points` is the other vector with no stored canonical JSON, and
  it is NOT skipped: its body is given as a recipe (`input.body_parts`), the script
  builds that body, applies the one rule of §2 the vector is about — the cut to the
  first 1 048 576 code points — and recomputes the hash like any other vector.
- The `regenerate` field inside the JSON files, and the usage lines inside the scripts,
  name the path the vectors have in the specification's own source tree
  (`spec/test-vectors/…`). In this package they are in `vectors/`.
- The `specification` field of `vectors.json` still reads `canonical-content.md v1.3`.
  That is a stale label and nothing more: the field was not updated when the
  specification moved to v1.4, and it says nothing about what the file contains. The
  vectors themselves do cover v1.4 — `shape-a-008` through `shape-a-012` and `parts-010`
  exercise §2 step 0, which the text itself marks "normative since v1.4".
  `differential/cases.json` names the versions it was built against in its own header.
  Where a vector and the normative text could be read against each other, the text is
  what governs.

Two notes on how these files were cut for publication:

- Every **expected value** here is byte for byte the one our own implementations are
  held to, and so is every **input**, with one exception: the two header lines of the
  fixture the `parts-manifest` vectors are read as — and of the `manifest` cases of the
  differential — use the reserved example domains. Those lines are scaffolding; what
  those vectors measure is the boundary parameter and the shape of the message. The
  answers were recomputed over the changed messages and came out identical, which is
  what makes it safe to say so.
- The **prose** beside the vectors — `description`, `note`, `notes`, `why`,
  `categories`, `spec_condition` — was written for readers inside the project and is
  edited here for readers outside it. No implementation, validator or generator reads
  any of those fields; `CONFORMANCE.md` lists, per file, the fields that are compared,
  and none of them is one of these.

## differential/

`differential/cases.json` asks the same questions as the files above, but over 5 341
seeded inputs instead of hand-picked ones: every code point of the trim set and its
neighbours, line endings and their mixtures, combining sequences, sampled code points
from every plane, named and numeric character references, markup edges, our own delivered
blocks in the places a reply puts them, the reshaping an ordinary forward does, the
multi-byte encodings of the standard over valid and invalid bytes, RFC 2047 subjects,
messages whose boundary is written in RFC 2231 segments or with a character the trim set
does not hold, and bodies over the §2 size limit.

Each case carries its input and, under `expected`, the answers of a reference
implementation. `CONFORMANCE.md` says what to compare for each kind of case and how to
report the result. Two kinds of case do not carry their input as text: a `manifest` case
carries a whole message as hex, and a `cut` case carries its body as a RECIPE — pieces of
the form `{"literal": "s"}` and `{"repeat": "s", "count": n}`, joined in order — because a
body over the size limit is a megabyte and does not belong in a file meant to be read.

The cases come from the seed in the file (`20260923`) and the generator count beside it.
The file is ASCII — every code point outside ASCII is a `\uXXXX` escape — because the
cases carry unassigned, private-use and noncharacter code points, and an ASCII file with
escapes is read the same way by every JSON parser.

## Licence

These vectors are part of the ZEKNOP Signed Email specification and are published by
Zeknod OÜ under the **Creative Commons Attribution 4.0 International licence
(CC BY 4.0)**: <https://creativecommons.org/licenses/by/4.0/>

You may use, share and adapt them, including commercially, with attribution.

That covers everything in this directory. The six scripts carry the licence in their own
header; the JSON files cannot carry one, and this section is their notice. Where a file
anywhere in this package does carry a header of its own, that header is what names its
licence — the example clients shipped elsewhere here are under Apache-2.0 and say so.

## What this directory does not say

A vector says what the specification requires for one input. It does not say that an
implementation which matches every vector is correct, secure, or fit for any purpose, and
nothing here is a measurement of security, performance or privacy. The vectors are the
agreement about bytes, and that is all they are.
