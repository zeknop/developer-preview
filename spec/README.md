<!-- Developer Preview: the README of the ZEKNOP Signed Email specification. New text, not a copy. -->
**ZEKNOP Signed Email — the specification.** Publisher: Zeknod OÜ.
Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

**Developer Preview — the protocol and the API may change; nothing in this package is a
security guarantee.**

---

# The specification

Four documents, and between them they say everything an implementation of signing and
verifying needs: what is hashed, what the signature is made over, what a delivered message
looks like, and what changed when. One section is left out — how a deployment checks a copy
forwarded by an ordinary mail client; see "What is left out" below.

| Document | Version | Normative for |
|---|---|---|
| [canonical-content.md](canonical-content.md) | 1.4 | **what is hashed** — reading the bytes, the strict form, the free text form, the parts manifest |
| [signature-input.md](signature-input.md) | 1.4 and 1.5 | **what is signed** — the signature input, the algorithm registry, the identity record, the API |
| [delivered-envelope.md](delivered-envelope.md) | 1.4 | **what is delivered** — the visible block a signer writes, and how a verifier takes it off |
| [CHANGELOG.md](CHANGELOG.md) | up to 1.4 | the normative changes, version by version |

**When two of them disagree, the one that is normative for the subject wins:**
`canonical-content.md` for what is hashed, `signature-input.md` for what is signed,
`delivered-envelope.md` for what is delivered.

**One place where that rule has to be used.** A signer writes the envelope into a displayed
`text/html` part as well, as the head and tail blocks of `delivered-envelope.md` §3.3.1 — that
document is normative for it, and its §4 gives the date that was decided. The paragraph in
`canonical-content.md` §2b.7 that speaks of no signer writing an envelope into HTML describes
the state on the day that document was written, which is earlier; it is not permission to
leave those blocks inside the hashed text. What §2b.7 does settle, and what holds, are the
two rules around them: an envelope in the HTML alternative gets no free hash of its own, and
the blocks come off the HTML **source** before the markup is resolved to text.

Around this directory:

- [`../vectors/`](../vectors/) — the test vectors every implementation is held to, with the
  generators that build them and the differential cases;
- [`../api/`](../api/) — the public part of the relay's HTTP contract, and the semantics the
  schema cannot state;
- [`../examples/js/`](../examples/js/) and [`../examples/python/`](../examples/python/) — two
  small clients that verify a message, sign one, and run the vectors. They are examples, not
  libraries, and they are the shortest way to read how the documents fit together.

## Quick start for v1.4

Seven steps, in the order the protocol itself goes. The section numbers are the ones in the
documents; each step is a place to stop and compare against the vectors.

**1. Read the bytes** — `canonical-content.md` §2, Step 0. A part's declared charset decides
how its bytes become text, and the rule is the WHATWG Encoding Standard's with pinned index
data, not the decoder your runtime happens to carry. Reading never fails: an unknown label
reads as UTF-8. Get this wrong and every hash below is wrong for exactly the messages that
are hardest to test. Vectors: `../vectors/charset-vectors.json`.

**2. Build the strict form** — `canonical-content.md` §1 and §2 to §8. The canonical content
object has two shapes and the shape is chosen from the structure of the message (§1.1), never
from a header. Shape A is the plain one: the normalised sender (§3), the normalised
recipients (§4), the trimmed subject (§5), the normalised body (§2, steps 1 to 4) and the
timestamp (§8). BCC is outside it (§6). The strict hash is SHA-256 over the JSON
serialisation of that object, in base64 (§7). Vectors: `../vectors/vectors.json`, `../vectors/timestamp-vectors.json`.

**3. Build the free text form** — `canonical-content.md` §2b. The second hash: the displayed
text with our envelope taken off (§2b.5), HTML flattened to text (§2b.3), every U+FEFF
removed, every run of white space collapsed to one space, trimmed, NFC over pinned Unicode
tables (§2b.4), UTF-8, SHA-256. The full list of steps, in order, with the white space set
written out character by character, is §2b.2 — read it there rather than from this sentence.
One message has exactly one free hash (§2b.1). Vectors:
`../vectors/free-form-vectors.json`.

**4. Build the parts manifest where the message needs it** — `canonical-content.md` §9. Shape
B replaces the body with an ordered manifest of every leaf of the MIME tree: the walk is
document order (§9.1), a container with no usable boundary is one opaque leaf (§9.2, §9.2a),
and the order is normative. Vectors: `../vectors/parts-manifest-vectors.json`.

**5. Build the signature input** — `signature-input.md` §2. From v1.4 the signature is not
made over the strict hash alone: the input is the separator `ZEKNOP-SIG`, the version, the
algorithm name and the two raw hashes, each field preceded by its length. §1 says which
headers carry the version and the algorithm, §3 is the algorithm registry and the three
states a name can be in, and §4 says how a message that announces no version is read.
Vectors: `../vectors/signature-input-vectors.json`.

**6. Take the delivered envelope off, or write it** — `delivered-envelope.md`. A signer writes
the visible block §3.1 and §3.3 into every displayed `text/plain` part, and §3.3.1 into every
displayed `text/html` part; a message it cannot sign carries the not-verified block (§3.2)
instead, and never nothing (§2). A verifier removes the outer block first (§6.1) and hashes
what remains — the block is outside the hash, so the removal belongs before steps 2 and 3
above. Vectors: `../vectors/delivered-envelope-vectors.json`.

**7. Ask, or check locally** — `../api/`. With the two hashes, the version and the algorithm,
`POST /v1/verify` answers whether the signature holds for the identity the message claims;
`GET /v1/verify/{uuid}` publishes that identity's keys with their validity, which is what lets
you check a signature yourself instead of taking the answer for it.

A verifier that recomputes a fingerprint which does not match says the message was changed, so
the two orders that matter are worth repeating: the envelope comes off before the content is
read, and the version is read before the content is hashed.

## Showing that an implementation agrees

Run your implementation over every file in `../vectors/` and over the differential cases
there; that directory's own notes say what to compare for each kind of case and how to report
the result, so that one implementation's result can be read beside another's. Agreement with
the vectors is what the word "conformant" means here, and nothing in this package certifies an
implementation or grants it anything.

## Licence

These four documents are published by Zeknod OÜ under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/): use them, quote them and build on
them, with attribution. Each file carries the digest of the source it was copied from, and
apart from that header the only differences are the rewrites described below, the notes
described under them, and the one section left out of `signature-input.md`.

This README is published by Zeknod OÜ under the same licence. It is new text written for this
package and a copy of nothing, so it carries no source digest — the other four `.md` files
here each carry one, because each of them is a copy of a file that has one; where this README
summarises a rule, the document it names is the one that decides.

**What the rewrites are.** In the publisher's repository these documents point at the code,
the tests and the records behind each rule. A reader outside that repository cannot open any of
it, so each such pointer either became a pointer inside this package — the vectors, a sibling
document, a section number — or was dropped, and one paragraph that was only about the
repository's own layout went with it. Internal item, window and review identifiers, internal
decision records, build revisions and the names of people are gone the same way. No normative
sentence was changed: the rules, the tables, the vectors they name and the order of the steps
are the ones the implementations are held to.

**What the notes are.** Three of the four copies carry, between the header and the document, a
short list of notes from the publisher. They exist because a sentence may rest on something
this package does not carry: a measurement of the publisher's (the word "measured" in
`canonical-content.md`, `signature-input.md` and `delivered-envelope.md`) or a test of the
publisher's (the ticks of the §12 checklist in `canonical-content.md`). A note names the
sentence, says what it rests on, and says what in this package you can rerun instead. It is
marked as the publisher's, it is normative for nothing, and it never adds a rule the document
does not make. A sentence that was ambiguous, absolute about security, or at odds with another
part of a document is not a note's business: it was corrected in the specification itself
before these copies were made (see the entry of 2026-10-24 in `CHANGELOG.md`).

**What is left out.** `signature-input.md` §9 describes an operator-side service that checks a
copy forwarded by an ordinary mail client, and its trust model. It is not part of this preview.
Its heading stays, with a note in place of the section, so the numbering and the pointers to it
still resolve. The one path of it that a portal reads without a key,
`GET /v1/forward-checks/{envelope_id}`, is part of the preview and is described in
[`../api/README.md`](../api/README.md).
