<!-- Developer Preview: the changelog of this package. New text, not a copy. -->
**ZEKNOP Signed Email — Developer Preview, changelog of the package.** Publisher: Zeknod OÜ.
Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

---

# Changelog of the package

What changed between the published states of this package, newest first. The normative changes
to the specification are in [`spec/CHANGELOG.md`](spec/CHANGELOG.md), the changes to the HTTP
contract in [`api/API-CHANGELOG.md`](api/API-CHANGELOG.md); this file says where to look and
what else changed.

## beta.12

- **Specification** (`spec/`; the beta.12 entry of `spec/CHANGELOG.md`). The places where an
  implementation written from the documents and the vectors alone had to guess now say what the
  implementations and the vectors do: the EUC-JP decoder, white space in an address, an encoded
  word with an empty charset, the plain `boundary=` parameter, the HTML envelope rule, the
  reason tags of the timestamp vectors. The sentences that said more than the signature covers
  now say what it covers. No rule changes and every vector gives the answer it gave.
- **Tables** (`spec/tables/`, new). The index data of the Encoding Standard, the single-byte
  table, and the Unicode 15.1.0 and HTML5 tables the specification pins, as data. The
  single-byte table equals the standard's index files pointer by pointer.
- **Vectors** (`vectors/`). New: `signed-message/`, one delivered message signed end to end
  with an example key whose seed is published. `CONFORMANCE.md` says how to read
  `body_encoding`, and its example report carries no date. Two vector notes now say what their
  vector is (one named a date, one described a bare value wrongly); expected values are the same.
  `CONFORMANCE.md` says what to compare in `signed-message/`.
- **Generators** (`vectors/*.py`). The five generators and the validator are reformatted;
  every `--check` passes and no vector file changes because of it.
- **API** (`api/`). The format of an identity's public keys in
  `GET /v1/verify/{identity_uuid}`; the listing window of forwarded copies told apart from how
  long their records are kept; "changed" said of the signed content where it was said of the
  message. In `openapi-public.json` the `attachments` of `POST /v1/sign` are described as what
  the relay keeps with the signature record, not as part of what is signed. The `403` of
  `POST /v1/sign` no longer names a pricing plan.
- **Examples** (`examples/js/`, `examples/python/`). "Changed" said of the signed content where
  it was said of the message; neither README points at a sandbox to try a client against.
- **Sandbox, page, README.** No sandbox is published with this preview, and none of these says
  that one follows.

## beta.11

- **Specification:** §2 and §9.2a of `canonical-content.md` as the implementations follow them
  (the body cut by code points, one reading of the white space around a MIME boundary); §8,
  point 4 of the Replay Model, says what a relay's `POST /v1/verify` does with a repeated
  question; `delivered-envelope.md` §6.1 says "does not recompute".
- **Vectors:** `e2e-004` (a body cut by code points, written as a recipe), `pm-021` to `pm-027`
  (boundary white space where two languages' sets differ), the differential cases with the
  size-limit and trim families and a `cut` form; counts and digests updated.
- **Examples:** both clients read a recipe body and answer the `cut` form; the JavaScript copy of
  the canonicalisation cuts by code points; the Python copy reads the boundary, a transfer
  encoding and a header field name as the specification says.
- **API:** the three refusals of `POST /v1/sign`.
- **Repository:** a README at the root.

## First publication

The specification extract, the test vectors and the differential cases with reference answers,
the public part of a relay's HTTP contract, the description of a sandbox relay, and two example
clients.
