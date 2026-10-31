# ZEKNOP Signed Email — JavaScript example client

**Developer Preview — the protocol and the API may change; nothing on this page is a
security guarantee.**

Publisher: Zeknod OÜ. This example is licensed [Apache 2.0](LICENSE); see [NOTICE](NOTICE).

Three commands over a ZEKNOP relay, in Node with no dependencies at all:

- **`verify`** — read a delivered `.eml`, take the visible envelope off it, recompute both
  fingerprints, and ask a relay whether the signature holds. With `--offline` it computes
  and compares and makes no request.
- **`sign`** — ask a relay what it can sign, have it sign a composed message, and write the
  delivered form: the `X-ZEKNOP-*` fields and the visible envelope around the sender's text.
- **`conformance`** — run every published vector file and print the report in the format
  [`../../vectors/CONFORMANCE.md`](../../vectors/CONFORMANCE.md) fixes.

## What this is not

It is an example, not a library. There is no warranty; see sections 7 and 8 of the
[LICENSE](LICENSE). The version number in `package.json` is not an API, nothing here is
published to a package registry, and the shape of these modules will change without notice.
Read it, copy from it, measure your own implementation against it — but do not depend on it.

It makes no claim about security, performance or privacy, and neither does this file. What
it does claim is an arithmetic one, and `conformance` is how you check it yourself: over the
published vectors this client answers every question the way the reference implementation
does. That is a statement about bytes and nothing more.

It is also not complete. `sign` writes the envelope into a displayed part in an identity
transfer encoding (`7bit`, `8bit`, `binary`, or none) whose charset reads ASCII as ASCII, and
it refuses anything else by name: a `base64` or `quoted-printable` display part, a part in
UTF-16 or ISO-2022, a message with no displayed part, a malformed multipart. Those cases have
rules — [`../../spec/delivered-envelope.md`](../../spec/delivered-envelope.md) §3.3, §3.3.1,
§4 — and an example that got them half right would be worse than one that says it does not do
them. `verify` has no such limits: it reads whatever a signer wrote.

## What you need

Node 20 or newer, and nothing else. No `npm install`: `dependencies` is empty and there are
no development dependencies either. Everything used is built in — `fetch`, `node:crypto`,
`node:fs`, `node:http`, `node:test`.

```sh
node --version        # v20 or newer
node bin/conformance.mjs
```

## verify

```sh
# with a relay: the signature is checked
node bin/verify.mjs message.eml --relay https://relay.example.org

# without one: the fingerprints are computed and compared, and nothing is sent
node bin/verify.mjs message.eml --offline

# machine-readable
node bin/verify.mjs message.eml --offline --json
```

It prints what the message announces (version, algorithm, identity, time, envelope id), the
strict fingerprint the header carries and the one recomputed from the delivered bytes, the
second fingerprint over the free text form, and the verdict with one sentence saying what
that verdict means.

**The message does not leave the process.** What a relay is asked is the identity, the
signature, the two fingerprints and the time — never the message itself. `--offline` sends
nothing at all; what it establishes is smaller and it says so in its own output: a
fingerprint that agrees with the header means the signed content is the content the header
names, and nothing about who signed it. A fingerprint that disagrees means the signed
content changed, and that much needs nobody.

**Not every negative answer is about the message.** `signature-mismatch` is the one that says
the signed content changed. `unknown-identity` says the relay has no record of that identity, so
nothing was checked against anything; `identity-not-active` says the signature holds and the
identity is not active — the signed content is the content that was signed. A `409` is a refusal and
not a verdict: the signature was made under a version this client did not say it can build.
No connection, a timeout, a `5xx` and a `429` are outages, and this client exits 3 for them
rather than reporting anything about the message. The whole table is in
[`../../api/README.md`](../../api/README.md).

Exit codes: **0** the signature holds — with `--offline`, the two fingerprints agree; **1** a
verdict that is not green, the not-verified block included; **2** the command was asked
wrongly; **3** no verdict was obtained. A `409` exits **3** and not 1, because it is a refusal
of the question rather than a statement about the message. Exit 3 therefore covers both, and
what to do next is not the same: an outage may be asked again, a refusal is answered the same
way however often it is asked. The output tells them apart: the version refusal prints a
result whose verdict is `unsupported-version`, with the relay's own sentence in
`relay_detail`, while everything else that produced no verdict prints no result at all and
says on standard error what the relay answered.

## sign

```sh
node bin/sign.mjs composed.eml \
    --uuid 00000000-0000-4000-8000-000000000000 \
    --api-key "$ZEKNOP_API_KEY" \
    --relay https://relay.example.org \
    --portal https://verify.example.org/v1 \
    --out signed.eml
```

The identity and its key come from a relay you can register on — your own deployment, or a
sandbox once one is published ([`../../sandbox/`](../../sandbox/) says what one is). Put the key in the environment rather than in
a shell history; this example never writes it anywhere.

The order of the four steps is the specification's and not a convenience:

1. **`GET /v1/capabilities`**, and take the newest version both this client and that relay can
   build. A relay that does not answer `200` naming it has not said yes, and nothing is
   written. The reason is a message that cannot be repaired: a relay older than that route
   accepts a signing request naming a newer version and signs the input it has always built,
   the message leaves announcing a version its signature was not made over, and every verifier
   calls it invalid for ever — about a message nobody touched
   ([`../../spec/signature-input.md`](../../spec/signature-input.md) §6).
2. **Write the version, the algorithm and the timestamp**, and compute both fingerprints over
   the message with them in it. They are inputs to what is signed, so they go in first.
3. **`POST /v1/sign`**. The relay builds the signed bytes itself from the version, the
   algorithm and the two fingerprints; it is never handed bytes to sign. An `Idempotency-Key`
   names the request, so a retry after a lost answer cannot sign one message twice
   (`--no-idempotency-key` turns it off).
4. **Write the signature and the visible envelope.** The envelope can only be written now:
   its link carries the fingerprint and the envelope id the relay has just answered with. The
   whole block sits outside the fingerprint, which is why writing it afterwards is sound —
   a verifier takes it off again before hashing
   ([`../../spec/delivered-envelope.md`](../../spec/delivered-envelope.md) §6.1).

The relay and the portal are the ones your deployment gave you, and **both are required**:
there is no default for either. `--portal` is the whole prefix that deployment serves tokens
under, path and all, because the link line of the visible envelope is `<portal>/<token>` and
`<portal>` is the portal of the given deployment and not a fixed name
([`../../spec/delivered-envelope.md`](../../spec/delivered-envelope.md) §3.4). A default here
would be written into a delivered message, where a link nobody serves is worse than no link —
and both signers of one deployment must be given the same value. Every address in this package
is an example address: `example.org`, `example.com`, `192.0.2.x`. A sandbox, where one is
offered, says so itself in `GET /v1/capabilities`.

## conformance

```sh
node bin/conformance.mjs                      # the vectors of this package
node bin/conformance.mjs --vectors /some/dir  # another copy of them
node bin/conformance.mjs --json
```

It prints the report of [`../../vectors/CONFORMANCE.md`](../../vectors/CONFORMANCE.md) §1:
the counts `matched / compared` per file, the specification versions, and the SHA-256 of each
file **as this run read it** — print your own digests, not the ones in that document, because
two lists that differ is the fastest way to see a report over edited vectors.

Two things in the output are worth reading rather than skipping:

- **`SKIP`** names the two vectors that cannot be compared as a string.
  `e2e-003-body-truncation` describes a body of 1 049 000 characters and
  `e2e-004-body-cut-code-points` gives one as a recipe whose last code point before the cut
  is U+1F642; for neither does the file store the megabyte of canonical JSON the hash was
  taken over. The hash and the truncated length — in CODE POINTS — are reproducible for both
  and both are compared; only the string comparison is skipped.
- **`diagnostics`** are the fields `../../vectors/CONFORMANCE.md` §2 puts outside the measured totals
  (`decoded_text_sha256_b64`, `unwrapped_text`). They are compared here anyway and reported
  apart. Four of them differ from the reference, all four about the READ step and none about
  a fingerprint: three cases whose bytes begin with a UTF-8 byte order mark, which this
  reading removes and the reference keeps, and one field with white space at both ends, which
  this reading trims because that is what a header parser does to a field of a real message.
  §2 strips a leading byte order mark and trims the ends before anything is hashed, so the
  measured forms agree on every one of them. `test/conformance.test.mjs` pins that list, so a
  fifth would be a failing test rather than a surprise.

## Tests

```sh
node --test
```

- `conformance.test.mjs` — every vector file, and the number of comparisons each file asks
  for. A harness that has quietly stopped asking also stops mismatching, so the count is
  asserted as well as the result. The two vectors that describe their body as wire bytes are
  asserted separately, because a harness could render their decoded text instead and still
  match the expected hash while never reading a byte of what they are about.
- `verify-offline.test.mjs` — a delivered message assembled in the test: the envelope comes
  off, the fingerprint is the one in the header, one character changed makes it not, and a
  message carrying the not-verified block is not green here either.
- `sign-mock.test.mjs` — `sign` then `verify` against a relay stand-in on `127.0.0.1`
  (`test/support/mock-relay.mjs`). The stand-in holds an ed25519 key pair and signs the bytes
  of [`../../spec/signature-input.md`](../../spec/signature-input.md) §2, so `valid` is the
  result of checking a signature and the tampered case fails for the reason a tampered message
  fails anywhere. One case asks it to refuse: the `409` must not come out as a verdict. One
  more asks for a signature with no `--portal`: nothing is written and the relay is not asked,
  because the portal goes into the delivered message and this example has no default for it.
- `e2e-stack.mjs` — the same run against a real relay. It is SKIPPED unless `RELAY_URL`,
  `SIGNER_UUID`, `SIGNER_API_KEY` and `SIGNER_FROM` are in the environment, so the suite is
  safe to run with no relay anywhere.

## How the fingerprint is computed here

`vendor/canonical/` is a copy of the canonicalisation modules of the build this preview was
cut from. They are copied rather than reimplemented on purpose: the verdict rests on those
bytes, and a second implementation of the rules would be a second specification — the first
byte the two disagreed on would be a message one of them calls verified and the other calls
changed.

Each copied file carries a licence header, and each carries at least one substitution recorded
with the copy: a comment that pointed at a file of the publisher's own repository, or named one
of the publisher's own services, now points at the section of the specification that states the
same rule, or is written in terms of any reader of this protocol. Every one of them is inside a
comment. **The code is the same program as the code of that build** — that is what was checked
when the copy was made: both sides were parsed, and both the two lists of tokens and the two
parse trees had to come out identical. A comment is in neither of those, which is why what a
substitution can change is what a comment says and not what the program does. It is a statement
about that comparison and about nothing else: it does not say the rules are right, only that
this copy computes what the build it came from computes. What the comments no longer say is
which service of the publisher's deployment does what; every rule, and every reason a line is
the way it is, is still there.

Everything else here (`src/`, `bin/`, `test/`) is written for this example, from the
specification documents it cites.

The rules themselves are in [`../../spec/`](../../spec/):
[`canonical-content.md`](../../spec/canonical-content.md) (what is hashed, strict form §2 and
free text form §2b, the parts manifest §9),
[`signature-input.md`](../../spec/signature-input.md) (what the signature is made over),
[`delivered-envelope.md`](../../spec/delivered-envelope.md) (what the reader sees, and how a
verifier takes it off again). The HTTP contract is in [`../../api/`](../../api/), the vectors
in [`../../vectors/`](../../vectors/), and what a sandbox relay is in
[`../../sandbox/`](../../sandbox/); none is published with this preview.

The example addresses here are `example.org` and `example.com`, the only address literal is
the loopback one the test relay stand-in binds (`127.0.0.1`), and there are no keys anywhere.
`sign` takes an API key from `--api-key`, puts it in the `X-API-Key` header of `POST /v1/sign`
and writes it nowhere else — not into the message, not onto a stream.

One real host name does appear, and it belongs there: the not-verified block of
[`src/envelope-build.mjs`](src/envelope-build.mjs) names the verification portal, because
[`../../spec/delivered-envelope.md`](../../spec/delivered-envelope.md) §3.2 fixes that
sentence byte for byte and a verifier compares the block against it. Changing it to an example
address would make this client write a block no verifier recognises.
