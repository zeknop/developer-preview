<!-- Developer Preview copy of the ZEKNOP Signed Email specification. -->
**`CHANGELOG.md`** — the normative changes, version by version. Version the changes up to v1.4 (newest entry 2026-10-24).
Publisher: Zeknod OÜ. Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
Source digest (SHA-256 of the file this copy was made from): `f492cfda7f87ca1892fb4c002f0042e5abc7065d43c058bd78be53682b992107`.
This copy differs from that file in this header and in the reference rewrites described in
[README.md](README.md): a pointer to something a reader outside the publisher's repository
cannot open becomes a pointer inside this package or is dropped. No normative sentence is
changed.

---

# ZEKNOP Canonical Content Specification — changelog

Normative changes to the specification in this directory: `canonical-content.md`,
`delivered-envelope.md` (from v1.4) and `signature-input.md` (from v1.4).

## v1.4 — 2026-10-24: the text says what the implementations and the vectors already do

No computed value changes: every vector gives the answer it gave. The sentences below said
less, or more, than the rule the vectors hold, and now say the rule; one of them, the body
limit, also decides a case no vector reaches.

**`canonical-content.md` §2 step 1** works on the text step 0 produced, never on bytes: under a
UTF-8 or a UTF-16 label a byte order mark in that encoding is the character `U+FEFF` by then,
and it is removed at position 0 only; under any other label those bytes are content. The
warning for a UTF-16 part is a log line and changes nothing that is hashed.

**`canonical-content.md` §2 step 4** writes the trim set out — what `String.prototype.trim()`
removes, and nothing else — instead of showing `text.trim()` and `text.strip()` as one rule.
Python's bare `str.strip()` removes a different set (it also removes U+001C–U+001F and U+0085,
and it keeps U+FEFF). §5 and §9.4 trim with the same set.

**`canonical-content.md` §2 Body Size Limit** is 1,048,576 characters counted as Unicode code
points; the constant's name once said bytes. An implementation that cuts UTF-16 code units
differs only for a body over the limit that carries a character outside the Basic Multilingual
Plane before the cut. The publisher's JavaScript implementations — the signer, the portal and
the plugin — still cut code units and are to follow in a later release; until then a message of
that kind they signed does not verify for a reader that follows this rule.

**`canonical-content.md` §8 and §9.2** no longer say more than the construction does: §8 says
which content the hash covers — the normalised fields, and the first 1,048,576 characters of
the body — and that an alteration of that content after signing is detected; §9.2 says a
tampered message does not verify. Nothing in the protocol prevents a change.

**`canonical-content.md` §9.2a point 4** says which parameters are percent-decoded: one written
in segments (`attribute*N=`, `attribute*N*=`, `attribute*=`), never one written without a `*`.

**`canonical-content.md` §13** describes the timestamp vectors by §8 as it stands: no maximum
age for inbound verification, the future guard, and the 24h window of an outbound MTA. The
seven-day inbound window it still named had been gone since inbound verification stopped
expiring.

**`canonical-content.md` §9.5 and `delivered-envelope.md` §3.3.1, §4 and §6.1** drop three
labels the documents never defined; each sentence already says what it refers to, and the one
in `delivered-envelope.md` §4 now points at the exception above it rather than below.

## v1.4 — 2026-10-05 (beta.8): one rule for the customer's action, one sentence for a version

**The relay receives a hash of the attachment's name, not the name** — `signature-input.md`
§6 and §7: the `filename` field of an `attachments` entry carries SHA-256 over the UTF-8 bytes
of the name after trimming, the fallback `unnamed` for an empty name and the client's
lower-casing, written as 64 lowercase hex digits (an optional `sha256:` prefix is accepted).
The relay accepts only `^(sha256:)?[0-9a-f]{64}$` on `/v1/sign` and `/v1/sign-domain`. The
reason is the one §7 already gave for that item: a file name is content about the message.
Decided 13 October 2026.

**A refusal, not a hash computed on arrival.** The relay does not repair a plain name into a
hash: that would need a second implementation of the same normalisation, in another language
whose lower-casing and trimming differ from the client's, and the relay would receive the name
anyway. So the shape is enforced on arrival and nothing else is accepted — the value is checked
exactly as it was sent, with no trimming and no case folding first, so a stray space or an
upper-case hex digit is answered `422` rather than quietly rewritten. The consequence, written
down because it is a real one: a sender without this change answers a `422`, and its message
with a NON-EMPTY attachment does not go out at all — never unsigned, and the person is told
why. The word "non-empty" is exact: metadata is only built for an attachment of non-zero
length, so a message whose attachments are all zero-length sends no `attachments` at all and
goes out signed.

**What does not change.** `n` in the signed content manifest (`canonical-content.md` §9.4) is
still the plain name and is still under the signature; no answer of the relay carries attachment
metadata (§7); and the milter sends no attachment metadata at all, so the shared schema changes
nothing for `/v1/sign-domain` in practice.

**Unicode is not folded.** The NFC and the NFD writing of one visible name give two different
hashes. This stands in §6 so that nobody builds a comparison of names across systems on top of
it.

**`signature-input.md` §6a.1 (new, normative).** What a customer's `on_fail` acts on is
written down as ONE rule and ONE table: it is taken by every message that claims an identity
the relay knows and that cannot be declared valid, and it is not taken when the claimed
identity is unknown or unreadable, nor when nothing was answered at all. That moves two states
across: a `409` and a header block that is not the right shape but names an identity the relay
knows now take `on_fail`, where before they took `on_none` — the action for a message that
claims nobody. Which states are RED is unchanged and is a separate question: a signature that
does not hold for a known identity, and a fingerprint a verifier recomputed itself and that
does not match. Decided 5 October 2026.

**One sentence for a version nobody can work with.** A message announcing a version this
verifier has never heard of, and a `409` from the relay, are shown to a reader with the same
sentence — `Not verified: unsupported ZEKNOP version`. Which of the two it is belongs in the
state field, in the Details a reader can open and in the log, not in the sentence.
Decided 5 October 2026.

**`identity-not-active` is written into §6a's table of what a reader says**: `Not verified:
identity not active`. It is not red — the bytes are the bytes that were signed — and it takes
`on_fail`, because the relay knows the identity and cannot declare the message valid.
Decided 5 October 2026. The relay's side of it is unchanged: `reason` has
carried the word since contract 1.8.

## v1.4 — 2026-09 (beta.2; the cutover)

**The signature is made over more than the content hash** — `signature-input.md` §2:
a separator, the version, the algorithm, the strict content hash and the free text
hash, each preceded by its length. A message that announces `X-ZEKNOP-Version: 1.4`
carries `X-ZEKNOP-Sig-Alg` and is verified over that input; a message that does not is
verified over the strict hash alone, exactly as before (§4), so every message signed
until now still verifies. The registry of algorithm names is §3: `ed25519` is the only
one signed with today, four more are reserved, an unknown one is "unsupported
algorithm" — never green, never a crash. The identity record carries the algorithms and
the history of public keys with their validity, so a message is verified with the key
that was valid when it was signed (§5), and a re-issue does not make earlier messages
red.

**Canonical content, §2 step 0 (new, normative).** How a declared charset and an RFC
2047 encoded word are READ is now part of the specification rather than a property of
whichever library each implementation happened to use: the WHATWG index data, pinned
and committed, in one generated decoder per runtime. An unknown label reads as UTF-8;
it is never a failure and never a deferral. Step 3 names the set of characters that end
a line (the set the production signer uses), which Python and JavaScript had been
reading differently. §5 carries the encoded-word algorithm in full.

**Canonical content, §2b (new).** The free text form — the second hash under the
signature: the displayed text without our envelope, HTML flattened to text, every run of
whitespace to one space, trimmed, NFC, UTF-8, SHA-256. It is what a verification from an
ordinarily forwarded copy is compared against. Five implementations, one
generator, tables pinned to Unicode 15.1.0.

**Canonical content, §9.5 rewritten.** What leaves the milter, in the words of
`delivered-envelope.md` §2, §4 and §5: the positive envelope wherever it can be written,
signed without it where it cannot, `FAIL_POLICY` for a message that cannot be signed, and
no setting that produces a third delivery.

**Delivered envelope (`delivered-envelope.md`, new in v1.4, amended here).** §3.1
the positive envelope and its token, which from v1.4 is `{v: 2, uuid, hash}` and carries
no signature; §6.1 the outer envelope is recognised at the head and the tail of a part
and never searched for inside it; §6.2 a signer takes only POSITIVE envelopes out of a
reply, and only lines that are exactly the shapes a signer has delivered — a quoted
not-verified envelope and a sentence of the sender's own that merely names our host both
stay.

**What this means for mail already signed.** A message signed before the cutover
verifies unchanged. A verification link made before it works unchanged. A signer, a
verifier and the relay all have to move together on the day the input changes, which is
why the deployment order is relay, verifiers, signers.

## v1.3.1 — 2026-09-09

**§9.5 Milter scope — rewritten.** The postfix-milter now signs Shape A *and* Shape B.
The old rule ("plain only, MUST NOT implement `parts`, ACCEPT unsigned otherwise")
was written when the milter had no MIME walker; its practical effect was that HTML
and multipart mail — most mail — went out unsigned, while beta ships the Thunderbird
plugin plus the milter. The milter does not carry a second implementation of §9:
it reassembles the wire form from what libmilter hands it and reads it with the
Shield's own MIME walk and canonical builders, imported as a shared library. The section
now also states the fail-closed rules and the delivered envelope (outside the hash,
with the verification-portal link in place of Haraka's "forward it to" line).

**§9.3 — line endings of a raw-bytes leaf, made explicit.** `attachment`, `inline`,
`rfc822` and `opaque` entries hash the bytes AS DELIVERED (CRLF wire form). The rule
was implicit in "the decoded content bytes, raw" and the Haraka signer read it the
other way: its parser hands it an LF-normalised copy (the CR is stripped per line on
the way in and re-inserted on the way out), so a forwarded message was signed with a
hash no verifier could reproduce — signed, then red at the Shield. Fixed in the Haraka
plugin; the spec now says which bytes count.

**§12 Implementation Checklist — completed and made honest.** A box is ticked only
where a test holds an implementation to the rule. Four rules are deliberately left unticked
because nothing pins them today (BCC exclusion, verifier-side timestamp validation,
the 24-hour outbound age limit, and `../vectors/timestamp-vectors.json`, which no
test reads).

## v1.3 — 2026-08-09

The `parts` manifest (§9) replaces the v1.2 `attachments`/`html`/`inline` fields;
`message/rfc822` becomes an opaque leaf for every implementation; shape selection is
structural (§1.1). Decided 2026-08-08.
