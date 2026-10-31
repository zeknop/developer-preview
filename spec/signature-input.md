<!-- Developer Preview copy of the ZEKNOP Signed Email specification. -->
**`signature-input.md`** — what is signed. Version 1.4 and 1.5 (the source header carries no date).
Publisher: Zeknod OÜ. Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
Source digest (SHA-256 of the file this copy was made from): `0099806af5699c6c219363a8cb3c6120a9e87c25d64210be0cd1acd30fdceadc`.
This copy differs from that file in this header, in the one section it leaves out (§9, with a
note where it stood), and in the reference rewrites described in [README.md](README.md): a
pointer to something a reader outside the publisher's repository cannot open becomes a pointer
inside this package or is dropped. No normative sentence of what it keeps is changed.
Under this header stand notes from the publisher, marked as such: new text, normative
for nothing, each about one sentence of this document.

---

**Notes from the publisher on this copy.** They are not part of the specification and no
rule is changed by them. Each one names a sentence of this document that a reader outside
the publisher's repository can read two ways, or that rests on something this package does
not carry, and says which reading the implementations are held to and where in this package
you can check it.

* **On the word “measured”.** Where this document says something was measured, the measurement
  is the publisher's and its evidence is not part of this package. What you can rerun here is
  `../vectors/` — every file, with `../vectors/validate_vectors.py` and each generator's
  `--check` — and `../vectors/differential/cases.json` through either example client.

---

# ZEKNOP Signature Input and Algorithm Identifier (v1.4, v1.5)

Status: normative from `X-ZEKNOP-Version: 1.4`. Signers of the current build write
`X-ZEKNOP-Version: 1.5`.
Companion of `canonical-content.md` (what is hashed) and `delivered-envelope.md`
(what the reader sees). This file says what a signature is made **over**, and how a
message names the algorithm that made it.

Until v1.4 a signature was made over the strict content hash on its own: thirty-two
bytes, with nothing around them. Nothing in the message said which algorithm produced
the signature, so the algorithm could not be part of what the signature protects, and a
later change of algorithm would have needed a cutover with no way to tell the two kinds
of message apart. v1.4 puts the version and the algorithm identifier **under** the
signature.

---

## §1 The headers

| Header | From | Value |
|---|---|---|
| `X-ZEKNOP-Version` | every signed message | `1.4` or `1.5` for messages signed under this file |
| `X-ZEKNOP-Sig-Alg` | **mandatory** from version `1.4` | a name from the registry in §3 |

**The versions of the input** (`INPUT_VERSIONS`, one list in five files), oldest first:

| Version | Written by | What else it says about the message |
|---|---|---|
| `1.4` | the beta.4 signers | §6.1 takes the visible envelope off a `text/plain` part |
| `1.5` | the signers of this build | §6.1 takes it off a `text/html` part as well (`delivered-envelope.md` §3.3, §6.1) |

A message whose `X-ZEKNOP-Version` is neither of them does not carry `X-ZEKNOP-Sig-Alg`
and is read by §4.

A message that announces one of them and carries **no** `X-ZEKNOP-Sig-Alg`, or carries
it **more than once**, is not verifiable: there is no single algorithm to put into the
signature input. It is never green.

**Why 1.5 exists.** The version is what tells a reader HOW to read the message before it
hashes it. Version 1.5 changed that reading — a signed HTML part now carries our block
at its two ends, and §6.1 takes it off before hashing. A reader built for 1.4 does not, so
it would hash the block along with the sender's document, find a fingerprint that does not
match, and report a message nobody touched as changed. The new value is what lets such a
reader say "I cannot read this" instead (§4), which is the whole of the difference.

## §2 The signature input (normative)

    signature input =
        "ZEKNOP-SIG"                 10 bytes, fixed, no length prefix
        len(version)     1 byte  ||  version    as UTF-8
        len(algorithm)   1 byte  ||  algorithm  as UTF-8
        len(strict hash) 1 byte  ||  strict hash    raw 32 bytes
        len(free hash)   1 byte  ||  free hash      raw 32 bytes

* **Order is fixed**: separator, version, algorithm, strict hash, free hash.
* **Every field after the separator carries its own length** as one unsigned byte.
  Without the lengths, version `1.4` with algorithm `ed25519` and version `1.4e` with
  algorithm `d25519` would be the same string; with them they are two. A field longer
  than 255 bytes cannot be expressed and the signature is refused rather than truncated.
* **The algorithm name is measured in bytes**, not characters, and may be any UTF-8 text.
  Nothing here assumes it is ASCII.
* **The hashes are raw bytes**, not base64: the 32 bytes of SHA-256. The headers and the
  API carry them base64-encoded, as every other hash in this specification does; they are
  decoded before they enter the input.
* **The strict hash** is the content hash of `canonical-content.md` §1–§2. It does not
  change in v1.4.
* **The free hash** is SHA-256 of the free text form of `canonical-content.md` §2b.

Worked example, version `1.4`, algorithm `ed25519`, strict hash `H1`, free hash `H2`:

    5A 45 4B 4E 4F 50 2D 53 49 47   "ZEKNOP-SIG"
    03 31 2E 34                     3 "1.4"
    07 65 64 32 35 35 31 39         7 "ed25519"
    20 <32 bytes of H1>
    20 <32 bytes of H2>

Vectors: `../vectors/signature-input-vectors.json`, assembled from this section by
`../vectors/signature_input_vectors.py` and never from the relay.

## §3 Algorithm registry (normative)

| Name | State | Meaning |
|---|---|---|
| `ed25519` | **signed** | the only algorithm signatures are made with today |
| `ml-dsa-44` | reserved | taken, nothing signs with it |
| `ml-dsa-65` | reserved | taken, nothing signs with it |
| `slh-dsa-sha2-128s` | reserved | taken, nothing signs with it |
| `ed25519+ml-dsa-65` | reserved | taken, nothing signs with it |

The value is the field body with the whitespace around it removed — what unfolding leaves,
and what every reader of these headers sees — and it is then compared **byte for byte and
with regard to case**: `ED25519` is not `ed25519`, and `ed25519x` is not either. The
spacing is not part of the value, so `ed25519  ` is still `ed25519`.

Three states, and every value a sender can write falls into one of them:

* **signed** — the verifier has an implementation; verification proceeds.
* **reserved** — the name is known, no implementation exists. The verifier says
  **unsupported algorithm**. Never green.
* **unknown** — anything else. The verifier says **unsupported algorithm**. Never green,
  and never an error the verifier does not survive: the value came off a header.

## §4 Messages that do not announce a version of this input

A message without `X-ZEKNOP-Sig-Alg`, or with a version outside the table in §1, is read
as `ed25519` over the **old** input: the strict hash on its own, with no separator, no
version, no algorithm and no free hash. Every message signed before v1.4 is such a
message and goes on verifying unchanged.

A verifier that meets a version it does not know — a later one than it was built for —
says so and is not green. It does **not** fall back to the old input for it: falling back
would make "name a version that does not exist" a way of asking for the weaker check. The
old input belongs to a message that names no version at all, or one from before v1.4.

**Which versions are "from before v1.4":** `1.0`, the version every signer wrote until this
one, and no version header at all. Every value that is neither one of those nor one of the
input versions of §1 is a version the verifier does not know.

**A version is not a number.** Nothing here parses or compares numerically: the value is
matched against a list. `1.4.0`, `1`, `1.41` and `v1.4` are therefore all unknown versions,
not older or newer ones, and reading them as "older" would make naming a version that does
not exist a way of asking for the weaker check.

**What the verifier says** (normative from v1.4). A message this verifier
cannot READ is not a message somebody changed, and must never be reported as one. The verdict
therefore has its own value, alongside the one for an algorithm the verifier has no
implementation for, and the reason names the version:

| surface | value | reason |
|---|---|---|
| the Shield | `X-ZEKNOP-Content-Verified: unknown-version` | `X-ZEKNOP-Content-Verified-Details`: not verified, the version the message announces, the newest this verifier reads, and that a newer verifier can check it |
| the portal | its own card, NOT the red one — the amber one it already uses for an algorithm it cannot check | the same sentence, with the version the message names and the newest one this page reads |
| the extension | (from the release that introduced 1.5) | |

The trust tier is `unverified` and a customer policy that does not name the status treats it
as a failure. Decided before the content is read, so the verdict cannot be about the content.

This is not a downgrade path for a message that announces one of these versions. The version
is inside the input, so a signature made under §2 does not verify against the old input — and
for the same reason a `1.5` signature does not verify as `1.4`: the two are different inputs,
and a header edited from one to the other simply fails. A message whose version header is
edited down to `1.0` — with or without the algorithm header — fails as well. There is nothing to choose between: the message says which input it wants, and
only one of the two can be right for a given signature.

### §4a A verifier older than the message (the cutover)

The day the signers begin writing v1.4 there are verifiers in the world that were built
before it. Our own — the Shield and the portal — are deployed first; the Thunderbird
extension sits in other people's profiles and version 1.1.0 will meet v1.4 mail.

Such a verifier asks the relay the only way it knows: the identity, the signature, the hash
it recomputed and the timestamp. Nothing in that question names a version. Read by §4 it is
a question about the old input, the answer is "this signature does not match", and every one
of those verifiers shows that to the person as a **failure of the message** — which is
wrong: the message is sound, the verifier is older than it. A verifier of THIS build that meets
the refusal says one fixed sentence for it instead of its own error text, the same sentence it
says when it is itself too old to read a message (§6a.1).

So the question is **refused** rather than answered, whenever the relay's own record says
this exact signature was made under v1.4 over exactly this hash. The caller's own error path
then says what it says for a relay it cannot reach: "could not verify". Measured: the
extension shows its grey shield and "Could not verify" instead of the red
one; the portal shows its error screen instead of "Verification Failed"; the Shield still
writes `X-ZEKNOP-Content-Verified: fail`, now with the reason in its details field — it has
no third answer between `pass` and `fail`, and it is ours to deploy first.

**A refusal is not the only answer that is not a verdict.** §6a and the `reason` field of
1.8 name the others: an identity the relay does not know is `unknown-identity` and never the
red "changed", however the answer arrives (a `404`, or a `200` body that names it).

**Which caller.** A current verifier also asks the old way — when the version field has been
taken **off** a message, or edited down to `1.0`. That message must stay red: something
touched it. The two questions are identical on the wire, so the request carries one more
field, `understands`, which says the newest signature input the **caller** can build,
whatever the message announces. Every verifier of this build sends the newest version of §1;
a verifier written before v1.4 cannot send the field at all.

**The refusal is per version, not per field** (normative from v1.5). The relay compares what
the caller says it can build with the version **its own record** names, and refuses when the
caller is behind it. Three cases, and the middle one is why the field was given a value
rather than made a flag:

| the record | `understands` | answer |
|---|---|---|
| `1.4` | absent | refused — a verifier from before the field |
| `1.4` | `1.4` | **answered**: this caller can read the message, so a red verdict is about the message |
| `1.5` | `1.4` | refused — a beta.4 verifier meeting mail from a beta.5 signer |
| `1.5` | `1.5` | answered |

A value the relay does not know — a version from before the identifier, a name it has never
seen, an empty string — counts as "cannot build it". Being wrong that way costs the caller a
"could not verify"; being wrong the other way costs a red verdict about a sound message.

So §4a never weakens §3: a v1.4 message whose version header was edited is still answered
"this signature does not match" to every current verifier, and is red. Only a caller that
cannot read v1.4 at all is refused instead — and it had no way of telling the two apart.

**The contract (normative from v1.4, extended per version in v1.5).** `understands` is an optional field of `POST /v1/verify` whose value is
the newest signature input the CALLER can build — the newest version of §1 for every verifier
of this build, absent for one written before the field. The refusal is **HTTP 409** with the
reason in `detail`, which names the version the record was made under; it is not
`valid: false`, so a caller that reads only `valid` cannot mistake it for a verdict about the
message. A caller is never refused under §4a about a version it says it can build, whatever
the message says. Third parties: none at the time of writing; a client written against 1.3
keeps working for every message signed before the cutover and receives 409 — never a false
red — for one signed after it.

Three things this deliberately does not do:

* it does not touch a message someone **really changed**. The record is matched on the hash
  as well as the signature, so a changed message does not match it and keeps the old answer:
  an old verifier that cannot read v1.4 can still read a hash that does not match, and that
  warning is worth keeping.
* it does not outlive the record. Once a signature record is past its retention (§7) there
  is nothing to match and the answer is the old one again. It is a measure for the cutover,
  not a permanent contract.
* **it does not reach a verifier that never asks.** §4a works on the question a verifier
  puts to the relay. Where an old verifier recomputes a fingerprint that differs from the one
  in the header, it has already decided — locally, before the relay is in it at all — that
  the message was changed. See below.

### §4b Where §4a cannot reach, and what that costs

Version 1.4 changed two things at once: WHAT a signature is made over (§2), and HOW a
message is read before it is hashed (§2 step 0, §5). §4a answers the first. The second has
no answer at all, and it is written down here rather than discovered on the cutover.

Where the old reading and the new reading of a message differ, an old verifier recomputes a
different fingerprint from the one the message carries, and its own local rule fires first:
`analysis.hash !== zeknop.hash` in the portal, `computedHash !== headerHash` in the
extension, the content-hash comparison in the Shield. All three call that **changed**, about
a message nobody changed — and the relay, which is the only thing §4a can speak through, is
never asked.

Measured against messages this build has just signed:

| the message | Shield | portal | extension |
|---|---|---|---|
| anything whose reading did not change | `fail`, reason names the version | error screen | grey, "Could not verify" |
| a Subject with an encoded word the two readings disagree on | `fail`, **content hash mismatch** | **"Content Modified"** | **red, "Content modified after signing"** |
| an 8-bit Subject | `fail`, **content hash mismatch** | **"Content Modified"** | **red, "Content modified after signing"** |
| a body carrying U+2028 or U+2029 | `fail`, **content hash mismatch** | error screen | grey, "Could not verify" |

The last row is one-sided because the line-end set was unified TO the JavaScript one
(`canonical-content.md` §2, step 3): the Shield's reading moved, the portal's and the extension's did not.

Nothing in this version closes it. The signer cannot go back to the old reading without
undoing §5, which is what this version exists to fix, and the relay is not consulted. What
bounds it is the **deployment order** — the verifiers before the signers — which is why
that order is a condition and not a preference.

### The second cutover (1.4 → 1.5)

Version 1.5 does the same thing again, and the same limit applies again — but not
evenly, because since v1.4 two of the three surfaces read the version BEFORE they
read the content (§4), and the third does not yet.

| the message, announcing 1.5 | Shield beta.4 | portal beta.4 | extension 1.2.0 |
|---|---|---|---|
| plain text, untouched | `unknown-version` (§4, decided before the content) | its amber card, the version sentence | grey, "Could not verify" — the relay refuses the question (§4a) |
| **with an HTML part** | `unknown-version` | `unknown-version` | **red, "Content modified after signing"** |

The last cell is the whole of the residual risk of this cutover, and it is worth stating
plainly. The extension of that build has no verdict for a version it cannot read (the
unknown-version verdict of §4 reached the Shield and the portal with v1.4 and the
extension only with 1.5), so it
recomputes the fingerprint first, hashes the block §3.3 puts in the HTML part along with the
sender's document, and calls the message changed. The relay is never asked, so §4a cannot
speak.

**What that means for the order.** The Shield and the portal are ours and go first, so they
are covered by the ordinary rule. The extension is not ours to deploy — it sits in other
people's profiles — so "verifiers before signers" is not enough for it: an extension that
has not been updated will be red on HTML mail from a signer that has. Either the update
reaches the profiles before the signers move, or the HTML block waits for a second step, or
the red is accepted for the beta and written into the runbook. That is a deployment decision
and it is named here so it is made rather than discovered.

## §5 The identity record (anti-downgrade)

A signature that verifies proves the key. It does not, on its own, prove that the mailbox
or domain the key belongs to ever agreed to sign with the algorithm named in the message.
The relay's identity record closes that:

* the record carries, for each identity, **which algorithms it signs with and since when**;
* and the **history of its public keys**: each key with the algorithm it is for, the time
  it became valid and — once it is replaced — the time it stopped being valid for new
  signatures.

A key that is replaced is **not deleted**. Its validity is closed, and messages signed
before the replacement go on verifying against it afterwards: verification uses the key
that was valid **at the time the message was signed**, not the newest one.

A v1.4 message whose algorithm the identity record does not list — or lists only from a
time later than the message's own timestamp — is **red**, whatever the signature says.

The algorithms of an identity are derived from its key history: an identity signs with
algorithm A since T exactly when it has a key for A valid from T. One record, so the two
cannot drift apart; a claimed algorithm with no key behind it is not a state the relay
can reach.

## §6 The API

`POST /v1/sign` — the signer sends `version`, `alg`, `content_hash` (strict) and
`free_hash`; the relay builds the input of §2 **itself** and signs it. The signer never
hands the relay the bytes to sign: if it could, the algorithm identifier under the
signature would be worth no more than the header above it. The answer carries the
algorithm it used alongside the signature and the envelope id.

`POST /v1/sign-domain` — the same, for a milter.

`attachments` is optional and is sent only when the message carries at least one attachment. Each entry has `hash` (SHA-256 of the raw bytes, standard base64), `size`, `mime` and `filename`. Since v1.4.0-beta.10 the `filename` field carries a hash of the name, not the name: the UTF-8 bytes of the name after trimming, the fallback `unnamed` for an empty name, and the client's lower-casing — no Unicode normalisation, so the NFC and NFD forms of one name give two different hashes — hashed with SHA-256 and written as 64 lowercase hex digits (an optional `sha256:` prefix is accepted). The relay accepts only `^(sha256:)?[0-9a-f]{64}$` on `/v1/sign` and `/v1/sign-domain` and answers 422 to anything else. The reason is the one §7 gives: a file name is content about the message. The `n` field of the signed content manifest (canonical-content.md §9.4) is not affected.

`POST /v1/verify` — the verifier sends `version`, `alg`, `message_hash` (strict) and
`free_hash`; the relay rebuilds the same input, checks the algorithm against the identity
record (§5), picks the key valid at the message's timestamp and verifies. A request
without `version` and `alg` is read by §4, which is what every verifier of an older
message sends. It also sends `understands`, the newest input the caller can build; a
request that does not, about a signature this relay recorded as v1.4, is answered **409**
and not `valid: false` (§4a, the contract paragraph there).

`GET /v1/verify/{uuid}` publishes the identity's public key **with its algorithm** and
the validity of each key it has had. Publishing the whole history, and not only the current
key, is what lets someone check a signature themselves instead of taking this relay's word
for it: without the window each key was valid in, a message older than the last re-issue
cannot be checked by anyone but us. The cost is that the dates of the re-issues are public
metadata about the identity; the endpoint is unauthenticated and rate limited, and the uuid
is in the headers of every message the identity signs.

`GET /v1/capabilities` — which versions of this input the relay can **sign** and can
**verify**, as two lists, plus the number of the HTTP contract it serves. It is the
question a SIGNER asks before it writes a version header, and the answer is a property of
the build, not of the moment: it does not depend on whether a datastore is reachable.

A relay that does not answer it with those lists — `404`, any other status, a body that is
not a JSON object, a `signs` that is not a list of strings — **cannot sign that version**.
That is not a guess about an old build; it is the only safe reading. A relay from before
this endpoint signs a request naming a version it never heard of by ignoring the three
fields and making the signature it has always made (§4). The message would then leave with
`X-ZEKNOP-Version: 1.5` above a signature made over the older input, and every verifier
would call it invalid — a red verdict on a message nobody touched, permanent, for as long
as the message exists.

So the rule is on the SIGNER's side and it is one sentence: **a signer writes a version
only while the relay it is about to ask says it can sign that version.** The signer asks
at start and refreshes at most once every 5 minutes; a cached answer expires, and an
expired answer is not an answer — a relay rolled back under a running signer stops being
believed within one refresh interval, and cannot be believed by a failed refresh. When the
answer is missing, stale or negative the message is simply **not signed**, and the
delivery is the one §5 of `delivered-envelope.md` already describes for a message
this signer cannot sign: `defer` (451, the sender's server tries again) or `notice`. The
message is never delivered bare and never delivered with a version its signature was not
made under.

**The price of asking, and it is accepted.** The
refresh is serialised: while one ask is in flight the others wait for its answer rather than
each making their own. During an outage that means the signers of one deployment make ONE
`GET /v1/capabilities` at a time, and a message that arrives while an ask is waiting out its
timeout waits with it. That is slower than asking in parallel, and it is the behaviour that
was chosen: a relay that has just come back under load must not be met with one ask per
message, and a signer that answered faster by asking more would be deciding to sign on a
stale answer. What the waiting message costs is a delay; what a stale answer costs is a red
verdict on a message nobody touched, for as long as the message exists.

### §6a What a verifier does with each answer (1.8)

A verifier has exactly two safe directions, and the answer decides which one. Until 1.8 it
had one: anything that was not a verdict was read as an outage and the message was held.
That cost mail. A relay that answers the same way however often it is asked is not an
outage, and a message held for it is held for ever.

**The shape of the signature material is the verifier's own question.** Before it asks
anyone, the verifier checks that the header block is the right shape: all four fields
present, `X-ZEKNOP-Hash` base64 of a 32-byte digest, `X-ZEKNOP-Signature` base64,
`X-ZEKNOP-UUID` a UUID, `X-ZEKNOP-Timestamp` an ISO 8601 instant. The length of the
signature is **not** checked: it belongs to the algorithm, and §3 reserves names for
algorithms a reader has never seen. A block that is not the right shape is **delivered**
with `Not verified: malformed ZEKNOP headers`; the relay is not asked about it.

**Delivered with the reason** — the relay answered, and will answer the same way again:

| answer | what the reader says |
| --- | --- |
| `400`, `422` | `Not verified: malformed ZEKNOP headers` |
| `404`, or a 200 body with `valid: false, reason: "unknown-identity"` | `Not verified: unknown identity` |
| `409` | `Not verified: unsupported ZEKNOP version` |
| a 200 body with `valid: false, reason: "identity-not-active"` | `Not verified: identity not active` |

Which of these a customer's policy acts on is §6a.1 below, and it is not the same question
as which of them is red.

**Deferred (451), because nothing was answered at all:** no connection, a timeout, `5xx`,
`429`, a body that is not JSON or that names no verdict — and `401`/`403`, which is the
verifier's own credential being wrong. That last one is deliberately on this side: read as
a statement about the message, one mistyped secret in one deployment would mark every
message of every customer as not verified.

**What the relay sends (normative from 1.8).** Every `valid: false` answer of
`POST /v1/verify` carries `reason`, one word naming which kind of "no" it is:
`signature-mismatch`, `unknown-identity`, `identity-not-active`, `unsupported-version`,
`unsupported-algorithm`, `algorithm-not-in-record`, `free-hash-missing`,
`signature-input-not-buildable`, `timestamp-in-future`. A positive answer carries none, and
the absence of one on a negative answer means the relay is older than 1.8 — a reader of this
build then falls back to what it did before, which is to read the `message`.

`unknown-identity` and `signature-mismatch` are the pair the distinction exists for, and they
reach a reader two ways that must read the same: a `404`, and a `200` body that names
`reason: "unknown-identity"`. The relay answers the second from `POST /v1/verify`; the `404`
is what a relay without a record for the route, or `GET /v1/verify/{uuid}`, gives. Until 1.8
both arrived as `valid: false, message: "Verification failed"`, which every reader showed as
the red "changed" — a sound message reported as changed, and, under a customer's
`on_fail: reject`, thrown away, for no reason but that this relay had never been told who the
sender is. Decided 3 October 2026.

An identity that is revoked or not active is deliberately NOT red either: the signed content
is the content that was signed, so nothing the signature covers was changed. What a reader
says about the sender is its own business; what it may not say is "this message was changed".

**The red verdict has one source:** `valid: false` for an identity the relay HAS, with
`reason: "signature-mismatch"` — or a fingerprint a verifier recomputed itself and that does
not match the one the message carries. Nothing else turns a badge red: nothing else read the
content, so nothing else may say a message was changed. The portal host in a delivered
envelope is the portal host of the given deployment (§3).

### §6a.1 One rule for the customer's action

**What a customer's `on_fail` acts on is a DIFFERENT question from what turns a badge red,
and until 5 October 2026 it was answered three ways in two files.** The two were written as
one rule, so a `409` between two of our own services, and a header block a sender wrote
crooked, were delivered with the customer's `on_none` — the action for a message that claims
nothing at all — while a version THIS reader could not read took `on_fail`. A customer who
writes `on_fail: quarantine` is not asking "was this changed". The question is "may I treat
this as mail from that sender", and the answer is no for every message that claims an
identity this relay KNOWS and that cannot be declared valid. Decided 5 October 2026.

**The rule.** `on_fail` is taken by every message that claims an identity the relay knows and
that cannot be declared valid. It is NOT taken when the claimed identity is unknown or
unreadable — there is no sender to act on — and not when nothing was answered at all.

| state | what the reader says | red? | the customer's action |
| --- | --- | --- | --- |
| `pass` | `Sent from mailbox <address>, unchanged` / `Sent from domain <domain>, unchanged` | no | delivered |
| `fail` | the relay's `signature-mismatch`, or a fingerprint this reader recomputed and that does not match | **yes** | `on_fail` |
| `identity-not-active` | `Not verified: identity not active` | no | `on_fail` |
| `unknown-version` | `Not verified: unsupported ZEKNOP version` | no | `on_fail` |
| `unsupported-algorithm` | `Not verified: unsupported signature algorithm` | no | `on_fail` |
| `unsupported-version` (`409`) | `Not verified: unsupported ZEKNOP version` | no | `on_fail` |
| `malformed`, the claimed identity readable and known | `Not verified: malformed ZEKNOP headers` | no | `on_fail` |
| `malformed`, the claimed identity unreadable or unknown | `Not verified: malformed ZEKNOP headers` | no | `on_none` |
| `unknown-identity` (`404`, or the 200 body that names it) | `Not verified: unknown identity` | no | `on_none` |
| `unsigned-notice` | `Not signed: the message carries the notice that it could not be signed, nothing to verify` | no | `on_none` |
| `none` | the message claims nothing | no | `on_none` |
| nothing was answered | nothing is marked; the message is held (`451`) | — | no policy is evaluated |

Each state is one row and one row only, and the reader's sentence is fixed: a customer may
have a rule on it, so the same words appear in `X-ZEKNOP-Content-Verified-Details`, in the
customer's policy tag, on the portal and in a deployment's checking service for forwarded
copies (§9, which is not part of this preview).
The `pass` row gives the words the Shield writes at this release. They say "unchanged" without
a qualifier, and the word means the signed content (`canonical-content.md` §1) and nothing
else. The portal's green title says it in full: `Sent from mailbox <address>, signed content
unchanged` / `Sent from domain <domain>, signed content unchanged` (`delivered-envelope.md` §8).
The checking service answers a different question in its own words.

**Why a malformed block is two rows.** A block that is not the right shape is the verifier's
own finding, made before anyone is asked (above), so by itself it says nothing about who sent
the message. When the `X-ZEKNOP-UUID` is not a UUID at all there is no identity to ask about
and the message is treated as one that claims nobody. When it IS a UUID, the verifier asks the
relay the public identity question (`GET /v1/verify/{uuid}`, §7) and nothing else: a `200`
means this relay knows that identity, and a message claiming a known identity with material
this crooked is one the customer may act on; a `404`, or a lookup that could not be made at
all, leaves the softer action. The message is DELIVERED either way, with the same sentence —
only the customer's action differs — and a lookup that fails never turns a delivered message
into a held one.

**One sentence for a version nobody can work with.** Two states reach a reader as "this
version cannot be worked with": the message announces a version THIS verifier has never heard
of (`unknown-version`, decided locally, §4), and the relay answers `409` because the record
was made under a version the CALLER did not say it can build (`unsupported-version`, §4a).
A reader is shown one sentence for both — `Not verified: unsupported ZEKNOP version` — because
the two are the same fact to the person: nobody in the chain could read it, and the message is
not at fault. Which of the two it is belongs in the Details a reader can open and in the log,
never in the sentence: `X-ZEKNOP-Content-Verified` names the state, the log line says it in
words, and a surface with a Details area prints it there. Decided 5 October 2026.

**`401`/`403` is not one of these rows.** It is the verifier's own credential being refused,
so it stays on the held side (above) — and it is logged at ERROR naming the setting that is
wrong, because it is not an event in a working deployment: it is the deployment not working.
Decided 5 October 2026.

### §6b The activation code (normative, 1.8)

Until 1.8 this document described no part of `POST /v1/activate`; what follows is the
normative half of its contract.

An **activation code** is the only way an identity is created while registration is
invite-only. The operator issues it on the relay with an operator-only route that is not
part of the public API, hands it to the applicant out of band, and the applicant redeems
it once at
`POST /v1/activate`. The code IS the invite: `PUBLIC_REGISTRATION_ENABLED` does not gate the
redemption, and `POST /v1/register` stays closed to a self-service applicant regardless.

**Shape.** Four groups of four characters from `A-Z0-9`, joined by `-`:
`XXXX-XXXX-XXXX-XXXX`. Sixteen characters of a 36-character alphabet, about 83 bits. A request
whose `code` does not match that shape is refused by the schema (`422`) and no lookup happens.
Comparison is case-insensitive (the relay upper-cases before hashing); the separators are
required.

**What the relay keeps.** The SHA-256 of the plain text, never the plain text. A code that is
lost is reissued; it cannot be recovered or extended.

**Single use.** A redeemed code is never redeemable again.

**Expiry.** Every code carries the moment it stops being redeemable, written into its row at
issuing from the deployment's `ACTIVATION_CODE_TTL_DAYS` (default 7 days). Changing that
setting MUST NOT move a code that already exists. A code with no such moment MUST be refused,
not treated as a code without a limit.

**What a caller is told.** Exactly three answers distinguish nothing:

| state of the code | answer, on an attempt that crosses no budget |
|---|---|
| unknown (never issued, or the hash does not match) | `404 Invalid or already used activation code` |
| already redeemed | `404 Invalid or already used activation code` |
| issued, never redeemed, expiry passed | `404 Invalid or already used activation code` |

The three MUST be indistinguishable to the caller, status and body alike. A distinct status
for the third (`410`, say) would tell a caller that one of its guesses was a real code, which
is the single fact the attempt budgets exist to withhold. The relay MUST write the difference
into its own log instead: the marker `activation_code_expired` with the code's id, its expiry
and the moment of the attempt; a code the relay does not hold gets the matching marker
`activation_code_unknown`.

**Indistinguishable on EVERY attempt, not only on that one.** Each of
the three counts as a failed redemption, and the attempt that CROSSES one of the budgets below
is answered `429 Too many failed activation attempts. Try again in 15 minutes.` rather than the
`404`: it has already been looked up, and a caller at the ceiling is better told to wait than
told its code was wrong. Which answer that is MUST depend on the budgets alone and never on
which of the three states the code was in. A relay that answered `404` for an expired code on
the attempt where an unknown code is answered `429` would hand a guesser exactly the fact the
table above withholds, by way of the budget that exists to withhold it — the guesser only has
to keep going until the refusal changes shape. The table above describes only the attempt that
crosses nothing; when §6b was first written, so did the relay.

**Attempt budgets.** Read BEFORE the code is looked up, never after. Three of
them:

* per caller, 10 redemption attempts an hour;
* per caller, 5 failed redemptions in a 15-minute window;
* per DEPLOYMENT, 200 failed redemptions in a 15-minute window. Crossing it refuses, before
  the lookup, every caller that has already failed in the window, and still serves a caller
  with a clean record — a ceiling that refused everybody would let one guesser lock out the
  customers an operator is handing codes to.

"Per caller" is the caller's **/64** when the caller's address is IPv6, and the address itself
when it is IPv4. A customer is routinely handed a whole /64, so an address-keyed budget bounds
nothing: the guesser never has to reuse an address. All per-caller budgets of this route MUST
use the same scope.

**One address, one spelling.** The caller's address is an address, not
the text it arrived as, and the relay MUST reduce it to one canonical spelling where the
caller's address is determined — before any budget, any other rate limit of this relay, and
the `ip` column a row is stored with:

* an IPv4 client that a dual-stack listener reports as an **IPv4-mapped** address
  (`::ffff:a.b.c.d`) is that IPv4 address, and MUST NOT be read as IPv6. Every IPv4-mapped
  address has the same /64, so reading it as IPv6 would put every IPv4 caller of a deployment
  into ONE budget — one guesser would stop every IPv4 customer redeeming the code it was
  issued, which is a worse hole than the one the /64 closes;
* a **zone id** (`fe80::1%eth0`) names the interface a packet arrived on, not the caller, and
  is not part of the key;
* two spellings of one address (`2001:db8::1` and `2001:0db8:0:0:0:0:0:1`, upper case and
  lower) MUST be ONE key and MUST be stored as one text. When a trusted proxy relays the
  address, the spelling is the caller's own — it is in the header — so a limit that varied
  with it would be a limit the caller steps around by respelling itself.

Deriving the scope from an address MUST NOT fail: it is read before the lookup, so anything
thrown there is a `503` for that caller, and the caller may be choosing the text.

An expired code counts as a failed redemption, like any other miss. A budget that cannot be
read MUST refuse (`503`) before the lookup rather than wave the request through.

## §7 What the relay stores, and what it publishes

For each signature, against its envelope id: the strict hash, the free hash, the identity
(its uuid, and through it the mailbox or domain), the algorithm, the version and the time.
**No content.** The two hashes are what a later verification from a forwarded copy is
compared against (§9, which is not part of this preview); the message itself is never stored, and neither is any
part of its text.

### Nothing is published against an envelope id

The envelope id is printed in the visible envelope of every signed message. Anyone holding a
forwarded copy — or a photograph of one — has it, and `GET /v1/signature/{envelope_id}` is
unauthenticated (the id is unguessable, the endpoint is rate limited). So the rule is not
"the free hash is not published" but **no fingerprint is published against an envelope id**:

| was in the answer | why it is gone |
|---|---|
| the free hash | a fingerprint of text with its whitespace flattened. "Amount due: 100 EUR" is cheap to guess and then confirm. |
| the strict hash | the same, for the exact message: guess From, To, Subject, timestamp and body — a forwarded copy carries all but the body — and check. |
| the signature | the public key is published beside it (§6), so a signature is a fingerprint-checker: guess, recompute, verify. Removing the hashes and leaving this would have closed nothing. |
| the attachment metadata | its per-file hash confirms a file the asker already has; the file name is content about the message, so the relay receives only a hash of the name and refuses a plain name. |

What the answer carries now: the identity (uuid, mailbox or domain, its level and type and
status) and the **time** the signature was made. That is "who signed envelope X, and when" —
no more.

Comparing a forwarded copy is therefore a **question the server answers**, never a
fingerprint it hands out: the check of §9 (not part of this preview) asks "does this text match?" and is told a verdict and
the identity. The asker has to bring the text; nobody can sit at the endpoint and try texts
against a fingerprint they were given.

### What IS public about an identity

`GET /v1/verify/{uuid}` — unauthenticated and rate limited, and the uuid is in the headers of
every message the identity signs:

* every **public key** the identity has had, in full, not only the current one;
* the **algorithm** of each key;
* the window each key was **valid from — valid to** (open for the current one);
* the identity itself: the mailbox or domain, the level and type of verification, when it was
  verified, and whether it is active or revoked.

The whole key history is published deliberately: without the window each key was valid
in, a message older than the last re-issue could be checked by nobody but this relay. The cost
is that the **dates of the re-issues are public metadata** about the identity.

### Retention — decided

The retention period for signature records is **one configuration value**,
`SIGNATURE_RETENTION_DAYS` (default 90), used by the retention scheduler and passed to
the database function it calls, so changing it is a configuration change and not a
code change.

**What that means for a forwarded copy.** A signature record is what a copy is compared
against, so verification **from a forwarded copy** — §9, not part of this preview, where the headers are gone —
is possible for **`SIGNATURE_RETENTION_DAYS` (90) days after the message was sent**, and not
afterwards. After that a message can still be verified, but only **from its source**: the
headers carry the signature, the version, the algorithm and the strict hash, and the
extension, the Shield and the portal all check it from them with nothing stored at the relay
beyond the identity. This belongs in what the check of §9 (not part of this preview) tells a person who pastes an old
forwarded copy: not "this message is bad", but "there is no record of it any more — open the
original and use its source".

The same period bounds §4a: once a record is gone, an old verifier asking the old way is
answered the old way again.

## §8 Version history

| Version | What the signature is made over | What else the version says |
|---|---|---|
| 1.0–1.3 | the strict content hash alone | |
| 1.4 | §2: separator, version, algorithm, strict hash, free hash | the visible envelope is taken off a `text/plain` part before hashing |
| 1.5 | §2, unchanged — only the version field inside it differs | and off a `text/html` part as well (`delivered-envelope.md` §3.3, §6.1) |

1.5 changes nothing about the CONSTRUCTION of the input. It exists because a reader has to
know which reading of the message the fingerprint was taken over, and that is the one thing a
reader cannot work out for itself.

## §9 A copy that was forwarded by an ordinary mail client (the relay's side)

*§9 described the relay's side of checking a copy that was forwarded by an ordinary mail
client, and the trust model of a deployment's checking service. That part is not in this
preview, and the operator's path it uses is not public. The one path of it that a portal reads
without a key, `GET /v1/forward-checks/{envelope_id}`, is part of this preview and is described
in `../api/README.md`.*

## §10 The idempotency key of a signing request

A signer that asked for a signature and lost the answer asks again: the
relay had already signed and written its row, so the second request produced a **second**
signature of the same message. From 1.6 a signer names the request, and a repeat of the same
name inside 24 hours is answered with the **same** signature and the same envelope id, and
writes no second row.

```
POST /v1/sign          Idempotency-Key: <64 lowercase hex>
POST /v1/sign-domain   Idempotency-Key: <64 lowercase hex>
```

* The header is **optional**. A caller that sends none is signed exactly as before — no 409,
  no 400, nothing about the answer changes. Old signers keep working across the deploy.
* A malformed value (not 64 hex characters) is `400`. Ignoring it silently would drop the
  protection without telling anybody.
* A repeat inside 24 hours, from the same identity, with the same key: `200` with the
  `signature`, `envelope_id`, `alg`, `version` and `relay_timestamp` of the first answer —
  the same answer, not a new one — and `signatures_log` keeps exactly one row. Two requests
  that race are settled by the database: the key is unique per identity, and the loser reads
  the winner's row instead of writing its own.
* After 24 hours the same key signs again, as a new message — and the new row carries **no**
  name, so the row that holds it stays the only one that does and the index stays true. The
  window is what the key is valid for, and a signer does not retry a message a day later.
* The answer's `relay_timestamp` is the time written into the signature record, so the repeat
  carries the same time as the first answer. "The same answer" means every field of it.

**Why the database and not Redis.** The promise is "no second row in `signatures_log`", and that is
a property of that table: as a partial unique index on `(uuid, idempotency_key)` it holds even for
two requests that race, even across a restart of the relay, and it is written in the SAME
transaction as the row it guards — either both exist or neither does. Redis would have been a
second store to keep in step with the first: a key written after the commit leaves a window where
the relay signed, the answer was lost and nothing remembers the name, and a key written before it
can name a row that never happened. It also empties on a flush, and the one moment the protection
is needed is the moment something went wrong. The cost of the database is one index and one lookup
per named request, before the rate limit is counted.

**What the key is made of.** The relay never depends on this — to the relay the value is 64
hex characters and nothing else, so a signer can change how it derives them without a deploy
of the relay. What both signers of this build write is:

```
SHA-256( "ZEKNOP-IDEM-v1" 0x00 <scope> 0x00 <version> 0x00 <algorithm> 0x00
         base64(strict hash) 0x00 base64(free hash) )
```

`<scope>` is what the signer knows about the identity: the identity uuid for `/v1/sign`, and
the lowercased sender domain for `/v1/sign-domain`, where the identity is resolved by the
relay from the domain and the milter has never been told its uuid. The relay stores the key
**against the identity it resolved**, so two identities that sign identical bytes never end
up under one key, whatever scope the caller put in. The value is not a secret, and it is not signed
material: it names a request, and the request is authenticated by the API key as before.
