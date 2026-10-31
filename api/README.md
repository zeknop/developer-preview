# The public HTTP contract of a ZEKNOP relay

**Developer Preview — the protocol and the API may change; nothing on this page is a security
guarantee.**

Publisher: Zeknod OÜ. This document is licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
Contract version: **1.8**.

`openapi-public.json` beside this file is the machine-readable shape of the paths listed
below: their parameters, their bodies, their answers and their status codes. It is generated
from the relay's own schema and filtered to those paths: the shape is the schema's, and every
description in it is the publisher's public text, which the generator sets in place of the
server's own wording. It is not edited by hand. This file carries what a schema cannot state: what an answer means, what a
caller may do with it, and which of the relay's answers are statements about a message rather
than about the relay. `API-CHANGELOG.md` says what changed for a caller, and when.

The base URL is the relay you were given; no server is listed in the OpenAPI document on
purpose. Example values in this package are `example.org`, `example.com` and `192.0.2.x`.

## What is here and what is not

Here: the paths a third-party client needs in order to **check a signature** it received or to
**sign** a message through a relay, the paths the verification portal reaches **without a
credential** while doing either, and the paths by which an identity is obtained in a
deployment that onboards without an external identity provider.

Not here, and not part of this preview: administration, billing, tenant configuration, the
keys a mail server signs with, revocation and erasure. A path missing from the list below is
not a path you are expected to call.

## Paths in this file

<!-- paths:begin -->

| Method | Path | What it is for |
| --- | --- | --- |
| POST | `/v1/verify` | Ask whether a signature holds for the hashes of a message, and who signed it. |
| GET | `/v1/verify/{identity_uuid}` | Read the registration state of one identity and every public key it has had. |
| GET | `/v1/signature/{envelope_id}` | Ask which identity signed the message carrying this envelope id, and when. |
| GET | `/v1/forward-checks/{envelope_id}` | List the forwarded copies the deployment's checking service received for this envelope id. |
| POST | `/v1/sign` | Have the relay sign the hashes of a message for an identity whose API key you hold. |
| GET | `/v1/capabilities` | Ask which versions of the signature input this relay can sign and can verify. |
| GET | `/health` | Ask whether the relay can serve requests at all. |
| POST | `/v1/register` | Start a registration and receive the challenge a domain registration has to publish. |
| POST | `/v1/register/verify-domain` | Have the relay look for the domain challenge and activate the identity. |
| POST | `/v1/register/mailbox` | Start a mailbox registration; a link is sent to the address. |
| GET | `/v1/register/verify-mailbox/{token}` | Open the page the link in that mail points at. |
| POST | `/v1/register/verify-mailbox/confirm` | Confirm the link with the request code shown by the client that started it. |
| GET | `/v1/register/mailbox/status` | Collect the credentials of a mailbox registration once its link is confirmed. |
| POST | `/v1/activate` | Redeem an activation code a deployment handed out, and receive the credentials. |

<!-- paths:end -->

## Checking a signature

`POST /v1/verify` asks for **no credential**. You send the identity, the signature and the
hashes; you are answered a verdict and the identity that signed.

**A repeated question is answered, not refused.** The relay marks the triple (identity,
signature, message hash) in its store the first time it is asked, with a mark that lasts 24
hours. A second question about the **same** triple is not served out of that mark: the
signature is verified cryptographically again and the identity is read again, so the verdict
is never taken from the mark. When that verdict is positive the answer is `valid: true` with
`message: "Previously verified"`; when the identity has stopped being active in the meantime,
the answer says that instead. A first question whose verdict is negative removes the mark
again, so a caller that met a transient failure is not locked out of asking.

That is worth saying because it is easy to assume the opposite. The mark is kept per triple,
so it never answers a different question, and it does not spend a signature: a recipient who
verifies a message after somebody else already verified it gets a verdict and not a refusal. A
signature presented with a **different** message hash, or under a different identity, is a
different triple and therefore a first question — it is answered like any other first
question, `valid: false` with `reason: "signature-mismatch"`, and not refused.

The request field `source` and its companion `proxy_secret` are reserved for the operator's
own infrastructure. A third-party caller leaves both unset.

**Which answer is about the message.** `valid: false` carries `reason`, one word for which
kind of no it is. `signature-mismatch` is the only value that says something about the
signed content, and the only one a reader may show as "the signed content was changed". `unknown-identity`
says this relay has no record of that identity, so nothing was checked against anything;
`identity-not-active` says the signature holds and the identity is revoked or not active — the
signed content is the content that was signed. On a negative answer **of `POST /v1/verify`** the
absence of `reason` means the relay is older than contract 1.8. It is never set by
`GET /v1/verify/{identity_uuid}`, which checks no signature: there `valid: false` says only
that the identity is not active, and says nothing about any message.

**The keys of an identity.** `GET /v1/verify/{identity_uuid}` lists them in `keys`, oldest
first. Each has `algorithm`, `public_key` — the raw public key in standard base64 with
padding, for `ed25519` 32 bytes and so 44 characters — and `valid_from` and `valid_to`, ISO
8601 times, `valid_to` `null` while the key is current. `algorithms` lists the algorithms of
those keys.

**Which answers are an outage and which are not.** A `400`, `404`, `409` or `422` is a
deterministic refusal of the question: the relay answered, and it will answer the same way
however often the same question is asked. A caller must not defer a message on one of them —
it holds mail while the recipient is told nothing. No connection, a timeout, a `5xx` and a
`429` are outages; so is a `200` whose body is not JSON or names no `valid`.

## What an envelope id says publicly

The envelope id is 8 alphanumeric characters, printed in the visible envelope of every signed
message. `GET /v1/signature/{envelope_id}` therefore asks for no credential — anyone holding a
forwarded copy, or a photograph of one, can ask it — and it is rate limited per caller
address.

The answer is **who signed and when**: the identity — its `uuid`, its `domain` and its `email`,
which for a mailbox identity is the registered address itself — its verification level and
type, its state, the relay, and the time of the signature. Decide which identity you sign with
in that knowledge: anybody who holds a forwarded copy of a message can read the address it was
signed for, and that is the design, not an accident. It carries **no fingerprint of anything**:
not the hash over the strict form, not the hash over the free form, not the signature, not the
attachment metadata. Each of those would let someone confirm a guess about what the message
said, and the identity's public keys are published next to them. Anything else is 400 for a
malformed id, 404 for an id this relay has no record of, 429 when the limit is spent, and 503
when the store that limit lives in cannot be read.

## Signing

`POST /v1/sign` needs the identity's API key in `X-API-Key`. The relay builds the signed bytes
itself from the version and the algorithm the request names; it never signs bytes a caller
handed it. The request timestamp must be within 30 seconds of the relay's clock.

The optional header `Idempotency-Key` — 64 lowercase hex characters — names the request. A
repeat under the same name from the same identity inside the deployment's idempotency window
(24 hours by default) is answered with the same signature and the same envelope id, and
nothing is signed twice. A malformed value is refused with 400 rather than ignored.

## Status codes, as they are

These are the codes the paths above answer today. They are **not** reduced to one code per
kind of refusal in this release, and a client should read them as they are rather than as a
pattern.

**Where `openapi-public.json` is thinner than the relay.** The generated document carries the
codes each operation *declares*, which is the relay's own schema and is not the whole of what
the relay answers. For nine of the fourteen operations it answers a code it has not declared,
so this table is the correction to the document rather than a second opinion about it:

| Path | Also answers |
| --- | --- |
| `GET /health` | `503` |
| `POST /v1/verify` | `409`, `503` |
| `GET /v1/verify/{identity_uuid}` | `400` |
| `GET /v1/signature/{envelope_id}` | `503` |
| `POST /v1/sign` | `403` |
| `POST /v1/register` | `403`, `409`, `503` |
| `POST /v1/register/verify-domain` | `503` |
| `GET /v1/register/mailbox/status` | `503` |
| `POST /v1/activate` | `503` |

The `409` of `POST /v1/verify` is the one to notice: it is the refusal described under
**Versions** below, and a client with no branch for it reads a refusal as something it is not.
Any path may also answer `500`.

And whatever body shape the document declares for a code, a refusal of these paths is in fact
answered as `{"detail": "<one sentence>"}`. Three answers are not: the `422` of a malformed
request carries the list of refused fields the document declares, the `503` of `GET /health`
carries the health body, and a `500` that comes from an unhandled error carries
`{"error", "message"}` and says nothing about what went wrong. So read `detail`, and treat the
declared error object as the shape it is reserved for rather than the shape you will parse.

What each of the codes means:

- **401** on `POST /v1/sign`: the API key is not one this relay holds for that identity;
- **403** on `POST /v1/sign`: the key is good and the relay will still not sign. Either the
  identity is not active — suspended, or revoked — or the `From` address of the request is not
  one that identity may send as, or the deployment's own policy does not let that identity
  sign, which a domain identity meets on a deployment that lets only some identities sign for
  a domain. The `detail` of the answer says which of them it is;
- **403** on `POST /v1/register` and `POST /v1/register/mailbox`: the deployment keeps
  registration to invited callers and this caller is not one. A sandbox is usually open; a
  production deployment usually is not;
- **400** on `GET /v1/verify/{identity_uuid}`: what the path carries is not a uuid at all, so
  nothing was looked up. An identity this relay has no record of is the `404` below;
- **404** on `POST /v1/sign`: this relay has no identity with a signing key under that uuid —
  it was never registered here, or no signing key of this relay belongs to it. The key was
  accepted, so it is not the `401` above, and it is not the `403` above either: an identity
  this relay does know and will not sign for is that one. This is the one code the document
  declares for the path without saying what it means;
- **404** on `GET /v1/verify/{identity_uuid}` and `GET /v1/signature/{envelope_id}`: no record
  of that identity, or of that envelope id;
- **404** and **429** on `POST /v1/activate`: a code this relay does not hold, a code already
  redeemed and a code past its expiry are answered identically — `404` while no attempt budget
  is spent, `429` on the attempt that spends one. No answer tells you which of your guesses
  was once a real code;
- **409** on `POST /v1/verify`: the version refusal of the section **Versions** below — a
  refusal and not a verdict, and never a statement about the message;
- **409** on `POST /v1/register`: that domain is already registered on this relay;
- **503** everywhere the table above names it except `GET /health`: a store the relay keeps
  its attempt budgets and its replay marks in could not be read, so the request was not
  carried out — nothing looked up, nothing registered, nothing marked. It may be retried, and
  a `500` instead means what a `500` means anywhere else;
- **503** on `GET /health`: one of the datastores the relay cannot serve a request without is
  unreachable. The body names which one. It is the one place on this relay where the status
  code alone is meant to be acted on.

Elsewhere on the relay the same situation — a good key whose identity is not active — is
answered `404` rather than the `403` of `POST /v1/sign`. Those routes are not part of this
document; the difference is recorded here because this release documents the codes as they
are instead of unifying them.

## Versions

`GET /v1/capabilities` answers with two lists: `signs` and `verifies`, the versions of the
signature input this build can construct, oldest first, and `signature_input_version`, the
newest of them. They are the same list in this build — the relay builds one input and uses it
for both — and they are two fields because a caller must not have to assume that: a build that
could still verify a version it no longer signs would otherwise have no way to say so.

**A signer asks before it writes a version.** The reason is a message that cannot be repaired.
A relay older than this route accepts a signing request naming a newer version and signs the
input it has always built, because the version field is optional and an unknown value in it
was never refused. The signature comes back, the message leaves announcing a version its
signature was not made over, and every verifier calls it invalid — permanently, about a
message nobody touched. Such a relay answers `404` here, and a signer that reads anything
other than a `200` naming the version in `signs` does not write it. The route therefore
carries no credential and no rate limit of its own, and it reads neither datastore: a yes must
not be able to turn into a silence.

**A verifier older than the message is refused, not answered.** When a request names no
version and asks about a signature this relay recorded under a version the request does not
say it can build — the field `understands` is where a caller says that — the answer is `409`
with a detail naming the version the record holds. It is a refusal and not a verdict, because
a verdict is shown to a person as "this message is bad", and the message is not bad: the
verifier is older than it. The match is on the hash as well as on the signature, so a message
whose signed content was changed keeps its old answer.

## The verification portal

A reader who holds the message itself opens the link out of the visible envelope,
`https://verify.zeknop.org/v1/<token>`: the page recomputes the fingerprint of the message in
the reader's own browser and checks the signature.

A reader who was **forwarded** the message holds none of that, because an ordinary forward
drops the signing headers and rewraps the lines; they forward the copy to the check address
and read `/check`, which compares the text that survived. That check is weaker than a
signature check and the page reads as the weaker one: it says what it compared and what it did
not, a copy that does not match is **not confirmed** rather than "changed", a plain forwarded
copy is never shown green, every forward received for the code is listed oldest first so a
planted copy is one more row rather than an answer that replaces the reader's own, no
fingerprint is printed because none leaves the relay, and no login is asked for because the
reader has no account.

**That listing answers the same identity question.** `GET /v1/forward-checks/{envelope_id}`
carries an `identity` block — `uuid`, `domain`, `email`, verification level and type, state —
whenever this relay has a signature for the envelope id, **including when `checks` is
empty**. It is the second unauthenticated path keyed by an envelope id that names the signer,
and it tells you the same thing `GET /v1/signature/{envelope_id}` does. What it does not carry
is anything about a copy beyond the rows: no hash, no text, and never who forwarded one.

There is one kind of row that may be green, and it is a signature check and not a comparison:
a forward that arrived as a `message/rfc822` attachment whose signature the deployment's
checking service verified in full. In `GET /v1/forward-checks/{envelope_id}` that row is the
one with `kind: "attachment"`, no `note`, and `verdict: "match"` — all three. A forward that
claimed to be such an attachment and could not be read as one is recorded as a plain copy and
carries `note: "attachment_signature_invalid"` or `"attachment_identity_not_active"`, and the
text comparison is still reported in `verdict`. A client that marks a row as verified reads
all three fields, because a green anywhere else is a green on a copy.
