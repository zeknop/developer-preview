# Changelog of the public HTTP contract

**Developer Preview — the protocol and the API may change; nothing on this page is a security
guarantee.**

Publisher: Zeknod OÜ. This document is licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

What a CALLER sees, for the paths listed in `README.md` beside this file. Only changes a
client outside the relay could notice are recorded: fields, status codes, and what a field
means. The relay's internal changes are not changes to this contract and are not here, and
neither are the routes this package does not describe — administration, billing, tenant
configuration, the keys a mail server signs with, revocation and erasure.

The normative description of the signature input itself lives in `../spec/signature-input.md` in
this package; this file says when something arrived and what a client written earlier
experiences.

## 1.8 — the three refusals of `POST /v1/sign`, written down (2026-10)

No version change and no change to the relay: no field moves, no answer is different from the
answer it was yesterday, nothing a caller sends changes meaning, and the number of the contract
stays 1.8. What changes is this file and the README beside it. The three refusals below have
been answered this way for the whole of 1.8 and were written down nowhere a client reads — and
one of them, the `404`, is declared in `openapi-public.json` with nothing beside it but the
words `Not Found`, so a caller met a status code with no meaning attached to it.

**`401 Invalid API key`** — the API key is not one this relay holds for that identity. The key
is looked up together with the `uuid` the request names, so a key that is perfectly good for
another identity on the same relay is answered this way too. A caller cannot tell "no such key"
from "not your uuid", and it should not be able to: the other answer would confirm which
identities exist.

**`403`** — the key is good and the relay will still not sign, and the `detail` says which of
four states it is: the identity is not active (`UUID is suspended, cannot sign`, with the
status itself in the text), the identity has been revoked (`UUID has been revoked`), the `From`
address of the request is not one that identity may send as (`Sender address does not match
registered identity`), or the deployment's own policy does not let that identity sign, which a
domain identity meets on a deployment that lets only some identities sign for a domain. The route does
not *declare* `403` in `openapi-public.json`; it answers it, which is why the README carries a
table of the codes the document is thinner than the relay about.

**`404 UUID not found`** — this relay has no identity with a signing key under that uuid: it was
never registered here, or no signing key of this relay belongs to it. It is **not** the "not
active" case — an identity this relay knows and will not sign for is the `403` above. Other
routes of this relay, the ones this package does not describe, resolve a key straight to an
*active* identity and answer `404 Identity not found or not active` for both halves of that, so
the situation that is a `403` here is a `404` there. That difference is recorded rather than
unified: a client of `POST /v1/sign` should read `detail` and must not carry a rule about these
codes from one route of the relay to another.

The sentences quoted above are what a caller reads. `detail` is the one field of a refusal a
client is told to act on, so changing one of these sentences is a change to this contract and
belongs in this file.

## 1.8 — a refused activation code is refused the same way, and an address is one caller (2026-10)

No version change: no field moves, nothing a caller sends changes meaning, and the number of
the contract stays 1.8. Both of these are things a caller can notice, so they are written
here.

### `POST /v1/activate` — the answer no longer depends on WHY the code was refused

Three states are refused: a code the relay does not hold, a code already redeemed, and a code
whose expiry has passed. The first two were answered `404 Invalid or already used activation
code`, and `429 Too many failed activation attempts. Try again in 15 minutes.` on the attempt
that crossed an attempt budget. The third was answered `404` **always** — including on the
attempt where the other two give `429`.

So on that one attempt the answers differed, and a caller who simply kept redeeming until the
refusal changed shape was told which of its guesses had been a real code, just too old. That
is the single fact these budgets exist to withhold. **All three now answer identically on
every attempt: `404` while no budget is crossed, `429` on the attempt that crosses one.** A
caller written against "an expired code is always 404" can now meet a `429` instead, with the
same meaning it has anywhere else on this route: wait out the fifteen-minute window.

### Two spellings of one address are one caller, in every limit

Not a field and not a status: WHICH caller a rate limit counts an attempt against. The relay
read the caller's address as the text it arrived as, so the same address written two ways was
two callers, in every limit the relay keys on the caller.

What a caller can notice: an **IPv4 client of a dual-stack listener** (reported as
`::ffff:a.b.c.d`) is now counted as the IPv4 address it is. It used to be counted as an IPv6
address, and every IPv4-mapped address has the same /64, so the /64-wide activation budget of
the entry below was ONE budget for every IPv4 caller of the deployment: `429` could arrive
because a stranger had mistyped five codes. That is gone.

The scope of each limit is otherwise unchanged: IPv4 a budget per address, IPv6 a budget per
/64 on `POST /v1/activate`, per address everywhere else, and the deployment-wide budget
untouched.

## 1.8 — the activation code gets longer, gets an expiry, and one budget per IPv6 prefix (2026-10)

No version change: the contract number stays 1.8, no existing field moves and no answer loses
a field. What a caller CAN notice is here, and the first of the three is a BREAK for a caller
holding an old code — which is why it is written out.

### `POST /v1/activate` — the code is now four groups of four

`XXXX-XXXX-XXXX-XXXX` (A-Z and 0-9, unchanged alphabet), sixteen characters instead of eight:
about 83 bits instead of about 41. An eight-character code is refused by the request schema,
with the `422` a malformed body has always had — it is not looked up, and no answer
distinguishes it from a code of the right shape that does not exist. A code is only ever held
as a hash, so an old one cannot be converted; a deployment that issued codes reissues them.

### `POST /v1/activate` — a code that was never redeemed expires

Every issued code carries the moment it stops being redeemable, written into its row when it
was issued. The default is seven days, and changing the deployment's setting never moves a
code that already exists.

**A redemption after that moment is answered exactly as an unknown code is** — normally
`404 Invalid or already used activation code`, and `429` on the attempt that crosses an
attempt budget, with the same text either way (see the entry above about those two answers). A
caller cannot tell the two apart, and that is deliberate: `410` would say "this code existed",
which is the one thing a caller guessing codes must not be told. The attempt counts into the
same budgets as any other miss.

### The attempt budget of an IPv6 caller covers its /64

Not a field and not a status: the SCOPE the per-caller budgets of `POST /v1/activate` are
counted under. An IPv6 customer is routinely handed a /64, so a budget keyed on the address
gave every one of 18 quintillion addresses its own attempts. The per-address limit of an IPv4
caller is unchanged, and the deployment-wide budget is unchanged.

A caller that sits in the same /64 as another customer of the same deployment now draws on
that customer's redemption budget: `429 Too many failed activation attempts.` can arrive for
attempts it did not make. The budgets are generous for this reason (five failures per caller,
ten redemptions an hour), and a caller that hits it waits out the fifteen-minute window.

## 1.8 — an outage of the attempt store is a 503 on two more answers (2026-10)

No version change: no field moves, nothing a caller sends changes meaning, and the number of
the contract stays 1.8. What a caller CAN notice is a status code, so it is written here.

`POST /v1/activate` and `POST /v1/register` are both guarded by a store the relay counts
attempts in. When that store cannot answer, the documented answer has been `503`
`Rate limiting service unavailable` ever since the budgets in front of a redemption were made
fail-closed — but only for one of the two ways a store can be unavailable. A store the process
had never reached gave `503`; a store that went away under a running process gave `500`, which
is the way an outage actually happens. Both now give `503`.

For a client: a `500` from these two endpoints no longer means "the store is down" — it means
what a `500` means everywhere else. A `503` from them means the attempt budget could not be
read, the code was not looked up, nothing was registered, and the request may be retried.

## 1.8 — the signer asks before it writes a version (2026-09)

**An addition, not a break**: nothing a 1.7 client sends changes meaning, and no existing
answer loses a field. The new number is here because a client can now ask a question it could
not ask before, and because the answer to that question is what a signer acts on.

### `GET /v1/capabilities` — what this relay can sign and can verify

Unauthenticated, no rate limit of its own, no datastore touched. The answer:

```json
{
  "contract": "1.8",
  "relay_id": "<this relay's id>",
  "signs": ["1.4", "1.5"],
  "verifies": ["1.4", "1.5"],
  "signature_input_version": "1.5"
}
```

`signs` and `verifies` are the versions of the signature input (`../spec/signature-input.md` §2)
this build can construct, oldest first; `signature_input_version` is the newest of them.

**Why an endpoint of its own and not a field in `/health`.** `/health` answers `503` when a
datastore is unreachable, and the body of a `503` is not something a caller may act on — a
signer would then have no answer at all, exactly when it most needs one, and the temptation
would be to keep the last one. What a build can sign does not depend on whether a datastore is
up. `/health` is also outside `/v1`: it is the orchestrator's liveness probe, it carries no
contract number, and a caller has no promise about its body. The versioned surface is where a
versioned answer belongs.

**What a relay that does not have it tells a caller.** `404`. Any status but `200`, a body
that is not a JSON object, or a `signs` that is not a list of strings, is read by a caller of
this contract as **this relay cannot sign that version** — see `../spec/signature-input.md` §6. A
relay from before this endpoint accepts a signing request with `version: "1.5"` and signs the
input it has always built, because the three fields of 1.4 are optional and an unknown value
in them was never refused. The signature comes back, the message leaves announcing
`X-ZEKNOP-Version: 1.5` over the older bytes, and every verifier calls it invalid, for ever.
The `404` is what keeps that message from being written at all.

### What a SIGNER does with the answer

The signers of this build ask at start and refresh at most once every 5 minutes, and they
write `version` only while the answer names it in `signs`. A missing, unreadable or expired
answer is not a yes: the message is not signed and the deployment's "cannot sign" delivery
applies (`../spec/delivered-envelope.md` §5 — `defer`, the default, is a `451` and the sender's
server tries again). This is a change a mail administrator sees during a rollback of a relay
and nowhere else: while the relay is below the signers, mail defers instead of being signed
into a permanent red.

### `POST /v1/verify` — which of its answers a caller may deliver on (amends 1.8)

No field and no status code changes. What changes is the contract about **what a caller does
with an answer**, and a caller written against 1.7 behaves differently from one written against
1.8 — so it belongs here.

A `400`, a `404`, a `409` or a `422` from this endpoint is a **deterministic refusal of the
question**: this relay is up, it answered, and it will answer the same way however often the
same question is asked. A caller must **not** treat one as an outage. A caller that defers on
them (an SMTP `451`, a queued retry) holds mail for as long as the sender keeps trying, and the
recipient is told nothing. The message is delivered, with the reason:

| this answer | what the caller tells the person |
| --- | --- |
| `400`, `422` | `Not verified: malformed ZEKNOP headers` |
| `404` | `Not verified: unknown identity` |
| `409` | `Not verified: unsupported ZEKNOP version` |

Still an outage, and still to be deferred or queued: no connection, a timeout, `5xx`, `429`, a
`200` whose body is not JSON or names no `valid` — and `401`/`403`, which is the caller's own
credential being wrong and says nothing about the message.

**The one answer that is a statement about the message** is `valid: false` for an identity this
relay has. A caller acts on that, and only on that, with whatever it does to a message that
did not verify. An identity this relay does not have is not that answer: see the entry below.

### `POST /v1/verify` — the new field `reason` on a negative answer (amends 1.8)

**An addition.** No status code and no existing field changes meaning, and a 1.7 client reads
exactly what it read before with one field more it does not look at.

Every `valid: false` answer of this endpoint now carries `reason`: one word saying WHICH kind
of "no" it is. A positive answer carries none, and the ABSENCE of it on a negative answer
means the relay is older than this.

| `reason` | what it says | what a reader shows |
| --- | --- | --- |
| `signature-mismatch` | the signature does not hold for an identity this relay HAS | the red "changed" — and this value alone |
| `unknown-identity` | this relay has no record of that identity, so nothing was checked against anything | `Not verified: unknown identity`, amber/grey |
| `identity-not-active` | the signature holds; the identity is revoked or not active | not red: the signed content is the content that was signed |
| `unsupported-version` | the version the request names is not one this build can construct | `Not verified: unsupported ZEKNOP version` |
| `unsupported-algorithm` | the algorithm the message names has no implementation here | `Not verified: unsupported signature algorithm` |
| `algorithm-not-in-record` | the identity record does not say it signs with that algorithm | not green; see `../spec/signature-input.md` §5 |
| `free-hash-missing`, `signature-input-not-buildable`, `timestamp-in-future` | the question as asked cannot be answered | the `message` says which |

**Why the addition is worth a line in the contract.** Until now `valid: false` with
`message: "Verification failed"` was the answer both for a signature that does not hold and
for an identity this relay has never heard of. A reader cannot tell them apart, so it shows
the red "changed" for both — and a deployment that rejects mail on a failed verification
throws away the mail of every sender whose identity this relay does not know. That is a
verdict about a message, stated about something that was never read.

**What it replaces.** The uniform `"Verification failed"` existed so that nothing could be
learned about which identities exist. It protected nothing that was not already public:
`GET /v1/verify/{identity_uuid}` answers `404` for an unregistered identity and `200` for a
registered one on the same unauthenticated surface, and the identifier is 122 random bits —
there is no enumeration to protect against. The `message` is unchanged for compatibility; the
distinction is in `reason`.

### `GET /v1/forward-checks/{envelope_id}` — the new field `service_misconfigured` (amends 1.8)

**An addition**, `false` by default, so a client written against 1.7 reads one field more and
nothing it already read has changed.

`true` means this relay has recently refused the credential of the deployment's own checking
service — the component that writes these rows — and has accepted none of its questions since.
It is a statement about **that service**, not about the envelope id in the path: it carries no
code, no row and no identity, and it is the same answer for every code while it lasts.

**Why the relay says it and not the checking service.** A checking service whose credential
does not match is refused for every copy any reader forwards, so no row is ever written. A
page that can only read rows then tells the reader "no forward has arrived for this code yet",
and the reader waits for something that was never coming, over a fault entirely on the
deployment's side. The relay is the only component that knows a credential was refused.

**No client has to change.** No answer, row or status moves, and a relay whose store is
unavailable never sets the field.

## 1.7 — the forwarded copy's endpoint is closed (2026-09)

A new version and not an amendment of 1.6, because of a change to a route this package does
not describe. One thing a caller of the public listing can notice:

### `GET /v1/forward-checks/{envelope_id}` — its own rate limit

The listing no longer borrows the signature lookup's limit. It has its own, configurable by
the deployment: 120 lookups per 15 minutes by default. The `429` body is unchanged
(`Lookup rate limit exceeded`). An office behind one NAT address used to spend the lookup
limit between colleagues.

## 1.6 — a copy that was forwarded, and a request that was asked twice (2026-09)

Additions, and no change to anything a client already sends. The idempotency key is described
normatively in `../spec/signature-input.md` §10; the listing below is described in
[`README.md`](README.md).

### `GET /v1/forward-checks/{envelope_id}` — new

Public, rate limited: every forward received for that envelope id in the last 7 days (the
listing window, a deployment setting; the records are kept longer, see Retention below), each
with the time it arrived, its verdict and its kind, plus the identity. Never a hash, never any
text, and never the forwarding address or its hash. A copy somebody else pushed in is one more
row, never a verdict that overwrites another. An unknown code is an empty list with a `reason`:
`"unknown_code"`, or `"past_retention"` when the optional `sent_at` (the date the forwarded
copy itself claims) is older than the retention window. Past retention the record is deleted
and nothing is kept in its place, so the relay cannot tell an expired envelope id from one
that never existed.

### `POST /v1/sign` — the optional header `Idempotency-Key`

64 lowercase hex characters naming the request. A repeat inside **24 hours** with the same key
from the same identity is answered with the **same** `signature`, `envelope_id`, `alg`,
`version` and `relay_timestamp`, and no second signature record is written: the key is unique
per identity in the relay's store, so even two requests that race end with one signature. What
the key is derived from is the caller's business (§10 says what the signers of this build
write); to the relay it is 64 hex characters.

**A client that sends no key keeps working unchanged** — no `409`, no `400`, the same answer as
before. A malformed value is `400`, because silently ignoring it would drop the protection
without telling anybody.

### Retention

The records of received forwards are kept for the same number of days as signature records (90
by default) and deleted by the same daily cleanup. The stored row holds no text of a copy, no
subject and no addresses: the envelope id, the hash over the free form of the copy, the
verdict, the time it arrived, its kind and the hash of the forwarding address.

## 1.5 — the second cutover (2026-09)

The message version the signers write moves to `1.5`. Nothing about the SHAPE of a request or
an answer changes; what changes is which values two existing fields take, and when the `409`
of §4a fires.

### `POST /v1/verify` — `understands` is compared per version

* `understands` now means what it always said it meant: the newest signature input the CALLER
  can construct. Until 1.5 the relay only asked whether the field carried the one version it
  knew; it now compares the value with the version **its own record** names and refuses the
  caller that is behind it. A client sending `understands: "1.4"` is still answered about a
  signature recorded as 1.4 — that is unchanged — and now receives **409** about one recorded
  as 1.5, instead of a `{"valid": false}` it would have shown as a changed message.
* `version` accepts `"1.5"` as well as `"1.4"`. A request naming any other value is still
  answered `{"valid": false, "message": "Unsupported signature version"}` and never over the
  older input.
* The `detail` of the `409` now names the version the record was made under, so a caller that
  logs it can say which input it was too old for.

### `POST /v1/sign` — both versions are signed

`version` accepts `"1.4"` and `"1.5"`. Both are signed, because on a cutover the signers are
upgraded LAST and the ones still running ask for the version they write. The version is part
of the signed bytes, so the two are different inputs and neither can be substituted for the
other.

**A client written against 1.4** keeps working for every message signed before this cutover.
For a message signed after it, that client receives `409` instead of `{"valid": false}` — the
same protection 1.4 gave a client written against 1.3, for the same reason.

## 1.4 — the cutover (2026-09)

### `POST /v1/verify` — the new field `understands`, and 409

* **New optional field `understands`.** Its value is the newest signature input the CALLER can
  construct — `"1.4"` for a verifier of that build. A verifier written before v1.4 cannot send
  it, which is the point: the field distinguishes a caller that cannot read a v1.4 message
  from a current caller asking about a message whose version header was taken off or edited
  down.
* **New status 409** for a request that names no `version`, does not say it understands v1.4,
  and asks about a signature this relay recorded as made under v1.4 over exactly that hash.
  `detail` says why. Before 1.4 such a request was answered `200 {"valid": false}`, which
  every old verifier renders to the person as a failure of the MESSAGE — about a message
  nothing is wrong with. The refusal lets the caller's own error path say "could not verify"
  instead.
* **New optional fields `version`, `alg`, `free_hash`.** A request without them is read as a
  message from before v1.4 and verified over the strict hash alone, exactly as before.

**A client written against 1.3** keeps working unchanged for every message signed before the
cutover. For a message signed after it, that client receives `409` instead of
`{"valid": false}`. Nothing it can send turns the `409` into a false green, and nothing turns a
message whose signed content was changed into a `409`: the refusal is matched on the hash as well
as on the signature, so such a message keeps the old answer.

### `POST /v1/sign` — the new fields `version`, `alg`, `free_hash`

The signer says which rules it signs under; the relay builds the signature input itself and
never signs bytes the caller handed it. The answer carries the algorithm alongside the
signature. A request without the three fields is signed the old way.

### `GET /v1/verify/{identity_uuid}` — the key history

The answer carries each public key the identity has had, with its algorithm and the window it
was valid in, so a message older than the last re-issue can be checked by someone who does not
want to take this relay's word for it.

### `GET /v1/signature/{envelope_id}` — narrowed

The public answer carries the verdict and the identity, and no longer the strict hash, the
signature or the attachment metadata: next to a published key a signature is a guessing aid,
and the file names of a message are not public data. Callers that read those fields have to ask
with the message source instead.

### Retention

Signature records are kept for a number of days the deployment sets (90 by default) and then
deleted, which is what the deployment's published privacy text says. After that a forwarded
copy can no longer be checked against the record — the message source still verifies on its
own — and the `409` of §4a stops as well, because there is no record left to match.
