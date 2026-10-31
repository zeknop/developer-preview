<!--
Licence: Creative Commons Attribution 4.0 International (CC BY 4.0)
          https://creativecommons.org/licenses/by/4.0/
Publisher: Zeknod OÜ
Part of: the ZEKNOP Signed Email specification, Developer Preview
Date: 2026-10-31
-->

# The ZEKNOP sandbox

**Developer Preview — the protocol and the API may change; nothing on this page is a security
guarantee.**

Publisher: Zeknod OÜ. This document is licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

A sandbox is a relay you may sign with and check against without registering anything. It is
**the same relay** as any other, started with one setting turned on: it serves the same
HTTP contract, computes the same signature input, and produces envelopes that satisfy the same
specification. Nothing in this package describes a special protocol for sandboxes, because
there is not one. A sandbox runs a build that carries the code of that setting; no other
deployment does.

Address of the public sandbox: **none is published in this preview.** Everything below is how
a sandbox behaves and how to recognise one; the parts of this package you can use without any
relay at all are the test vectors and the differential cases.

---

## Part one — for developers

### How to tell you are talking to a sandbox

Ask `GET /v1/capabilities`, which needs no credential:

```json
{
  "contract": "1.8",
  "relay_id": "relay.sandbox.example.org",
  "signs": ["1.4", "1.5"],
  "verifies": ["1.4", "1.5"],
  "signature_input_version": "1.5",
  "sandbox": true
}
```

`"sandbox": true` is the **only** machine-readable marker of a sandbox anywhere in the
contract. Test for the presence of the key, not for `false`: a relay that is not a sandbox
**leaves the field out**, which is also what every relay built before the field existed does.

The marker is on this endpoint because it is the endpoint a client asks first anyway (it is
how a signer learns which signature-input versions a relay can sign), it needs no credential,
and it reads no datastore — so a client can find out what it is talking to in one request,
before it sends a message or a key anywhere.

### The shared identity

A sandbox seeds one identity when it starts and the operator publishes it: a `uuid` and an
`api_key`, which is everything `POST /v1/sign` needs. It is a **domain-level** identity, the
same shape a domain registration ends in, so a signature made with it is an ordinary
signature.

Five consequences, all of them of the fact that the key is public:

* **everybody shares it.** The signing rate limit is counted per identity, so the sandbox's
  whole signing budget is this one identity's budget — 20 signatures a minute where a
  production relay's default is 100. A 429 on a sandbox usually means somebody else is
  working, not that your request was wrong. There is no way round it either: a relay has a
  second signing path, for a mail server's own component, which authenticates with a
  credential of its own and carries its own budget — and a sandbox does not mount the paths
  that hand such a credential out. They answer `404`, so nobody can hold one, and the second
  signing path has nothing it would accept. That is why the sentence above is a fact about
  the deployment and not a hope about its visitors;
* **the records a sandbox keeps about what you sent are deleted daily.** Signature records,
  identities other than the shared one, and the rows and cache entries that describe them
  are removed on a schedule the operator runs. A sandbox is not a store: nothing in it is
  kept, and nothing in it is backed up — that last one is a line in the deployment note of
  part two, not something this package can check. What a deployment's own logs hold, and how
  long, is the operator's;
* **send nothing you would mind losing, and nothing you would mind being read.** What a relay
  records about a signature is fingerprints and not text — including the two content hashes,
  the time, the address the request came from, and per attachment a hash of its contents, a
  hash of its name, its size and its media type. No subject, no body, no recipient and no
  file name. But a sandbox is a machine whose signing key is published and whose data
  somebody else may also be looking at, and nothing you send it is covered by any promise.
  Use messages you made up;
* **you cannot end it, and neither can anybody else.** A relay has paths that revoke or
  erase an identity, and they authenticate with that identity's API key alone — so on a
  sandbox, where the key is published, one request from one visitor would end the identity
  everybody is sharing. Both answer `403` for the shared identity and name what to do
  instead. Register an identity of your own if you want one you can throw away;
* **a sandbox signature proves nothing about who sent a message.** Anybody holding the
  published key can produce one. Never treat a sandbox verdict as evidence, and never let a
  sandbox identity reach a user interface that presents a verified sender.

### What a sandbox does not do

* **no billing paths.** `/v1/billing/*` is not mounted at all: all four paths answer `404`,
  the same answer as a relay that never had them. Nothing in this preview describes them.
  The same is done to the paths that issue the second kind of signing credential named
  above, and for a sharper reason: they authenticate with the identity's own API key, which
  on a sandbox is published;
* **no registration through an external identity provider.** `POST /v1/register` with
  `verification_type` of `bankid` or `eidas` is refused with `403` and a body that names what
  does work. Those methods identify a real person through a third party, which is not
  something a playground should be asking a stranger for;
* **no mail path, in either direction.** A sandbox is reached over HTTP by your own code. It
  receives no mail, so the forwarded-copy listing (`GET /v1/forward-checks/{envelope_id}`)
  answers with an empty list — which is the truthful answer: nothing was forwarded to it.
  And it sends none, which is why the one registration method that needs the relay to send
  a mail — the magic link to the address being registered — cannot complete on a sandbox:
  the request is accepted and no mail arrives. Do not build on it there.

### Registering an identity of your own

You do not have to: the shared identity signs. If you want your own, the way that works on a
sandbox is a domain you control.

Send `POST /v1/register` with `verification_type` `dns_txt` or `domain_manual` and your
domain. The answer carries a `uuid`, an `api_key` and the record to publish — a TXT record at
`_zeknop.<your domain>`, or a file under `/.well-known/`. Publish one of them, then send
`POST /v1/register/verify-domain` with the `uuid`: the relay looks the record up itself and
the identity becomes active. From then on it signs like any other, with its own rate budget
rather than the shared one — and the daily deletion removes it, so expect to do this again
tomorrow.

### A sandbox signature checked against another relay

This is the question worth being exact about, because getting it wrong once in a user
interface teaches a person the wrong thing.

Take a message signed by a sandbox and check it against a different relay — the production
one, or your own. The signature is intact and the signed content is as it was signed, but the relay you
asked has never heard of that identity. What you get back from `POST /v1/verify` is:

```json
{ "valid": false, "reason": "unknown-identity", "message": "Verification failed" }
```

and `GET /v1/verify/{identity_uuid}` for that identity answers `404`.

**That is "I do not know this identity", and it is not "the signed content was changed."** The two
are different facts about different things — one is about the relay you asked, the other is
about the signed content — and `reason` is the field that tells them apart. A client that reads only
`valid` cannot distinguish them and will report the message as failing verification, which is
exactly the confusion to avoid: read `reason`, and say *not verified: unknown identity*
rather than anything about the content. On the mail path, a deployment's own checking service
makes the same distinction: it records an unknown identity as `unknown-identity`, with the
sentence *Not verified: unknown identity*, and does not mark the message as one to act on.

What makes a sandbox signature distinguishable is **the identity's domain and the name of the
relay that made it** — both of which are inside the signed input and in the answer — and not
anything in the envelope. The envelope of a sandbox message is the envelope the specification
describes, byte for byte; the specification does not change because a relay is a sandbox, and
a client must not look for a sandbox marker in a message. There is none. The marker is on
`GET /v1/capabilities` of the relay you are talking to, and nowhere else.

---

## Part two — for whoever runs one

**This part is for whoever runs a relay from its source.** It is about deploying a sandbox,
and the files it mentions are part of a relay's own deployment files, which are not in this
package — the relay itself is not published. If you are here to use a sandbox rather than to
run one, part one is the whole of it.

A sandbox is deployed from the relay's own deployment files: the production stack file
together with a sandbox overlay, and a root environment file copied from the example beside
it. The overlay is the complete list of differences, and the production file is not modified
by it — a deployment that uses the production file alone has never heard of a sandbox.

### The machine

* **its own machine, running no part of any production deployment.** This machine serves a
  published signing key to strangers and throws its data away daily; it has no business
  sitting beside something that does not;
* **in the EU**, like the deployments it stands beside;
* **its own certificates, on the machine**: its own nginx in front of the relay and its own
  certbot renewing the certificate. Its DNS records are to **resolve only** — no
  content-delivery or reverse-proxy service that terminates TLS or forwards requests in the
  data path between a developer and this relay. While that holds, the bytes a developer sends
  are the bytes the relay reads and the certificate a developer sees is the one on this
  machine. Nothing in this package can check that it holds, so whoever announces a sandbox
  says where its name resolves;
* **nothing shared.** Its own database, its own cache, its own secrets. No datastore, no
  credential and no deployment configuration file is shared with another deployment, and no
  federation secret of another deployment is present on it. There is to be no path from this
  machine into anything else: that is the whole reason it is a machine of its own;
* **no backups.** Nothing on this machine is backed up — not the database, not the cache, not
  the log. What the daily deletion removes is then gone, which is the point of it; a backup
  would be a second copy of strangers' records that no deletion reaches.

### The two caps that are not the relay's to set

* **`POST /v1/verify` carries no credential and no rate limit of its own.** Every other
  public path either needs a key or counts requests per caller address; this one does
  neither, and the relay has no global limiter, so on a machine deliberately shown to
  strangers the only place a ceiling can go is the nginx in front of it. Put one there.
* **the relay's per-address limits count the address they are given.** Behind a reverse
  proxy that is the proxy's address, for every visitor, until the deployment names that
  proxy as trusted — one address, never a subnet. Left unnamed, no forwarding header is
  believed at all, which on a sandbox is a nuisance rather than a hole.

### What a sandbox's own log holds

The daily deletion empties the database and the cache. It does not touch the relay's log,
and nothing else does either: a line there can name an envelope id, an identity uuid, a
domain and the address a request came from. The deployment files bound the file (a fixed
size, a fixed number of files) so it cannot grow without end, and the machine's
requirements above say it is not backed up; what is in it while it lives is the operator's
to decide and to say when the sandbox is announced. The published sentence in part one is
deliberately about the records in the database and the cache, not about logs.

### What the overlay changes, and what the relay refuses

The overlay turns the switch on, gives the sandbox **its own relay name** and its own portal
names, lowers the signing rate limit, opens self-serve registration (a sandbox is the one
deployment where it is the point: it is emptied daily and holds nobody's data), adds the
daily deletion, and switches off the six services a sandbox does not need — the
mail-receiving path and the policy service with its datastores. None of them serves a path
of the public contract, so no developer can tell whether they are there.

It also names, with no default, every value whose fallback is another deployment's: the
browser origins the relay answers (the code's default is the production portals'), the
address the portal prints on its checking page, the support address and the documentation
origin. A sandbox that has not been told its own does not start, rather than starting as a
page that points visitors at production.

Nothing in the overlay gives the relay a way to **send** mail, which is deliberate and is
why the one registration method that needs it is not offered in part one. An operator who
adds one has to say so where the sandbox is announced.

The shared identity cannot be **revoked or erased** through the API: on a sandbox both paths
that would do it answer `403` for that one identity, because its key is published and one
request would otherwise end the sandbox for everybody. And every start-up repairs a shared
identity that has been damaged some other way — a status that is not active, a revocation
left behind, a deployment policy it cannot sign under, a key that no longer works — rather than leaving a
sandbox that answers every question and signs nothing. Repairing a key that no longer works
means issuing a new one: the start-up log says so, and the new key has to be published in place
of the old.

The relay **refuses to start** as a sandbox if it would carry the production relay name, if it
has no domain for its shared identity, or if it has nowhere to write that identity's key. All
three are values a sandbox cannot invent, and each failure they prevent is silent: a sandbox
answering under the production name would put that name on signatures made with a published
key, and no verifier anywhere could tell the two apart.

### The shared identity, and the one file that must survive

At every start-up the relay makes sure the shared identity exists, and does nothing if it
already does. The first start-up writes its `uuid` and its `api_key` to a file, mode `0600`,
on a volume of its own. **That file is the only copy of the key** — the relay keeps a hash of
it and cannot read it back, and the key is never written to the log.

So the volume has to survive a restart. If it does not, the next start-up revokes the
published key and issues a new one, writes a warning saying so, and the key you published
stops working. Publish the two values from that file as the sandbox's shared identity, next to
the sentences in part one: shared budget, daily deletion, nothing sensitive.

### The deletion

The overlay runs the deletion as a sidecar from the same image as the relay, immediately and
then every twenty-four hours. It removes every signature record and every identity except the
shared one — which it recognises by the one value the seed was made from, so the identity that
is published and the identity that survives cannot drift apart — together with the rows and
cache entries that describe them. It also empties the table of the second kind of signing
credential, although a sandbox built from this release mounts no path that issues one: a
sandbox that was running before that change, or an operator who mounted those paths
themselves, is the case that statement is the only answer to. It refuses to run at all unless
the sandbox switch is set, which is what keeps a deletion written for a playground from ever
being pointed at a deployment that is not one.

### Announcing it

A sandbox is announced with its address, its shared `uuid` and `api_key`, and the five
sentences of part one — plus the two things only its operator knows: where its name resolves,
and what its own log keeps. It is announced as a preview, not as a service: there is no
availability promise, the data is deleted daily, and the published key means a signature made
there is evidence of nothing.
