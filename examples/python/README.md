# A ZEKNOP client in Python — example

**Developer Preview — the protocol and the API may change; nothing on this page is a
security guarantee.**

Publisher: Zeknod OÜ. Licensed [Apache-2.0](LICENSE); see [NOTICE](NOTICE).

This is **an example, not a library, and it comes with no warranty.** It is here to be read
beside the documents in [`../../spec/`](../../spec/) and to be run against the vectors in
[`../../vectors/`](../../vectors/). It is not packaged, not versioned, and nothing depends on
it; copy what is useful into your own code rather than importing it.

It makes no claim about the security, the performance or the privacy of anything. What it
does claim is one measurable thing: it answers every vector in this preview the way the
reference implementation does, and `conformance` prints the evidence.

## What it does

| Command | What it does |
| --- | --- |
| `verify <file.eml>` | Recomputes both hashes from the bytes, compares them with the fields the message carries, and asks a relay whether the signature holds and whose identity signed. |
| `verify <file.eml> --offline` | The same up to the comparison, and then stops. Asks nobody anything. |
| `sign <file.eml>` | Asks a relay what it can sign, has it sign the hashes of the message, writes the fields and the visible block, and saves a `.eml`. |
| `conformance` | Runs every vector file and the differential cases, and prints the report of [`../../vectors/CONFORMANCE.md`](../../vectors/CONFORMANCE.md). |

## What it does not do

- **It does not decide anything about an identity.** Whether a signature holds and whether
  the identity is active are questions for a relay. `--offline` can say that the hash in a
  message is the hash of the message, and that is all it can say.
- **It does not turn a refusal or an outage into a verdict.** A `400`, `404`, `409` or `422`
  is the relay refusing the question; no connection, a timeout, a `5xx` and a `429` are an
  outage. Neither says anything about the message, and the exit code keeps them apart from
  both answers. A `401` and a `403` are read by the path they come from, because they mean
  different things there: from `POST /v1/sign` they are refusals — the key is not one the
  relay holds for that identity, or it is and the relay still will not sign, and asking
  again changes neither — while `POST /v1/verify` asks for no credential at all, so a `401`
  or a `403` there is something in front of the relay turning this caller away, which is an
  outage and never a verdict (`../../spec/delivered-envelope.md` §2 is explicit about that).
- **It does not write the visible block everywhere a production signer does.** It writes it
  into a message that is one non-multipart `text/plain` or `text/html` part whose transfer
  encoding is `7bit`, `8bit`, `binary` or absent, whose charset is UTF-8 or US-ASCII, and
  whose payload is in fact that charset — a part that does not decode exactly cannot carry a
  block written through that decoding (§4). An EMPTY body is written into like any other:
  §4 says an empty message body carries the envelope around empty content. Anything else is
  signed and delivered without the block, and it says so — which is what
  `../../spec/delivered-envelope.md` §4 provides for: such a message is signed, it verifies, and it
  shows no markers.
- **It holds no key and verifies no signature itself.** Signing and verifying a signature
  happen at a relay, which is where the key is.

## Requirements

Python **3.11 or newer**, and nothing else. There is no `requirements.txt`, no
`pyproject.toml` and nothing to install, because every import is from the standard library:

- the client itself: `argparse`, `base64`, `binascii`, `dataclasses`, `datetime`, `email`,
  `hashlib`, `json`, `pathlib`, `re`, `sys`, `urllib`, `uuid`;
- the canonicalisation it carries: the same, plus `quopri`;
- the tests only: `contextlib`, `hmac`, `http.server`, `io`, `os`, `secrets`, `string`,
  `tempfile`, `threading`, `unittest`.

## Running it

From this directory.

```sh
# every vector file and the differential cases
python3 -m zeknop_example conformance

# the hashes of a message, and nothing that needs anybody
python3 -m zeknop_example verify message.eml --offline

# the same, and then the relay's verdict
python3 -m zeknop_example verify message.eml --relay https://relay.example.org

# sign through a relay for an identity you hold the key of
python3 -m zeknop_example sign draft.eml \
  --uuid 11111111-2222-3333-4444-555555555555 \
  --api-key "$ZEKNOP_API_KEY" \
  --relay https://relay.example.org \
  --portal https://verify.example.org/v1 \
  --out signed.eml
```

The relay and the portal are the ones your deployment gave you, and **both are required**:
there is no default for either. The portal is the whole prefix that deployment serves tokens
under, path and all, because the link line of the visible block is `<portal>/<token>` and
`<portal>` is the portal of the given deployment and not a fixed name
(`../../spec/delivered-envelope.md` §3.4). A default here would be written into a delivered message,
where a link nobody serves is worse than no link. Every address in this package is an example
address: `example.org`, `example.com`, `192.0.2.x`. A sandbox, where one is offered, says so
itself in `GET /v1/capabilities`.

Exit codes: **0** when what was asked came out positive, **1** when it came out negative
(the hashes differ, the signature does not hold), **2** when the question could not be
answered — a refusal, an outage, a message whose fields are not the right shape, a file that
cannot be read, or a fault in this program. The difference between 1 and 2 is the whole
point: only 1 is a statement about the message, which is why nothing going wrong in here can
produce it.

## The tests

```sh
python3 -m unittest discover -s tests
```

36 tests, standard library only, no relay and no network:

- `tests/test_conformance.py` — every vector file, with the counts asserted by number, the
  shape of the report asserted line by line against `../../vectors/CONFORMANCE.md` §1, and the two corners
  of the §8 timestamp rule the vectors do not reach;
- `tests/test_verify_offline.py` — messages built in the test: one nobody touched, one with a
  character changed, one with a changed subject, one carrying the block that says it could not
  be signed, one whose fields are malformed, one announcing a version this reader cannot
  build, and one with a result field a sender wrote;
- `tests/test_sign_and_verify.py` — `sign` and then `verify` against
  `tests/mock_relay.py`, a stand-in that makes a keyed digest instead of an Ed25519
  signature. That file says what the stand-in does and does not prove. It also holds the
  delivered bytes against §3.3 — one blank line between the content and the end marker,
  which no hash would notice — the two rules about the fields (an `X-ZEKNOP-*` field a sender
  wrote is removed with its folded continuations, and a value carrying a line break is
  refused rather than written), and the two readings of a `401`.

`e2e_local_relay.py` is the run against a real relay — sign, verify, change one character,
verify again — and needs one; its header says which environment variables it reads.

## How it is put together

```
zeknop_example/
  cli.py                 the three commands, and what each may and may not say
  message.py             what a verifier reads off a message, and the two hashes
  signature_input.py     the bytes a signature is made over (signature-input.md §2, §4)
  envelope.py            writing the visible block (delivered-envelope.md §3)
  compose.py             writing the signed message out
  relay.py               the three relay calls, over urllib
  conformance.py         every vector file, and the report
  vector_message.py      a vector rendered to the raw bytes of a message
  canonicalization/      a COPY of the reference implementation — see NOTICE
```

Six of the seven files under `canonicalization/` are whole files of the reference
implementation; `message_fields.py` is five functions of one of them, gathered into a module
of their own. `NOTICE` says which, and what was compared against what.

The order the work is done in is the order of the specification, and `message.py` says why
each step comes where it does. Three of them are worth naming here, because an implementation
that gets either wrong is wrong about messages nobody touched:

1. **the visible block comes off before anything is hashed**
   (`../../spec/delivered-envelope.md` §6.1). It is written after signing and is not covered by the
   signature;
2. **the shape of the canonical object is chosen from the structure of the message**
   (`../../spec/canonical-content.md` §1.1), never from a field, so it cannot be moved by whoever wrote
   the fields;
3. **a signer reads the message before it samples the timestamp.** The timestamp is one
   field of the canonical object and nothing read off the message depends on it, so the two
   separate — and they have to, because a relay refuses a timestamp more than 30 seconds from
   its own clock and hashing a large body takes time. `message.read_message` does the
   reading, `message.canonical_at` puts the timestamp in, and a signer that does it the other
   way round is refused for messages nothing is wrong with.

## Around this directory

- [`../../spec/`](../../spec/) — the specification: what is hashed, what is signed, what is
  delivered. `../../spec/README.md` is the quick start, in the order the protocol goes;
- [`../../vectors/`](../../vectors/) — the vectors this example is held to, and
  `../../vectors/CONFORMANCE.md`, which fixes the report format so that your result and this one can be
  read side by side;
- [`../../api/`](../../api/) — the public part of the relay's HTTP contract, and the
  semantics the schema cannot state. Read it before `relay.py`;
- [`../../sandbox/`](../../sandbox/) — what a sandbox relay is (none is published with this preview);
- [`../js/`](../js/) — the same three commands in JavaScript.
