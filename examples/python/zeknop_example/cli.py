# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zeknod OÜ
"""The three entry points: verify, sign, conformance.

    python3 -m zeknop_example verify <file.eml> [--relay URL] [--offline]
    python3 -m zeknop_example sign <file.eml> --uuid U --api-key K --relay URL --portal URL
    python3 -m zeknop_example conformance [--vectors DIR]

What each of them may and may not say is the point of this file as much as what it
computes:

* `verify --offline` reads the bytes and says whether the hashes in the message
  are the hashes of the message. It says NOTHING about the identity or the
  signature — nobody was asked, and no local computation can answer either;
* `verify` adds the relay's answer, and keeps the three kinds of answer apart: a
  verdict, a refusal of the question, and an outage. Only `signature-mismatch`, and
  a hash that does not match the content, say anything about the message;
* `sign` writes the fields the relay answered with, and the visible block when it
  can write one exactly. It never invents an identifier for the block, and it
  never invents the portal the link names: `--relay` and `--portal` are both
  given, because a neutral example cannot have a default for either without
  naming one deployment — and a default portal would be written into a delivered
  message, where a link nobody serves is worse than no example at all.

Exit codes: 0 when the thing asked for came out positive, 1 when it came out
negative, 2 when the question could not be answered (an outage, a refusal, a file
that cannot be read, or a fault in here). Only 1 is a statement about the
message, which is why no failure of this program's own can produce it.
"""

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import compose, conformance, envelope, message, relay
from .canonicalization import mime_walk, sig_alg

#: The algorithm this example asks for. §3 of `signature-input.md` has one name in
#: the state `signed`, and the reserved names are reserved: nothing signs with them.
ALGORITHM = sig_alg.SIGNED_ALGORITHMS[0]

OK = 0
NEGATIVE = 1
UNANSWERED = 2


def _now() -> str:
    """§8 — ISO 8601 with milliseconds and UTC, which is the format of the field."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _read(path: Path) -> bytes:
    return path.read_bytes()


def _print_recomputed(recomputed, fields) -> None:
    print(f"  shape                {recomputed.shape}")
    print(f"  from                 {recomputed.from_address or '(none)'}")
    print(f"  to                   {', '.join(recomputed.recipients) or '(none)'}")
    print(f"  subject              {recomputed.subject!r}")
    print(f"  timestamp            {fields.timestamp or '(none)'}")
    print(f"  strict hash (bytes)  {recomputed.content_hash}")
    print(f"  strict hash (field)  {fields.content_hash or '(none)'}")
    print(f"  free hash (bytes)    {recomputed.free_hash or '(not asked for this version)'}")
    kinds = ", ".join(str(kind) for kind in recomputed.envelope_kinds) or "(no displayed text)"
    print(f"  visible block        {kinds}")


def verify(args) -> int:
    raw = _read(args.file)
    parsed = message.parse(raw)
    fields = message.claimed(parsed)
    if fields.version is None and not fields.signature:
        print("This message carries no ZEKNOP fields. There is nothing to check.")
        return UNANSWERED

    recomputed = message.recompute(raw, parsed)
    print(f"{args.file}:")
    _print_recomputed(recomputed, fields)

    # §6.1 step 1, decided before anything else: a message delivered as one the
    # signer could not sign is not verified, whatever fields it carries.
    if recomputed.carries_not_verified_envelope:
        print("\nNot signed: the message carries the block saying it could not be signed.")
        return NEGATIVE

    problem = message.shape_problem(fields)
    if problem:
        print(f"\nCould not check: the ZEKNOP fields are not the right shape ({problem}).")
        print("Nothing was read about the content, so this is not a statement about the message.")
        return UNANSWERED

    if recomputed.version_state == "unknown":
        print(f"\nCould not check: this message announces version {fields.version!r},")
        print("which this reader cannot build the signed bytes for. Not a statement about")
        print("the message either: a reader older than a message says so (§4).")
        return UNANSWERED

    if recomputed.algorithm_problem:
        print(f"\nCould not check: {recomputed.algorithm_problem}.")
        return UNANSWERED

    if recomputed.content_hash != fields.content_hash:
        print("\nThe content hash of the bytes is not the hash in the message.")
        print("Something changed after signing. No relay was asked: this one is local.")
        return NEGATIVE

    print(f"\n  signature input      {recomputed.signature_input().hex()}")
    print("  the content hash of the bytes is the hash in the message")

    if args.offline:
        print(
            "\n--offline: the hashes agree. Whether the SIGNATURE holds, and whose identity\n"
            "signed, is a question for a relay — nobody was asked, so neither is answered here."
        )
        return OK

    if not args.relay:
        print("\nNo relay given. Pass --relay URL, or --offline to compare the hashes only.")
        return UNANSWERED

    try:
        answer = relay.verify(
            args.relay.rstrip("/"),
            uuid=fields.uuid,
            signature=fields.signature,
            message_hash=recomputed.content_hash,
            timestamp=fields.timestamp,
            version=recomputed.accepted_version,
            algorithm=recomputed.algorithm,
            free_hash=recomputed.free_hash,
            understands=sig_alg.SIGNATURE_INPUT_VERSION,
        )
    except relay.RelayRefused as refusal:
        print(f"\nThe relay refused the question: {refusal}.")
        print("A refusal is not a verdict — it says nothing about the message.")
        return UNANSWERED
    except relay.RelayUnavailable as outage:
        print(f"\nThe relay could not be asked: {outage}.")
        print("An outage is not a verdict either.")
        return UNANSWERED

    print("\nThe relay's answer:")
    print(f"  valid                {answer['valid']}")
    for key in ("reason", "message", "email", "domain", "verification_level", "status"):
        if answer.get(key):
            print(f"  {key:<20} {answer[key]}")
    if answer["valid"]:
        who = answer.get("email") or answer.get("domain") or answer["uuid"]
        print(f"\nThe signature holds for {who}, over the bytes this message carries.")
        return OK
    if answer.get("reason") == "signature-mismatch":
        print("\nThe signature does not hold for these bytes.")
    else:
        print(
            "\nNot verified. The reason above is about the IDENTITY, not about the content:\n"
            "`signature-mismatch` is the only reason that says the message was changed."
        )
    return NEGATIVE


def sign(args) -> int:
    raw = _read(args.file)
    base = args.relay.rstrip("/")

    # The signer asks what the relay can sign BEFORE it writes a version, because
    # a message that announces a version its signature was not made over cannot be
    # repaired afterwards. A relay too old to answer this answers 404, and the
    # right thing to do then is to write no version at all (§4).
    version = None
    algorithm = None
    try:
        capabilities = relay.capabilities(base)
        common = [v for v in sig_alg.INPUT_VERSIONS if v in capabilities.signs]
        if common:
            version, algorithm = common[-1], ALGORITHM
        print(f"relay {capabilities.relay_id or base}, contract {capabilities.contract}")
        print(f"  signs       {', '.join(capabilities.signs) or '(none)'}")
        print(f"  this client {', '.join(sig_alg.INPUT_VERSIONS)}")
        print(f"  signing as  {version or 'no version (the older input of §4)'}")
        if capabilities.sandbox:
            print("  this relay says it is a sandbox")
    except relay.RelayRefused as refusal:
        if refusal.status != 404:
            print(f"The relay refused to say what it can sign: {refusal}.")
            return UNANSWERED
        print("This relay does not answer /v1/capabilities, so no version is written (§4).")
    except relay.RelayUnavailable as outage:
        print(f"The relay could not be asked what it can sign: {outage}.")
        return UNANSWERED

    # The message is read FIRST and the timestamp is sampled after it. The walk,
    # the decoding of the part and the free text form are the expensive half, and
    # the relay refuses a timestamp more than 30 seconds from its own clock: a
    # signer that samples the moment before it hashes a large body spends that
    # window on its own work and is refused for a message nothing is wrong with.
    # `message.read_message` holds nothing but the reading, and `canonical_at`
    # puts the timestamp into the canonical object — the same object either way.
    read = message.read_message(raw, algorithm=algorithm)
    timestamp = _now()
    recomputed = message.canonical_at(read, timestamp)
    from_address = args.from_address or recomputed.from_address
    if not from_address:
        print("The message has no From address and none was given with --from.")
        return UNANSWERED

    try:
        answer = relay.sign(
            base,
            api_key=args.api_key,
            uuid=args.uuid,
            content_hash=recomputed.content_hash,
            free_hash=recomputed.free_hash,
            timestamp=timestamp,
            from_address=from_address,
            version=version,
            algorithm=algorithm,
        )
    except relay.RelayRefused as refusal:
        print(f"The relay would not sign: {refusal}.")
        return UNANSWERED
    except relay.RelayUnavailable as outage:
        print(f"The relay could not be asked to sign: {outage}.")
        return UNANSWERED

    signature = answer.get("signature")
    envelope_id = answer.get("envelope_id")
    if not signature:
        print("The relay answered without a signature. That is not a signature: nothing is sent.")
        return UNANSWERED

    print(f"  strict hash {recomputed.content_hash}")
    print(f"  free hash   {recomputed.free_hash or '(none: the older input)'}")
    print(f"  signed      {answer.get('version') or '(no version)'} {answer.get('alg') or ''}")
    print(f"  envelope id {envelope_id or '(none)'}")

    out = raw
    verify_url = None
    root = mime_walk.parse_part(raw)
    refusal = compose.block_refusal(root)
    if not envelope_id:
        # §3.1: a positive block never names a placeholder or an invented
        # identifier. Without one from the relay there is no block to write.
        refusal = "the relay answered no envelope id, and a block never invents one"
    if not refusal:
        token = envelope.verify_token(recomputed.content_hash, args.uuid)
        # §3.4: the link line is `<portal>/<token>`, where `<portal>` is the
        # portal of the given deployment — the whole prefix it serves tokens
        # under, path and all. There is no fixed name and none is invented here.
        verify_url = f"{args.portal.rstrip('/')}/{token}"
        out = compose.wrap(raw, root, envelope_id, verify_url)
        print("  visible block written into the one displayed part")
    else:
        print(f"  no visible block: {refusal}")
        print("  the message is signed and verifies; it shows no markers (§4)")

    out = compose.with_fields(
        out,
        compose.header_lines(
            version=answer.get("version") or version,
            algorithm=answer.get("alg") or algorithm,
            signature=signature,
            content_hash=recomputed.content_hash,
            uuid=args.uuid,
            timestamp=timestamp,
            relay_id=answer.get("relay_id", ""),
            level=args.level,
            envelope_id=envelope_id,
            verify_url=verify_url,
        ),
    )

    # The written message is read back the way a verifier reads it — BOTH hashes,
    # because both are inside the signed bytes (`signature-input.md` §2). If the
    # block this example wrote moved either of them, the message would be
    # delivered claiming a fingerprint of something else and every verifier would
    # call it invalid, so it is checked here and not hoped for.
    again = message.recompute(out)
    if (again.content_hash, again.free_hash) != (recomputed.content_hash, recomputed.free_hash):
        print("\nThe written message does not recompute to the hashes that were signed.")
        print(f"  signed      {recomputed.content_hash} {recomputed.free_hash or '(no free)'}")
        print(f"  written     {again.content_hash} {again.free_hash or '(no free)'}")
        print("Nothing was written to disk.")
        return UNANSWERED

    args.out.write_bytes(out)
    print(f"\n{args.out}: signed, and it recomputes to the hashes the relay signed.")
    return OK


def run_conformance(args) -> int:
    vectors = args.vectors
    results = conformance.run(vectors)
    # `CONFORMANCE.md` §1 writes the runtime inside the name of the implementation
    # ("my-verifier 0.3.0 (Rust 1.83)"), and a report in a shape of its own is
    # exactly what a fixed format is for. This example is not versioned, so the
    # name is the name and the runtime is the interpreter that ran it.
    runtime = f"CPython {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    print(conformance.report(results, vectors, f"zeknop_example ({runtime})"), end="")
    return OK if all(r.matched == r.compared for r in results) else NEGATIVE


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m zeknop_example",
        description=(
            "An example ZEKNOP client. It is an example and not a library, it makes no "
            "claim about security, performance or privacy, and it comes with no warranty."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    one = commands.add_parser("verify", help="check a signature on a delivered message")
    one.add_argument("file", type=Path, help="the message, as a .eml file")
    one.add_argument("--relay", default="", help="the relay to ask, e.g. https://relay.example.org")
    one.add_argument(
        "--offline",
        action="store_true",
        help="compare the hashes only; ask nobody anything",
    )
    one.set_defaults(handler=verify)

    two = commands.add_parser("sign", help="have a relay sign a message and write the .eml")
    two.add_argument("file", type=Path, help="the message to sign, as a .eml file")
    two.add_argument("--uuid", required=True, help="the identity the relay signs for")
    two.add_argument("--api-key", required=True, help="that identity's own key")
    two.add_argument("--relay", required=True, help="the relay, e.g. https://relay.example.org")
    two.add_argument(
        "--portal",
        required=True,
        help=(
            "the deployment's verification portal, which the link in the block names "
            "(§3.4), e.g. https://verify.example.org/v1"
        ),
    )
    two.add_argument(
        "--from",
        dest="from_address",
        default="",
        help="the From address to sign for, when the message does not carry it",
    )
    two.add_argument(
        "--level", default="", help="the value of X-ZEKNOP-Level, when the deployment uses one"
    )
    two.add_argument(
        "--out", type=Path, default=Path("signed.eml"), help="where to write the result"
    )
    two.set_defaults(handler=sign)

    three = commands.add_parser("conformance", help="run every vector file and report")
    three.add_argument(
        "--vectors",
        type=Path,
        default=Path(__file__).resolve().parents[3] / "vectors",
        help="the directory holding the vector files",
    )
    three.set_defaults(handler=run_conformance)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.handler(args)
    except FileNotFoundError as missing:
        print(f"{missing}")
        return UNANSWERED
    except Exception as unexpected:  # noqa: BLE001 — see below
        # Anything that got this far is a question that could not be answered, and
        # that is the one thing this has to say. A traceback leaves the process
        # with Python's own exit 1, and 1 is the code for a statement ABOUT THE
        # MESSAGE: a reader or a script above this one would read "negative" out
        # of a bug in here. So the type is printed, for whoever is debugging, and
        # the code is 2.
        print(f"Could not be answered: {type(unexpected).__name__}: {unexpected}")
        return UNANSWERED
