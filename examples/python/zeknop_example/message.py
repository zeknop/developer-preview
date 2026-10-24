# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zeknod OÜ
"""What a verifier reads off a delivered message, and the two hashes it recomputes.

The order of the work is the order of the specification, and it is not an
accident:

1. the visible block is taken off every displayed part first
   (`delivered-envelope.md` §6.1). It is written after signing and is not covered
   by the signature, so a verifier that hashes it finds a message nobody touched
   to be changed;
2. the shape is chosen from the STRUCTURE of the message and never from a header
   (`canonical-content.md` §1.1), so it cannot be moved by an attacker;
3. the strict hash is taken over the canonical object of that shape (§1-§2, §9);
4. the free hash is taken over the free text form of the one displayed part §2b.1
   names;
5. only then are the two hashes compared with what the message claims, and only
   then is a relay asked anything.

Nothing here decides a verdict about an identity: that question belongs to the
relay, and `relay.py` asks it.
"""

import base64
import binascii
import email
import email.policy
import json
import uuid as uuid_module
from dataclasses import dataclass, field
from datetime import datetime
from email.message import EmailMessage

from . import signature_input
from .canonicalization import canonical, message_fields, mime_walk, sig_alg

#: The fields a signer writes (`signature-input.md` §1, `delivered-envelope.md` §3.1).
#: A verifier reads them and trusts none of them: every hash is recomputed.
HEADER_VERSION = "X-ZEKNOP-Version"
HEADER_SIG_ALG = "X-ZEKNOP-Sig-Alg"
HEADER_SIGNATURE = "X-ZEKNOP-Signature"
HEADER_HASH = "X-ZEKNOP-Hash"
HEADER_UUID = "X-ZEKNOP-UUID"
HEADER_TIMESTAMP = "X-ZEKNOP-Timestamp"
HEADER_RELAY = "X-ZEKNOP-Relay"
HEADER_LEVEL = "X-ZEKNOP-Level"
HEADER_ENVELOPE_ID = "X-ZEKNOP-Envelope-ID"
HEADER_VERIFY = "X-ZEKNOP-Verify"

#: Fields that carry somebody else's VERDICT rather than a signature. A sender can
#: write them, so a verifier removes them before it reads anything and forms its
#: own verdict from the bytes.
RESULT_CLAIM_HEADERS = (
    "X-ZEKNOP-Verified",
    "X-ZEKNOP-Status",
    "X-ZEKNOP-Content-Verified",
    "X-ZEKNOP-Content-Verified-Details",
    "X-ZEKNOP-Content-Verified-Level",
    "X-ZEKNOP-Content-Verified-Since",
    "X-ZEKNOP-Trust-Tier",
)


@dataclass
class Claimed:
    """The ZEKNOP fields of the message, as written, with nothing checked yet."""

    version: str | None = None
    sig_alg_values: list[str] = field(default_factory=list)
    signature: str | None = None
    content_hash: str | None = None
    uuid: str | None = None
    timestamp: str | None = None
    relay: str | None = None
    level: str | None = None
    envelope_id: str | None = None
    verify_url: str | None = None


@dataclass
class Recomputed:
    """What the bytes of the message actually say."""

    shape: str
    canonical_object: dict
    canonical_json: str
    content_hash: str
    free_hash: str | None
    free_is_html: bool
    from_address: str
    recipients: list[str]
    subject: str
    #: `None` for a message read over the old input of §4, where there is none.
    algorithm: str | None
    #: The problem the algorithm field has, in the words of the registry, or `None`.
    algorithm_problem: str | None
    #: "current", "legacy" or "unknown" for the version field (§1, §4).
    version_state: str
    #: The version a verifier names to the relay, or `None` (§2, §4).
    accepted_version: str | None
    #: The outer visible block of each displayed part, or `None` where there is none.
    envelope_kinds: list[str | None]

    @property
    def carries_not_verified_envelope(self) -> bool:
        """§6.1 step 1: a message delivered as one the signer could not sign.

        There is nothing to verify, whatever fields it carries. A not-verified
        block quoted INSIDE the content of a positive block is content and does
        not count, which is why the outer kind is what is read.
        """
        return any(kind == "not-verified" for kind in self.envelope_kinds)

    def signature_input(self) -> bytes:
        """The bytes this message's signature was made over (§2, §4)."""
        strict = signature_input.decode_hash(self.content_hash)
        free = signature_input.decode_hash(self.free_hash) if self.free_hash else None
        return signature_input.for_message(self.accepted_version, self.algorithm, strict, free)


def parse(raw: bytes) -> EmailMessage:
    """The message as the standard library reads it, with result claims removed."""
    message = email.message_from_bytes(raw, policy=email.policy.default)
    for name in RESULT_CLAIM_HEADERS:
        while message.get(name) is not None:
            del message[name]
    return message


def claimed(message: EmailMessage) -> Claimed:
    """The ZEKNOP fields as written. Every instance of the algorithm field, not the
    first: a message naming more than one algorithm names no one algorithm
    (`signature-input.md` §1), and dropping the second instance would hide that.
    """
    return Claimed(
        version=message.get(HEADER_VERSION),
        sig_alg_values=[str(v) for v in (message.get_all(HEADER_SIG_ALG) or [])],
        signature=message.get(HEADER_SIGNATURE),
        content_hash=message.get(HEADER_HASH),
        uuid=message.get(HEADER_UUID),
        timestamp=message.get(HEADER_TIMESTAMP),
        relay=message.get(HEADER_RELAY),
        level=message.get(HEADER_LEVEL),
        envelope_id=message.get(HEADER_ENVELOPE_ID),
        verify_url=message.get(HEADER_VERIFY),
    )


def shape_problem(fields: Claimed) -> str:
    """What is wrong with the SHAPE of the signature material, before anyone is asked.

    These values come off fields a sender writes, so "not even the right shape" is
    a question a reader can answer by itself — and must answer by itself, for two
    reasons that are both about not making a claim: the relay's answer to a
    malformed question is a refusal and not a verdict, and a reader that has read
    no content has to say "could not check" rather than "changed".

    Returns '' when the material is the right shape, or a short phrase naming the
    first field that is not.
    """
    for name, value in (
        ("signature", fields.signature),
        ("hash", fields.content_hash),
        ("uuid", fields.uuid),
        ("timestamp", fields.timestamp),
    ):
        if not value:
            return f"{name} missing"
    digest = _base64_bytes(fields.content_hash)
    if digest is None or len(digest) != 32:
        return "hash is not base64 of a SHA-256 digest"
    if _base64_bytes(fields.signature) is None:
        return "signature is not base64"
    try:
        uuid_module.UUID(str(fields.uuid).strip())
    except ValueError:
        return "uuid is not a UUID"
    try:
        datetime.fromisoformat(str(fields.timestamp).strip().replace("Z", "+00:00"))
    except ValueError:
        return "timestamp is not an ISO 8601 instant"
    return ""


def _base64_bytes(value: str):
    """The bytes of a standard-base64 value, or None when it is not base64 at all."""
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        return None


def displayed_texts(raw: bytes, message: EmailMessage) -> list[str]:
    """The texts the visible block is taken off before hashing: the body of a Shape
    A message, or every `k:"plain"` leaf of the Shape B manifest in document order.
    The same texts, decoded the same way, as the hashes are computed over.
    """
    root = mime_walk.parse_part(raw)
    if mime_walk.is_shape_a(root):
        return [message_fields.extract_plain_text(message)]
    texts: list[str] = []

    def keep(text: str) -> str:
        texts.append(text)
        return text

    mime_walk.extract_parts_manifest(root, plain_transform=keep)
    return texts


@dataclass
class Read:
    """Everything the two hashes are made of EXCEPT the timestamp.

    The timestamp is one field of the canonical object (§1.1) and nothing that is
    read off the message depends on it, so the two can be separated — and for a
    signer they have to be. The copy of the reference implementation says why
    above `normalize_body` in `canonicalization/canonical.py`: hashing a large
    body takes long enough that a timestamp sampled BEFORE the work can be
    refused as stale by the time the signing request arrives, and the relay's
    window is 30 seconds. So a signer reads the message first, samples the
    timestamp after, and hands both to `canonical_at`.
    """

    shape: str
    from_address: str
    recipients: list[str]
    subject: str
    #: Shape A — the body with the visible block taken off; `None` for Shape B.
    body: str | None
    #: Shape B — the parts manifest of §9 in document order; `None` for Shape A.
    parts: list | None
    free_hash: str | None
    free_is_html: bool
    algorithm: str | None
    algorithm_problem: str | None
    version_state: str
    accepted_version: str | None
    envelope_kinds: list[str | None]
    #: The timestamp the message itself carries, which is what a VERIFIER hashes.
    claimed_timestamp: str


def read_message(
    raw: bytes,
    message: EmailMessage | None = None,
    algorithm: str | None = None,
) -> Read:
    """Everything above, from the bytes. This is the expensive half: the MIME walk,
    the decoding of every part, the removal of the visible block and the free text
    form all happen here, and none of them reads the timestamp.
    """
    message = parse(raw) if message is None else message
    fields = claimed(message)

    from_address = message_fields.extract_from_addr(message) or ""
    recipients = message_fields.extract_recipients(message)
    # §5: the encoded words of the RAW Subject are read by the same rule, with the
    # same tables, as the text of a part, and the result is trimmed by the same
    # characters as every other canonical field. The standard library would decode
    # the field with its own codecs, which read a windows-1250 or an ISO-2022-JP
    # word differently from a signer.
    subject = canonical.trim(
        mime_walk.decode_encoded_words(mime_walk.first_raw_header(raw, "Subject"))
    )

    root = mime_walk.parse_part(raw)
    body = None
    parts = None
    if mime_walk.is_shape_a(root):
        shape = "A"
        body = canonical.strip_zeknop_envelope(message_fields.extract_plain_text(message))
    else:
        shape = "B"
        parts = mime_walk.extract_parts_manifest(
            root,
            plain_transform=canonical.strip_zeknop_envelope,
            html_transform=canonical.strip_zeknop_html_envelope,
        )

    version_state = sig_alg.version_state(fields.version)
    read_algorithm, problem = sig_alg.header_algorithm(fields.version, fields.sig_alg_values)
    if algorithm is None:
        algorithm = read_algorithm

    free_hash = None
    free_is_html = False
    if algorithm:
        free_text, free_is_html = mime_walk.free_form_source(
            root,
            strip=canonical.strip_zeknop_envelope,
            html_strip=canonical.strip_zeknop_html_envelope,
        )
        free_hash = canonical.compute_free_hash(free_text, free_is_html)

    return Read(
        shape=shape,
        from_address=from_address,
        recipients=recipients,
        subject=subject,
        body=body,
        parts=parts,
        free_hash=free_hash,
        free_is_html=free_is_html,
        algorithm=algorithm,
        algorithm_problem=problem,
        version_state=version_state,
        accepted_version=sig_alg.accepted_version(fields.version) if algorithm else None,
        envelope_kinds=[
            canonical.delivered_envelope_kind(text) for text in displayed_texts(raw, message)
        ],
        claimed_timestamp=fields.timestamp or "",
    )


def canonical_at(read: Read, timestamp: str | None = None) -> Recomputed:
    """The canonical object of that reading at one timestamp, and its hash (§1.1, §2).

    `timestamp` is what a SIGNER is about to send to the relay. A VERIFIER passes
    nothing and the timestamp the message carries is used: it recomputes the
    object the signer hashed, and the signer hashed the moment it asked.
    """
    if timestamp is None:
        timestamp = read.claimed_timestamp
    if read.shape == "A":
        canonical_object = canonical.build_canonical_content(
            from_addr=read.from_address,
            to_addrs=read.recipients,
            subject=read.subject,
            body=read.body,
            timestamp=timestamp,
        )
    else:
        canonical_object = canonical.build_canonical_content_v13(
            from_addr=read.from_address,
            to_addrs=read.recipients,
            subject=read.subject,
            timestamp=timestamp,
            parts=read.parts,
        )
    return Recomputed(
        shape=read.shape,
        canonical_object=canonical_object,
        canonical_json=canonical_json(canonical_object),
        content_hash=canonical.compute_content_hash(canonical_object),
        free_hash=read.free_hash,
        free_is_html=read.free_is_html,
        from_address=read.from_address,
        recipients=read.recipients,
        subject=read.subject,
        algorithm=read.algorithm,
        algorithm_problem=read.algorithm_problem,
        version_state=read.version_state,
        accepted_version=read.accepted_version,
        envelope_kinds=read.envelope_kinds,
    )


def recompute(
    raw: bytes,
    message: EmailMessage | None = None,
    timestamp: str | None = None,
    algorithm: str | None = None,
) -> Recomputed:
    """The two hashes, from the bytes — the whole of it, in one call.

    A VERIFIER passes neither of the last two arguments: the timestamp is a field
    of the canonical object (§1.1), so it comes from the message and not from the
    clock, and which rules the message was signed under is read off its own
    fields.

    A SIGNER of a small message can pass both, because neither is in the message
    yet. A signer that may be handed a large one calls `read_message` first,
    samples the timestamp after it and finishes with `canonical_at`: the same
    values, in the order that does not spend the relay's 30-second window on
    hashing. `cli.sign` does it that way.
    """
    return canonical_at(read_message(raw, message, algorithm), timestamp)


def canonical_json(canonical_object: dict) -> str:
    """The canonical object as the string that is hashed (§2): UTF-8, no spaces
    after the separators, the key order the object was built with.
    """
    return json.dumps(canonical_object, separators=(",", ":"), ensure_ascii=False)
