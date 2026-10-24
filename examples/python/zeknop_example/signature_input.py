# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zeknod OÜ
"""The bytes a ZEKNOP signature is made over (`signature-input.md` §2 and §4).

Written from that section, and held to `../../vectors/signature-input-vectors.json`
by the `conformance` command. Nothing here signs or verifies anything: the bytes
are what a relay signs and what a relay verifies, and this module only assembles
them, which is what lets you see that two messages differing in their version
field are two different questions.
"""

import base64

# §1 — the versions of the signature input, oldest first. Taken from the copy of the
# reference implementation's registry so that this example cannot drift from it.
from .canonicalization.sig_alg import INPUT_VERSIONS as VERSIONS

#: §2 — ten bytes, fixed, and the only field without a length in front of it.
DOMAIN_SEPARATOR = b"ZEKNOP-SIG"

#: §2 — each field after the separator carries its length as one unsigned byte.
MAX_FIELD = 255

#: §2 — the hashes enter the input as the raw 32 bytes of SHA-256.
HASH_LENGTH = 32


def _field(value: bytes) -> bytes:
    if len(value) > MAX_FIELD:
        raise ValueError(f"a signature input field is at most {MAX_FIELD} bytes: {len(value)}")
    return bytes([len(value)]) + value


def decode_hash(value: str) -> bytes:
    """One base64 hash, as a header and the API carry it, as its raw bytes."""
    raw = base64.b64decode(value, validate=True)
    if len(raw) != HASH_LENGTH:
        raise ValueError(f"a hash is {HASH_LENGTH} bytes, this one is {len(raw)}")
    return raw


def build(version: str, algorithm: str, strict_hash: bytes, free_hash: bytes) -> bytes:
    """The length-prefixed input of §2.

    Order is fixed: separator, version, algorithm, strict hash, free hash. The
    lengths are what keep version `1.4` with algorithm `ed25519` and version
    `1.4e` with algorithm `d25519` from being the same bytes. A field that cannot
    be expressed raises rather than being truncated — a shorter input is a
    different question, and asking it is worse than refusing.
    """
    for name, value in (("strict hash", strict_hash), ("free hash", free_hash)):
        if len(value) != HASH_LENGTH:
            raise ValueError(f"the {name} is {HASH_LENGTH} bytes, this one is {len(value)}")
    return (
        DOMAIN_SEPARATOR
        + _field(version.encode("utf-8"))
        + _field(algorithm.encode("utf-8"))
        + _field(strict_hash)
        + _field(free_hash)
    )


def for_message(version, algorithm, strict_hash: bytes, free_hash) -> bytes:
    """The input for a message that announces `version` (§2 for a version of this
    specification, §4 for a message from before it).

    A message that announces no version of the input, or none at all, is read over
    the strict hash alone: no separator, no version, no algorithm, no free hash.
    That is every message signed before v1.4 and it goes on verifying unchanged. A
    version this reader has never heard of must never reach here — §4 says such a
    message is not read over the old input either, or naming a version that does
    not exist would be a way of asking for the weaker check.
    """
    if version in VERSIONS:
        if free_hash is None:
            raise ValueError(f"version {version} needs the free hash as well as the strict hash")
        return build(version, algorithm, strict_hash, free_hash)
    return strict_hash
