# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zeknod OÜ
#
# A copy of the ZEKNOP reference implementation of the canonical content
# specification, carried by the Python example so that the example computes the
# same bytes as the service that signed the message. Apart from this header and
# the substitutions recorded with the copy, nothing in this file was changed.
"""
The algorithm a message says its signature was made with (signature-input.md §1, §3).

The registry is normative: §3 is the list, and a verifier reads the value off a
header, so every name a sender can write falls into one of its three states.

A verifier reads the value off a header, so nothing here raises on anything: a name it cannot
check is a verdict, not an exception.
"""

VERSION_HEADER = "X-ZEKNOP-Version"
ALGORITHM_HEADER = "X-ZEKNOP-Sig-Alg"

# Every version of the signature input this build can BUILD, oldest first (spec §4). A message
# announcing one of them is read over the length-prefixed input of §2 with ITS OWN version
# inside, so mail signed under an older one goes on verifying exactly as it was signed. The
# last entry is what a signer of this build writes; anything not in this list and not in
# LEGACY_VERSIONS is a version this build has never heard of.
INPUT_VERSIONS = ("1.4", "1.5")

# What a SIGNER of this build writes into X-ZEKNOP-Version: the newest version it can build.
# Anything outside INPUT_VERSIONS — including no version at all — is not read over §2.
SIGNATURE_INPUT_VERSION = "1.5"

# The versions of the signature input a message may announce and this build can still read. A
# message with NO version header, and one announcing a version from this list, is a message from
# before v1.4 and is read over the old input (§4); "1.0" is what every signer wrote until v1.4.
# ANYTHING ELSE is a version this build has never heard
# of — a message from a signer newer than this reader — and §4 says such a message is not green and
# is NOT read over the old input either: falling back would make "name a version that does not
# exist" a way of asking for the weaker check.
#
# A reader that has not been brought to this rule yet treats such a message as
# merely not green instead of saying which version it could not read. Either way
# it is never green, which is the invariant.
LEGACY_VERSIONS = ("1.0",)

SIGNED_ALGORITHMS = ("ed25519",)
RESERVED_ALGORITHMS = (
    "ml-dsa-44",
    "ml-dsa-65",
    "slh-dsa-sha2-128s",
    "ed25519+ml-dsa-65",
)
LEGACY_ALGORITHM = "ed25519"

# Why a v1.4 message cannot be verified, in the words the verifier reports.
MISSING = "the message announces a signature version and names no algorithm"
DUPLICATE = "the message names more than one algorithm"
UNSUPPORTED = "unsupported algorithm"
UNKNOWN_VERSION = "unknown version"


def version_state(version) -> str:
    """One of "current", "legacy", "unknown" for the value of X-ZEKNOP-Version. Never raises: the
    value came off a header a sender can write. The version is trimmed here for the same reason
    header_algorithm trims it — the readers get it from different parsers and a message must not be
    read as one version by one of them and as another by the next."""
    text = str(version or "").strip()
    if text in INPUT_VERSIONS:
        return "current"
    if text == "" or text in LEGACY_VERSIONS:
        return "legacy"
    return "unknown"


def accepted_version(version):
    """The version a VERIFIER names to the relay: the one the MESSAGE announces, trimmed,
    when this build can build its input — and None otherwise (spec §2, §4).

    Never this build's own newest version. The version is INSIDE the signed bytes, so
    naming any other value makes the relay rebuild a different input and the signature
    cannot match: a message signed under an older version would come back invalid, about
    a message nobody touched. What the CALLER can build is a different field entirely
    (`understands`, signature-input.md §4a) and that one IS a constant of this build.
    """
    text = str(version or "").strip()
    return text if text in INPUT_VERSIONS else None


def algorithm_state(name) -> str:
    """One of "signed", "reserved", "unknown". Never raises."""
    if name in SIGNED_ALGORITHMS:
        return "signed"
    if name in RESERVED_ALGORITHMS:
        return "reserved"
    return "unknown"


def header_algorithm(version, values) -> tuple:
    """(algorithm, problem) for a message whose version header is `version` and whose
    X-ZEKNOP-Sig-Alg instances are `values`.

    * a version outside INPUT_VERSIONS, or none: (None, None) — the old input, ed25519 (§4);
    * a version in INPUT_VERSIONS: exactly one instance, naming an algorithm this build can
      check, or a problem.

    BOTH values are the field body with the whitespace around it removed — what unfolding
    leaves, and what every reader of these headers sees — and are then compared byte for byte
    and with regard to case: `Ed25519` is not `ed25519`. The version is trimmed here and not at
    the call sites, because readers get it from different header parsers — one keeps a
    trailing space, another keeps the line feed — and a message must not be read as a
    current version by one of them and as an older one by another.
    """
    if str(version or "").strip() not in INPUT_VERSIONS:
        return None, None
    names = [str(v).strip() for v in (values or [])]
    if not names:
        return None, MISSING
    if len(names) > 1:
        return None, DUPLICATE
    name = names[0]
    if algorithm_state(name) != "signed":
        return name, UNSUPPORTED
    return name, None
