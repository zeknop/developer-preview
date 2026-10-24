#!/usr/bin/env python3
# Licence: Creative Commons Attribution 4.0 International (CC BY 4.0)
#          https://creativecommons.org/licenses/by/4.0/
# Publisher: Zeknod OÜ
# Part of: the ZEKNOP Signed Email specification, Developer Preview
"""
spec/test-vectors/signature-input-vectors.json — what a signature is made over
(spec/signature-input.md).

Every vector carries the version, the algorithm, the two hashes and the EXPECTED BYTES,
assembled here from the rule written in the specification and never read out of the
relay: a relay that drifts must not be able to move its own vectors.

Usage:
    python3 signature_input_vectors.py            # rewrite the JSON next to this file
    python3 signature_input_vectors.py --check    # exit 1 when the JSON differs
"""
import base64
import hashlib
import json
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent / "signature-input-vectors.json"

SEPARATOR = b"ZEKNOP-SIG"


def _h(label: str) -> bytes:
    """A recognisable 32-byte hash for a vector — SHA-256 of the label, so the vector
    stays reproducible without any message behind it."""
    return hashlib.sha256(label.encode("utf-8")).digest()


def _field(value: bytes) -> bytes:
    assert len(value) <= 255, value
    return bytes([len(value)]) + value


def _assemble(version: str, algorithm: str, strict: bytes, free: bytes) -> bytes:
    """The form written in spec/signature-input.md §2, typed out here."""
    return (SEPARATOR
            + _field(version.encode("utf-8"))
            + _field(algorithm.encode("utf-8"))
            + _field(strict)
            + _field(free))


STRICT = _h("strict")
FREE = _h("free")

# (id, version, algorithm, strict, free, note)
VECTORS = [
    ("si-001-legacy-input-is-the-strict-hash-alone", "legacy", "ed25519", STRICT, None,
     "A message with X-ZEKNOP-Version 1.0, or none: the signature is made over the 32 "
     "bytes of the strict hash, with nothing around them. Every message written before "
     "v1.4."),
    ("si-002-v14-ed25519", "1.4", "ed25519", STRICT, FREE,
     "The ordinary v1.4 input."),
    ("si-003-v14-same-hashes-different-version", "1.4.1", "ed25519", STRICT, FREE,
     "The version is under the signature: a message relabelled to another version does "
     "not verify against this one."),
    ("si-004-v14-reserved-algorithm", "1.4", "ml-dsa-65", STRICT, FREE,
     "A reserved name is expressible in the input although nothing signs with it — the "
     "form does not change when the registry grows."),
    ("si-005-v14-composite-algorithm", "1.4", "ed25519+ml-dsa-65", STRICT, FREE,
     "The composite name of the hybrid reserved for H1 2027; seventeen bytes long."),
    ("si-006-v14-non-ascii-algorithm-name", "1.4", "ed25519é", STRICT, FREE,
     "Nine UTF-8 bytes for eight characters: the length prefix counts bytes (V-B1)."),
    ("si-007-v14-empty-hash-fields-are-still-length-prefixed", "1.4", "ed25519",
     bytes(32), bytes(32),
     "Two all-zero hashes: the length bytes are still there, so the boundaries hold."),
    ("si-012-v15-ed25519", "1.5", "ed25519", STRICT, FREE,
     "The ordinary v1.5 input: the same construction as si-002 with the version field one "
     "value further on. Version 1.5 was added because §6.1 began taking the visible "
     "envelope off an HTML part as well, and a reader has to know which reading the "
     "fingerprint was taken over. Its hashes and algorithm are si-002's: only the version "
     "differs, and the bytes differ with it, so a header edited from 1.5 to 1.4 fails."),
    ("si-010-separation-a", "1.4", "ed25519", STRICT, FREE,
     "Pair with si-011: the same bytes concatenated without lengths would be one string."),
    ("si-011-separation-b", "1.4e", "d25519", STRICT, FREE,
     "Pair with si-010: different fields, therefore different input."),
]


def build():
    vectors = []
    for vid, version, algorithm, strict, free, note in VECTORS:
        if version == "legacy":
            produced = strict
        else:
            produced = _assemble(version, algorithm, strict, free)
        vectors.append({
            "id": vid,
            "version": version,
            "algorithm": algorithm,
            "strict_hash_b64": base64.b64encode(strict).decode(),
            "free_hash_b64": base64.b64encode(free).decode() if free is not None else None,
            "signature_input_hex": produced.hex(),
            "note": note,
        })
    return {
        "about": ("The bytes a ZEKNOP signature is made over. 'legacy' is the input of every "
                  "message before v1.4: the strict hash on its own. Every other vector is the "
                  "length-prefixed form of spec/signature-input.md §2, assembled by this script "
                  "from the specification and not from the relay."),
        "spec": "spec/signature-input.md",
        "separator": SEPARATOR.decode("ascii"),
        "regenerate": "python3 spec/test-vectors/signature_input_vectors.py",
        "vectors": vectors,
    }


def main():
    text = json.dumps(build(), ensure_ascii=False, indent=2) + "\n"
    if "--check" in sys.argv:
        if not OUT.is_file() or OUT.read_text(encoding="utf-8") != text:
            print("signature-input-vectors.json is stale (run spec/test-vectors/signature_input_vectors.py)")
            return 1
        print(f"signature input vectors current: {len(build()['vectors'])} vectors")
        return 0
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.name}: {len(build()['vectors'])} vectors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
