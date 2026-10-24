#!/usr/bin/env python3
# Licence: Creative Commons Attribution 4.0 International (CC BY 4.0)
#          https://creativecommons.org/licenses/by/4.0/
# Publisher: Zeknod OÜ
# Part of: the ZEKNOP Signed Email specification, Developer Preview
"""
ZEKNOP Canonical Content Specification — Test Vector Validator

Validates vectors.json by recomputing hashes from canonical_json fields
and checking they match the expected content_hash.

Usage:
    python validate_vectors.py          # validate existing vectors.json
    python validate_vectors.py --dump   # also print canonical JSON for each vector
    python validate_vectors.py <file>   # another vector file

The file it validates is the one NEXT TO THIS SCRIPT, whatever directory it is run from.
A run that validates NOTHING is an error here, never a pass: the exit code is 2 when
the file is missing, when it holds no vectors, and when every vector was skipped.
"""

import json
import hashlib
import base64
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def compute_hash_from_json(json_str: str) -> str:
    digest = hashlib.sha256(json_str.encode("utf-8")).digest()
    return base64.b64encode(digest).decode("ascii")


def validate_vectors(vectors_path=None, dump: bool = False) -> int:
    path = Path(vectors_path) if vectors_path else HERE / "vectors.json"
    if not path.is_file():
        print(f"ERROR: no vector file at {path}")
        return 2
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    vectors = data.get("vectors") or []
    if not vectors:
        print(f"ERROR: {path} holds no vectors - nothing was validated")
        return 2
    passed = 0
    failed = 0
    skipped = 0

    for v in vectors:
        vid = v["id"]
        expected = v["expected"]

        canonical_json = expected.get("canonical_json")
        content_hash = expected.get("content_hash")

        if not canonical_json or not content_hash:
            print(f"  SKIP: [{vid}] — no canonical_json or content_hash in expected")
            skipped += 1
            continue

        computed = compute_hash_from_json(canonical_json)

        if dump:
            print(f"\n  [{vid}]")
            print(f"    canonical: {canonical_json[:120]}...")
            print(f"    expected:  {content_hash}")
            print(f"    computed:  {computed}")

        if computed == content_hash:
            print(f"  PASS: [{vid}]")
            passed += 1
        else:
            print(f"  FAIL: [{vid}]")
            print(f"    expected: {content_hash}")
            print(f"    computed: {computed}")
            failed += 1

    print(f"\nResults: {passed} passed, {failed} failed, {skipped} skipped out of {len(vectors)} vectors")
    if failed:
        return 1
    if passed == 0:
        print("ERROR: every vector was skipped - nothing was validated")
        return 2
    return 0


def main():
    dump = "--dump" in sys.argv
    given = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(given) > 1:
        print("usage: validate_vectors.py [--dump] [<vector file>]")
        return 2
    return validate_vectors(given[0] if given else None, dump=dump)


if __name__ == "__main__":
    sys.exit(main())
