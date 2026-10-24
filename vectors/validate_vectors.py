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


def body_from_recipe(parts) -> str:
    """A body given as pieces instead of a literal: {"literal": s} and {"repeat": s,
    "count": n}, the vocabulary the free-form lab vectors already use. A body over the §2
    size limit cannot be inlined in a vector file, and a body_length alone cannot say WHICH
    character sits in front of the cut."""
    return "".join(
        piece["literal"] if "literal" in piece else piece["repeat"] * piece["count"]
        for piece in parts
    )


def canonical_json_from_recipe(vector, max_body_size: int):
    """The canonical JSON of a recipe vector, or None when the vector is not one.

    This script REHASHES what the vectors state; it is not a second implementation of §1
    to §5. So the one rule applied here is the §2 body size limit — the first
    `max_body_size` CODE POINTS — and the vector must be written so that nothing else of
    §2 to §5 has any work to do. That is asserted below, never assumed: a recipe whose
    pieces carry a line end, trailing white space, a BOM or a non-canonical address would
    be refused here instead of being hashed against a rule this file does not know.
    """
    given = vector.get("input", {})
    parts = given.get("body_parts")
    if not parts:
        return None
    body = body_from_recipe(parts)
    for forbidden in ("\r", "\n", "\ufeff"):
        assert forbidden not in body, f"{vector['id']}: the recipe needs §2 normalisation"
    assert body == body.strip() and "\t" not in body, (
        f"{vector['id']}: the recipe needs §2 normalisation")
    to_field = given["to"]
    to_field = ", ".join(to_field) if isinstance(to_field, list) else to_field
    for field in (given["from"], to_field, given["subject"]):
        assert field == field.strip(), f"{vector['id']}: {field!r} needs canonicalisation"
    assert given["from"] == given["from"].lower(), f"{vector['id']}: from needs lowercasing"
    cut = body[:max_body_size]
    stated = vector["expected"].get("truncated_body_length")
    if stated is not None:
        assert len(cut) == stated, (
            f"{vector['id']}: the cut is {len(cut)} code points, the vector says {stated}")
    obj = {
        "from": given["from"],
        "to": to_field,
        "subject": given["subject"],
        "body": cut,
        "timestamp": given["timestamp"],
    }
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


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
    max_body_size = data.get("max_body_size") or 1024 * 1024
    passed = 0
    failed = 0
    skipped = 0

    for v in vectors:
        vid = v["id"]
        expected = v["expected"]

        canonical_json = expected.get("canonical_json")
        content_hash = expected.get("content_hash")

        if not canonical_json:
            # A body too big to inline is given as a recipe; the canonical JSON is built
            # from it here rather than stored (see canonical_json_from_recipe).
            canonical_json = canonical_json_from_recipe(v, max_body_size)

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
