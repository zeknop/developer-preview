#!/usr/bin/env python3
# Licence: Creative Commons Attribution 4.0 International (CC BY 4.0)
#          https://creativecommons.org/licenses/by/4.0/
# Publisher: Zeknod OÜ
# Part of: the ZEKNOP Signed Email specification, Developer Preview
"""
spec/test-vectors/parts-manifest-vectors.json — the ONE reading of a boundary
parameter (spec/canonical-content.md §9.2a).

Every vector is a whole `Content-Type` field, the boundary §9.2a reads out of it, and
the leaves the walk of §9.1 then finds in one fixed two-part message. The expected
values are written HERE, from the rule in the specification, and are not read out of a
walker: a reader that drifts must not be able to move its own vectors.

Usage:
    python3 parts_manifest_vectors.py            # rewrite the JSON next to this file
    python3 parts_manifest_vectors.py --check    # exit 1 when the JSON differs
"""

import json
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent / "parts-manifest-vectors.json"

# The message every vector is read as: two displayed parts, delimiters written --SEP.
HEAD = "From: a@example.org\r\nTo: b@example.com\r\nSubject: shape\r\n" "MIME-Version: 1.0\r\n"
PARTS = (
    "\r\n--SEP\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nAmount due: 100 EUR\r\n"
    "--SEP\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Amount due: 100 EUR</p>\r\n"
    "--SEP--\r\n"
)

# id → (the parameters of the Content-Type field, the boundary §9.2a reads, the leaves,
#       why the shape is here)
VECTORS = [
    (
        "pm-001-plain",
        '; boundary="SEP"',
        "SEP",
        ["plain", "html"],
        "the control: one parameter, written the ordinary way",
    ),
    (
        "pm-002-plain-unquoted",
        "; boundary=SEP",
        "SEP",
        ["plain", "html"],
        "a bare plain value runs to the next '\"' or ';', and the trim set comes off its ends",
    ),
    (
        "pm-003-plain-spaced",
        '; boundary = "SEP"',
        "SEP",
        ["plain", "html"],
        "white space around the '=' of a PLAIN parameter is allowed (§9.2a point 1)",
    ),
    (
        "pm-004-segments",
        ';\r\n boundary*0="S"; boundary*1="EP"',
        "SEP",
        ["plain", "html"],
        "the segments of RFC 2231 §3, joined — over a folded field",
    ),
    (
        "pm-005-segments-unquoted",
        "; boundary*0=S; boundary*1=EP",
        "SEP",
        ["plain", "html"],
        "the same, with bare values",
    ),
    (
        "pm-006-segments-extended",
        "; boundary*0*=us-ascii''S; boundary*1*=EP",
        "SEP",
        ["plain", "html"],
        "the extended spelling: charset'language' on the first segment",
    ),
    (
        "pm-007-segments-extended-only",
        "; boundary*=us-ascii''SEP",
        "SEP",
        ["plain", "html"],
        "one extended segment with no number is section 0",
    ),
    (
        "pm-008-segments-single",
        '; boundary*0="SEP"',
        "SEP",
        ["plain", "html"],
        "a single segment is the whole value",
    ),
    (
        "pm-009-segments-out-of-order",
        '; boundary*1="EP"; boundary*0="S"',
        "SEP",
        ["plain", "html"],
        "the ORDER of the segments in the field does not matter (point 2)",
    ),
    (
        "pm-010-segments-space-after-eq",
        '; boundary*0= "S"; boundary*1= "EP"',
        "SEP",
        ["plain", "html"],
        "white space AFTER the '=' of a segment is allowed (point 1)",
    ),
    (
        "pm-011-segments-all-upper",
        '; BOUNDARY*0="S"; BOUNDARY*1="EP"',
        "SEP",
        ["plain", "html"],
        "one case throughout: the group folds, the lookup is case-insensitive",
    ),
    (
        "pm-012-segments-space-before-eq",
        '; boundary*0 = "S"; boundary*1 = "EP"',
        "",
        ["opaque"],
        "white space BEFORE the '=' means it is no segment — §9.2 fail-closed",
    ),
    (
        "pm-013-segments-space-before-eq-tight-value",
        '; boundary*0 ="S"; boundary*1 ="EP"',
        "",
        ["opaque"],
        "the same, with no space after the '='",
    ),
    (
        "pm-014-segments-mixed-case",
        '; boundary*0="S"; BOUNDARY*1="EP"',
        "S",
        ["opaque"],
        "two groups (point 3): only *0 of the first one folds, and --S is no delimiter here",
    ),
    (
        "pm-015-segments-leading-zero",
        '; boundary*0="S"; boundary*01="EP"',
        "S",
        ["opaque"],
        "*01 is not *1 (point 2): the join stops after *0",
    ),
    (
        "pm-016-segments-zero-zero",
        '; boundary*00="S"; boundary*1="EP"',
        "",
        ["opaque"],
        "*00 is not *0 either: nothing folds and the field has no usable boundary",
    ),
    (
        "pm-017-segments-gap",
        '; boundary*0="S"; boundary*2="EP"',
        "S",
        ["opaque"],
        "a gap in the numbering stops the join",
    ),
    (
        "pm-018-plain-wins",
        '; boundary="XX"; boundary*0="S"; boundary*1="EP"',
        "XX",
        ["opaque"],
        "a plain parameter wins over the segments (point 5)",
    ),
    (
        "pm-019-plain-wins-written-after",
        '; boundary*0="S"; boundary*1="EP"; boundary="XX"',
        "XX",
        ["opaque"],
        "and it wins wherever in the field it stands",
    ),
    (
        "pm-020-empty-plain",
        '; boundary=""',
        "",
        ["opaque"],
        "an empty boundary is no boundary (point 6)",
    ),
    # The white space of point 6 is the trim set of §2 step 4 — the signer's `trim()` and
    # the `\s` of its RegExp — and NOT the white space of the reader's own language. The
    # seven below are written over the code points where Python's `str.strip()`,
    # `str.isspace()` and `re` `\s` differ from that set: U+001C-U+001F and U+0085, which
    # Python takes and the set does not, and U+FEFF, which the set takes and Python does
    # not. A character outside ASCII is written in the RFC 2231 extended spelling, because
    # a raw non-ASCII byte in a header field is read by the signer as latin-1 and by the
    # portal as UTF-8 — a different question, measured nowhere here.
    (
        "pm-021-quoted-unit-sep",
        '; boundary="\u001fSEP"',
        "\u001fSEP",
        ["opaque"],
        "U+001F (UNIT SEPARATOR) inside the quotes is not trim-set white space, so it stays "
        "in the boundary and --SEP is no delimiter: one opaque leaf",
    ),
    (
        "pm-022-unit-sep-before-eq",
        '; boundary\u001f="SEP"',
        "",
        ["opaque"],
        "U+001F between the attribute and the '=' is not white space either, so this is no "
        "`boundary=` parameter at all — §9.2 fail-closed",
    ),
    (
        "pm-023-segment-unit-sep",
        "; boundary*0=\u001fS; boundary*1=EP",
        "\u001fSEP",
        ["opaque"],
        "and it is not skipped before a segment value: the segments join to U+001F + SEP",
    ),
    (
        "pm-024-ext-nel",
        "; boundary*=utf-8''%C2%85SEP",
        "\u0085SEP",
        ["opaque"],
        "U+0085 (NEL) percent-decoded out of an extended segment stays in the boundary",
    ),
    (
        "pm-025-ext-bom",
        "; boundary*=utf-8''%EF%BB%BFSEP",
        "SEP",
        ["plain", "html"],
        "U+FEFF IS trim-set white space, so it comes off and the container splits",
    ),
    (
        "pm-026-ext-bom-trailing",
        "; boundary*=utf-8''SEP%EF%BB%BF",
        "SEP",
        ["plain", "html"],
        "the same at the end of the value",
    ),
    (
        "pm-027-ext-nbsp",
        "; boundary*=utf-8''%C2%A0SEP",
        "SEP",
        ["plain", "html"],
        "the control: U+00A0 is in BOTH sets, so this vector reads the same before and after "
        "the trim set was named in point 6",
    ),
]


def build() -> dict:
    return {
        "about": (
            "The ONE reading of a boundary parameter (spec/canonical-content.md §9.2a). "
            "`content_type` is the whole field; `boundary` is what §9.2a reads out of it "
            '("" = none, so the container is one opaque leaf); `manifest` is the `k` of '
            "each leaf the §9.1 walk then finds in `message_hex`. The reading is the "
            "signer's, because the signature covers the manifest the signer built."
        ),
        "spec": "spec/canonical-content.md §9.2a",
        "regenerate": "python3 spec/test-vectors/parts_manifest_vectors.py",
        "message": {
            "about": (
                "The message every vector is read as: the head below, then the "
                "Content-Type field of the vector, then two displayed parts whose "
                "delimiters are written --SEP."
            ),
            "head": HEAD,
            "parts": PARTS,
        },
        "vectors": [
            {
                "id": vid,
                "content_type": "multipart/alternative" + params,
                "boundary": boundary,
                "manifest": manifest,
                "why": why,
                "message_hex": (
                    HEAD + "Content-Type: multipart/alternative" + params + "\r\n" + PARTS
                )
                .encode("utf-8")
                .hex(),
            }
            for vid, params, boundary, manifest, why in VECTORS
        ],
    }


def main():
    text = json.dumps(build(), ensure_ascii=False, indent=2) + "\n"
    if "--check" in sys.argv:
        if not OUT.is_file() or OUT.read_text(encoding="utf-8") != text:
            print(
                "parts-manifest-vectors.json is stale "
                "(run spec/test-vectors/parts_manifest_vectors.py)"
            )
            return 1
        print(f"parts manifest vectors current: {len(build()['vectors'])} vectors")
        return 0
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.name}: {len(build()['vectors'])} vectors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
