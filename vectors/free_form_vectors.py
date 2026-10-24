#!/usr/bin/env python3
# Licence: Creative Commons Attribution 4.0 International (CC BY 4.0)
#          https://creativecommons.org/licenses/by/4.0/
# Publisher: Zeknod OÜ
# Part of: the ZEKNOP Signed Email specification, Developer Preview
"""
spec/test-vectors/free-form-vectors.json — the free text form of spec §2b.

Every vector carries the INPUT and the EXPECTED TEXT, both typed here by hand
from the rules of §2b, and never taken from an implementation: a signer or a
verifier that drifts must not be able to move its own vectors. The hash in the
JSON is SHA-256 of the expected text as UTF-8, base64 — computed from the typed
text alone, by this script, with no free-form code involved.

Usage:
    python3 free_form_vectors.py            # rewrite the JSON next to this file
    python3 free_form_vectors.py --check    # exit 1 when the JSON differs
"""
import base64
import hashlib
import json
import sys
from pathlib import Path

INVOICE = "Amount due: 4 200 EUR\nAccount: LT12 3456 7890\nThank you."
INVOICE_FLAT = "Amount due: 4 200 EUR Account: LT12 3456 7890 Thank you."

# (id, kind, input, expected text)
VECTORS = [
    # ── the steps of §2b.2 ───────────────────────────────────────────────────
    ("ff-001-plain-invoice", "text", INVOICE, INVOICE_FLAT),
    ("ff-002-crlf-and-trailing-spaces", "text",
     "Amount due: 4 200 EUR \r\nAccount: LT12 3456 7890 \r\nThank you. \r\n", INVOICE_FLAT),
    ("ff-003-rewrapped-lines", "text",
     "Amount due: 4 200 EUR\nAccount: LT12 3456\n7890\nThank you.", INVOICE_FLAT),
    ("ff-004-no-break-spaces", "text",
     "Amount due: 4 200 EUR\nAccount: LT12 3456 7890\nThank you.", INVOICE_FLAT),
    ("ff-005-blank-lines-flattened", "text", "a\n\n\n\nb", "a b"),
    ("ff-006-tabs-and-exotic-spaces", "text",
     "a\t    　b", "a b"),
    ("ff-007-line-and-paragraph-separators", "text", "a b c", "a b c"),
    ("ff-008-next-line-is-whitespace-here", "text", "a\u0085b", "a b"),
    ("ff-009-zero-width-no-break-space-is-removed", "text",
     "﻿a﻿b﻿", "ab"),
    ("ff-010-trim-both-ends", "text", "   \n\t a b \n   ", "a b"),
    ("ff-011-empty", "text", "", ""),
    ("ff-012-whitespace-only", "text", " \n\t  ", ""),

    # ── NFC, §2b.2 step 5 ────────────────────────────────────────────────────
    ("ff-020-nfc-composes", "text", "Å", "Å"),
    ("ff-021-nfc-singleton-angstrom", "text", "Å", "Å"),
    ("ff-022-nfc-reorders-by-combining-class", "text", "q̣̇", "q̣̇"),
    ("ff-023-nfc-hangul-composes", "text", "각", "각"),
    ("ff-024-nfc-leaves-an-excluded-pair-apart", "text", "ྲྀ", "ྲྀ"),
    ("ff-025-nfc-does-not-touch-compatibility", "text", "ﬁ", "ﬁ"),

    # ── HTML to text, §2b.3 ──────────────────────────────────────────────────
    ("ff-040-html-blocks-break-lines", "html", "<p>a</p><p>b</p>", "a b"),
    ("ff-041-html-inline-does-not", "html", "a<span>b</span>c", "abc"),
    ("ff-042-html-br", "html", "a<br>b", "a b"),
    ("ff-043-html-attribute-containing-gt", "html", '<a title="x>y">link</a>tail', "linktail"),
    ("ff-044-html-single-quoted-attribute-containing-gt", "html",
     "<a title='x>y'>link</a>tail", "linktail"),
    ("ff-045-html-comment-dropped", "html", "<!-- hidden -->shown", "shown"),
    ("ff-046-html-unterminated-comment-eats-the-rest", "html", "<!-- hidden shown", ""),
    ("ff-047-html-cdata-is-a-bogus-comment", "html", "<![CDATA[hidden]]>after", "after"),
    ("ff-048-html-doctype-dropped", "html", "<!DOCTYPE html>body", "body"),
    ("ff-049-html-script-content-dropped", "html", "<script>secret()</script>shown", "shown"),
    ("ff-050-html-style-content-dropped", "html", "<style>.x{a:b}</style>shown", "shown"),
    ("ff-051-html-template-content-dropped", "html",
     "<template><p>hidden</p></template>shown", "shown"),
    ("ff-052-html-unclosed-script-eats-the-rest", "html", "<script>never closed", ""),
    ("ff-053-html-lt-that-is-not-a-tag", "html", "a < b and 3<4", "a < b and 3<4"),
    ("ff-054-html-unclosed-attribute-quote-eats-the-rest", "html", "<p a='unclosed>x</p>", ""),
    ("ff-055-html-mobile-forward-shape", "html",
     '<div dir="ltr">Amount due: 4&nbsp;200 EUR<br>Account: LT12 3456 7890<br>Thank you.</div>',
     INVOICE_FLAT),

    # ── character references, §2b.3.1 ────────────────────────────────────────
    ("ff-060-named-with-semicolon", "html", "x&amp;y", "x&y"),
    ("ff-061-legacy-named-without-semicolon", "html", "x&amp y", "x& y"),
    ("ff-062-longest-match-wins", "html", "&notit;", "¬it;"),
    ("ff-063-unknown-name-is-literal", "html", "&unknown;", "&unknown;"),
    ("ff-064-numeric-decimal", "html", "&#65;&#66", "AB"),
    ("ff-065-numeric-hex-both-cases", "html", "&#x41;&#X42;", "AB"),
    ("ff-066-numeric-zero", "html", "&#0;", "�"),
    ("ff-067-numeric-surrogate", "html", "&#xD800;", "�"),
    ("ff-068-numeric-out-of-range", "html", "&#x110000;&#999999999999;", "��"),
    ("ff-069-numeric-c1-becomes-windows-1252", "html", "&#128;&#x9F;", "€Ÿ"),
    ("ff-070-numeric-noncharacter-is-kept", "html", "&#xFFFE;", "￾"),
    ("ff-071-ampersand-with-no-reference", "html", "&#; & &#x;", "&#; & &#x;"),
    ("ff-072-reference-then-nfc", "html", "A&#x30a;", "Å"),
    ("ff-073-long-name", "html", "&CounterClockwiseContourIntegral;", "∳"),

    # ── §2b.5, our envelope comes off before the form is taken ───────────────
    # (the vectors carry the text AFTER removal; the removal itself is §6.1)
    ("ff-080-quoted-envelope-inside-is-content", "text",
     "Reply text\n> ======= ZEKNOP =======\n> quoted body\n> ======= END ZEKNOP =======",
     "Reply text > ======= ZEKNOP ======= > quoted body > ======= END ZEKNOP ======="),
    ("ff-081-indented-envelope-inside-is-content", "text",
     "See below\n    ======= ZEKNOP =======\n    body",
     "See below ======= ZEKNOP ======= body"),

    # ── what MUST change the hash ────────────────────────────────────────────
    ("ff-090-changed-amount", "text", INVOICE.replace("4 200", "4 900"),
     INVOICE_FLAT.replace("4 200", "4 900")),
    ("ff-091-changed-account-number", "text", INVOICE.replace("7890", "7891"),
     INVOICE_FLAT.replace("7890", "7891")),
    ("ff-092-reordered-lines", "text",
     "Account: LT12 3456 7890\nAmount due: 4 200 EUR\nThank you.",
     "Account: LT12 3456 7890 Amount due: 4 200 EUR Thank you."),
]

OUT = Path(__file__).resolve().parent / "free-form-vectors.json"


def build():
    seen = set()
    vectors = []
    for vid, kind, source, expected in VECTORS:
        assert vid not in seen, f"duplicate vector id {vid}"
        seen.add(vid)
        assert kind in ("text", "html"), kind
        vectors.append({
            "id": vid,
            "kind": kind,
            "input": source,
            "text": expected,
            "hash": base64.b64encode(hashlib.sha256(expected.encode("utf-8")).digest()).decode(),
        })
    return {
        "about": ("The free text form of spec/canonical-content.md §2b: input, the text §2b.2 "
                  "makes of it, and SHA-256 of that text as UTF-8, base64. Inputs and expected "
                  "texts are typed from the specification, never read out of an implementation."),
        "spec": "spec/canonical-content.md §2b",
        "unicode_version": "15.1.0",
        "regenerate": "python3 spec/test-vectors/free_form_vectors.py",
        "vectors": vectors,
    }


def main():
    text = json.dumps(build(), ensure_ascii=False, indent=2) + "\n"
    if "--check" in sys.argv:
        if not OUT.is_file() or OUT.read_text(encoding="utf-8") != text:
            print("free-form-vectors.json is stale (run spec/test-vectors/free_form_vectors.py)")
            return 1
        print(f"free-form vectors current: {len(build()['vectors'])} vectors")
        return 0
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.name}: {len(build()['vectors'])} vectors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
