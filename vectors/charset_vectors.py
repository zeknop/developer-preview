#!/usr/bin/env python3
# Licence: Creative Commons Attribution 4.0 International (CC BY 4.0)
#          https://creativecommons.org/licenses/by/4.0/
# Publisher: Zeknod OÜ
# Part of: the ZEKNOP Signed Email specification, Developer Preview
"""Build or check spec/test-vectors/charset-vectors.json (spec §2 step 0, §5).

Every vector's INPUT (the label and the bytes) and its EXPECTED TEXT are typed
here by hand from the WHATWG Encoding Standard's decoder algorithms and index
data — no decoder of this repository was asked what the answer is. The hash is
then computed from the typed text, so a vector cannot agree with a wrong
implementation by having been produced by it.

    python3 spec/test-vectors/charset_vectors.py           # write
    python3 spec/test-vectors/charset_vectors.py --check    # exit 1 when stale
"""

import base64
import hashlib
import json
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent / "charset-vectors.json"

# (id, label, bytes as hex, expected text, why this vector is here)
VECTORS = [
    # ── valid text in each multi-byte encoding ──────────────────────────────
    (
        "mb-001",
        "Shift_JIS",
        "93fa967b8cea",
        "日本語",
        "two-byte characters through the jis0208 index",
    ),
    ("mb-002", "Shift_JIS", "b1b2b3", "ｱｲｳ", "half-width katakana: one byte each, 0xA1-0xDF"),
    (
        "mb-003",
        "Shift_JIS",
        "4180fc",
        "A\u0080�",
        "0x41 is ASCII, 0x80 is U+0080, a lead byte with nothing after it is one error",
    ),
    (
        "mb-004",
        "EUC-JP",
        "c6fccbdcb8ec",
        "日本語",
        "two-byte characters, lead and trail both 0xA1-0xFE",
    ),
    ("mb-005", "EUC-JP", "8eb1", "ｱ", "0x8E introduces half-width katakana"),
    (
        "mb-006",
        "EUC-JP",
        "8fa2af",
        "˘",
        "0x8F introduces the jis0212 index (its first assigned pointer, 108)",
    ),
    (
        "mb-006b",
        "EUC-JP",
        "8fa1a1",
        "�",
        "a jis0212 pointer the index leaves undefined is one error",
    ),
    (
        "mb-007",
        "ISO-2022-JP",
        "1b2442467c4b5c386c1b2842",
        "日本語",
        "an escape into the two-byte state and back to ASCII",
    ),
    (
        "mb-008",
        "ISO-2022-JP",
        "1b284a5c7e1b2842",
        "¥‾",
        "the Roman state: 0x5C is the yen sign and 0x7E the overline",
    ),
    ("mb-009", "ISO-2022-JP", "1b2849211b2842", "｡", "the katakana state"),
    (
        "mb-010",
        "ISO-2022-JP",
        "1b24421b28421b2842",
        "��",
        "three escapes with nothing written between them: the second and the third"
        " are each an error, because the output flag was still set",
    ),
    (
        "mb-011",
        "ISO-2022-JP",
        "1b2442467c",
        "日",
        "the part ends in the two-byte state: what was written stays, no error",
    ),
    ("mb-012", "EUC-KR", "c7d1b1b9beee", "한국어", "two-byte characters through the euc-kr index"),
    (
        "mb-013",
        "EUC-KR",
        "8141",
        "갂",
        "a trail byte below 0x80 is valid in this encoding (pointer 0)",
    ),
    ("mb-014", "Big5", "a4a4a4e5", "中文", "two-byte characters through the big5 index"),
    (
        "mb-015",
        "Big5",
        "8862",
        "Ê̄",
        "one of the four pointers the standard answers with TWO code points",
    ),
    ("mb-016", "GBK", "d6d0cec4", "中文", "two-byte characters through the gb18030 index"),
    (
        "mb-017",
        "gb18030",
        "8130813081308130",
        "",
        "two four-byte sequences through the range rule, both pointer 0",
    ),
    ("mb-018", "gb18030", "80", "€", "0x80 alone is the euro sign in this encoding"),
    ("mb-019", "gb18030", "e3329a35", "􏿿", "the last pointer the range rule answers, 1237575"),
    ("mb-020", "UTF-16LE", "48006900", "Hi", "two code units, low byte first"),
    ("mb-021", "UTF-16BE", "00480069", "Hi", "the same two, high byte first"),
    ("mb-022", "UTF-16LE", "3dd800de", "\U0001f600", "a well-formed surrogate pair"),
    (
        "mb-023",
        "UTF-16LE",
        "00d84100",
        "�A",
        "a lead surrogate followed by an ordinary unit: one error, then the unit",
    ),
    (
        "mb-024",
        "UTF-16LE",
        "410042",
        "A�",
        "an odd number of bytes: the trailing byte is one error",
    ),
    (
        "mb-025",
        "UTF-16LE",
        "fffe4100",
        "﻿A",
        "no byte order mark sniffing: the mark is read as U+FEFF",
    ),
    (
        "mb-026",
        "x-user-defined",
        "418081ff",
        "A",
        "ASCII stays, every other byte is U+F780 plus the byte minus 0x80",
    ),
    (
        "mb-027",
        "iso-2022-kr",
        "41424344",
        "�",
        "a label the standard maps to `replacement`: one error for the whole part",
    ),
    ("mb-028", "iso-2022-kr", "", "", "the same label, no bytes: nothing, not an error"),
    # ── errors, where the runtimes used to disagree ─────────────────────────
    (
        "mb-030",
        "Big5",
        "8781",
        "�",
        "a trail byte outside 0x40-0x7E and 0xA1-0xFE: one error, and nothing is"
        " read again because the byte is not ASCII",
    ),
    (
        "mb-030b",
        "Big5",
        "87ae",
        "䤰",
        "an assigned pointer (1018) where node's ICU decoder answers with a"
        " private use character instead",
    ),
    ("mb-031", "GBK", "ff44", "�D", "0xFF is no lead byte; the ASCII byte after it is read again"),
    (
        "mb-032",
        "EUC-KR",
        "8180",
        "�",
        "an unassigned pointer whose trail byte is not ASCII: one error",
    ),
    ("mb-033", "Shift_JIS", "8140", "　", "the first pointer of the jis0208 index"),
    ("mb-034", "EUC-JP", "a141", "�A", "a trail byte outside 0xA1-0xFE is read again as itself"),
    # ── the single-byte table and the unknown-label rule ────────────────────
    (
        "sb-001",
        "windows-1250",
        "50f8ed6c6f6861",
        "Příloha",
        "the single-byte table decides, not the runtime",
    ),
    (
        "sb-002",
        "iso-8859-1",
        "93c22094",
        "“Â ”",
        "iso-8859-1 names windows-1252, so 0x93 is a quotation mark",
    ),
    (
        "un-001",
        "utf-32",
        "50c5996ed96f6861",
        "Přn�oha",
        "a label no table names is read as UTF-8, errors and all",
    ),
    ("un-002", "x-unknown", "c5be", "ž", "the same rule for any other unknown label"),
    ("un-003", "", "c5be", "ž", "no label at all is UTF-8 too"),
]

# (id, raw Subject header value, expected text, why)
SUBJECTS = [
    ("sj-001", "=?UTF-8?B?RmFrdHVyYSA0MjAwIEVVUg==?=", "Faktura 4200 EUR", "an ordinary B word"),
    (
        "sj-002",
        "=?UTF-8?Q?Faktura_4200_EUR?=",
        "Faktura 4200 EUR",
        "a Q word: underscore is a space",
    ),
    (
        "sj-003",
        "=?ISO-2022-JP?B?GyRCRnxLXDhsGyhC?=",
        "日本語",
        "the word's charset is read by the rule of section 2 step 0",
    ),
    (
        "sj-004",
        "=?windows-1250?Q?Faktura_=81?=",
        "Faktura \u0081",
        "the single-byte table decides here too",
    ),
    (
        "sj-005",
        "=?iso-8859-1?Q?=93quoted=94?=",
        "“quoted”",
        "iso-8859-1 names windows-1252 in a Subject as well",
    ),
    (
        "sj-006",
        "=?UNKNOWN-LABEL?Q?x?=",
        "x",
        "a charset name no table knows is UTF-8, not a refusal",
    ),
    (
        "sj-007",
        "=?UTF-8?B?not base64?=",
        "=?UTF-8?B?not base64?=",
        "a broken B payload: not an encoded word, kept as it stands",
    ),
    (
        "sj-008",
        "=?UTF-8?X?abc?=",
        "=?UTF-8?X?abc?=",
        "an encoding letter that is neither B nor Q: kept as it stands",
    ),
    (
        "sj-009",
        "=?UTF-8?B?U3ByYXZh?= =?UTF-8?B?ZGFsc2k=?=",
        "Spravadalsi",
        "whitespace between two adjacent words is removed",
    ),
    (
        "sj-010",
        "=?UTF-8?B?U3ByYXZh?=  plain  =?UTF-8?B?ZGFsc2k=?=",
        "Sprava  plain  dalsi",
        "text between words is kept exactly",
    ),
    ("sj-011", "=?UTF-8*en?Q?tag?=", "tag", "an RFC 2231 language tag is dropped"),
    (
        "sj-012",
        "Re: =?UTF-8?B?VsSbYw==?= (fwd)",
        "Re: Věc (fwd)",
        "plain text around a word is kept",
    ),
    (
        "sj-013",
        "=?UTF-8?B?VsSbYw==?=\r\n =?UTF-8?B?ZHJ1aMSb?=",
        "Věcdruhě",
        "a folded Subject is unfolded first, then the words join",
    ),
    ("sj-014", "plain subject", "plain subject", "no words at all"),
]


def build():
    return {
        "about": "How a declared charset is read (spec/canonical-content.md §2 step 0) and how "
        "an RFC 2047 encoded word is read (§5). Input and expected text typed by hand "
        "from the WHATWG Encoding Standard; the hash is of the typed text.",
        "regenerate": "python3 spec/test-vectors/charset_vectors.py",
        "text_parts": [
            {
                "id": i,
                "charset": label,
                "bytes_hex": hexed,
                "text": text,
                "text_sha256_base64": base64.b64encode(
                    hashlib.sha256(text.encode("utf-8")).digest()
                ).decode(),
                "why": why,
            }
            for i, label, hexed, text, why in VECTORS
        ],
        "subjects": [
            {
                "id": i,
                "raw": raw,
                "text": text,
                "text_sha256_base64": base64.b64encode(
                    hashlib.sha256(text.encode("utf-8")).digest()
                ).decode(),
                "why": why,
            }
            for i, raw, text, why in SUBJECTS
        ],
    }


def main():
    want = json.dumps(build(), ensure_ascii=False, indent=1) + "\n"
    if "--check" in sys.argv:
        have = OUT.read_text(encoding="utf-8") if OUT.exists() else None
        if have != want:
            print("charset vectors are stale", file=sys.stderr)
            return 1
        print(f"charset vectors current: {len(VECTORS)} text parts, {len(SUBJECTS)} subjects")
        return 0
    OUT.write_text(want, encoding="utf-8")
    print(f"wrote {OUT.name}: {len(VECTORS)} text parts, {len(SUBJECTS)} subjects")
    return 0


if __name__ == "__main__":
    sys.exit(main())
