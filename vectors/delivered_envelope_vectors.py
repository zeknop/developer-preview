#!/usr/bin/env python3
# Licence: Creative Commons Attribution 4.0 International (CC BY 4.0)
#          https://creativecommons.org/licenses/by/4.0/
# Publisher: Zeknod OÜ
# Part of: the ZEKNOP Signed Email specification, Developer Preview
"""
spec/test-vectors/delivered-envelope-vectors.json from the literal texts of
spec/delivered-envelope.md §3.1, §3.2 and §7 — typed here, not taken from any
implementation, so a signer or verifier that drifts cannot move its own vectors.

Usage:
    python3 delivered_envelope_vectors.py            # rewrite the JSON next to this file
    python3 delivered_envelope_vectors.py --check    # exit 1 when the JSON differs
"""

import base64
import json
import re
import sys
from pathlib import Path

POS_START = "======= ZEKNOP ======="
POS_END = "======= END ZEKNOP ======="
POS_CLOSE = (
    "Text outside these markers is not covered by the signature. "
    "ZEKNOP never confirms authenticity by text inside a message."
)
NV_START = "------- ZEKNOP NOTICE: SENDER NOT VERIFIED -------"
NV_L1 = "This message passed through a ZEKNOP signing service but could not be signed."
NV_L2 = (
    "Treat it as ordinary, unverified e-mail. To check any ZEKNOP message, "
    "open verify.zeknop.org yourself and paste the message."
)
NV_END = "------- END ZEKNOP NOTICE -------"

# §3.3.2 — the style attribute every HTML block carries, typed from the spec.
HTML_STYLE = (
    "display:block !important;visibility:visible !important;opacity:1 !important;"
    "position:static !important;transform:none !important;filter:none !important;"
    "clip:auto !important;clip-path:none !important;content-visibility:visible !important;"
    "font-size:13px !important;line-height:1.4 !important;color:#000000 !important;"
    "background:#ffffff !important;width:auto !important;height:auto !important;"
    "max-height:none !important;overflow:visible !important;margin:8px 0 !important;"
    "padding:8px !important;text-indent:0 !important;z-index:auto !important;"
    "white-space:pre-wrap !important;font-family:monospace !important"
)
# §3.3.1 — the marker comments: the words of §3.1/§3.2 with one space on each side.
HTML_POS_START_MARK = "<!-- " + POS_START + " -->"
HTML_POS_END_MARK = "<!-- " + POS_END + " -->"
HTML_NV_START_MARK = "<!-- " + NV_START + " -->"
HTML_NV_END_MARK = "<!-- " + NV_END + " -->"
# §3.3.1 — a leading DOCTYPE the head block is written AFTER.
DOCTYPE_RE = re.compile(r"\A\s*<!DOCTYPE[^>]*>", re.I)


def _html_split_doctype(document):
    """(leading DOCTYPE declaration and the line break after it, the rest)."""
    m = DOCTYPE_RE.match(document)
    if m is None or m.group(0).count('"') % 2:
        return "", document
    end = m.end()
    for brk in ("\r\n", "\n"):
        if document[end : end + len(brk)] == brk:
            end += len(brk)
            break
    return document[:end], document[end:]


def _html_block(mark, lines, eol):
    return (
        mark
        + eol
        + '<div style="'
        + HTML_STYLE
        + '">'
        + eol.join(lines)
        + "</div>"
        + eol
        + mark
        + eol
    )


def positive_html(document, eid, url, eol):
    head = _html_block(
        HTML_POS_START_MARK, [POS_START, "Message ID: " + eid, "Verify: " + url], eol
    )
    tail = _html_block(HTML_POS_END_MARK, [POS_END, POS_CLOSE], eol)
    doctype, rest = _html_split_doctype(document)
    return doctype + head + rest + tail


def not_verified_html(document, eol):
    head = _html_block(HTML_NV_START_MARK, [NV_START, NV_L1, NV_L2], eol)
    tail = _html_block(HTML_NV_END_MARK, [NV_END], eol)
    doctype, rest = _html_split_doctype(document)
    return doctype + head + rest + tail


def positive(inner, eid, url, eol):
    lines = [POS_START, "Message ID: " + eid, "Verify: " + url, "", inner, "", POS_END, POS_CLOSE]
    return eol.join(lines) + eol


def not_verified(inner, eol):
    lines = [NV_START, NV_L1, NV_L2, "", inner, "", NV_END]
    return eol.join(lines) + eol


def legacy(inner, eid, url, eol, bar="======="):
    lines = [
        bar + " ZEKNOP VERIFIED MESSAGE " + bar,
        "ID: " + eid,
        "",
        inner,
        "",
        bar + " END ZEKNOP VERIFIED " + bar,
        "Content outside these markers is not verified.",
        "To verify this email has not been altered, open " + url,
        "Learn more: zeknop.org/verified",
    ]
    return eol.join(lines) + eol


EID = "Ab12Cd34"
URL = "https://verify.zeknop.org/v1/eyJzaWduYXR1cmUiOiJ4In0"
INNER_LF = "Amount due: 100 EUR\nPlease pay by Friday."
INNER_CRLF = "Faktura č. 2026-09\r\nSplatnost: pátek\r\n\r\nDěkujeme."


def b64(s):
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


DOC_LF = "<!DOCTYPE html>\n<html><head><title>Invoice</title></head>\n<body><p>Amount due: 100 EUR</p></body></html>\n"
DOC_CRLF = "<html>\r\n<body><p>Faktura \u010d. 2026-09</p></body>\r\n</html>\r\n"

build_html = [
    {
        "id": "build-html-positive-001-lf-doctype",
        "kind": "positive",
        "input": {"inner": DOC_LF, "envelope_id": EID, "verify_url": URL, "eol": "\n"},
        "note": "a document with a DOCTYPE: the head block is written AFTER it (\u00a73.3.1), so the "
        "sender's document keeps the parsing mode it had",
    },
    {
        "id": "build-html-positive-002-crlf-no-doctype",
        "kind": "positive",
        "input": {"inner": DOC_CRLF, "envelope_id": EID, "verify_url": URL, "eol": "\r\n"},
        "note": "no DOCTYPE: the head block is the first byte of the part",
    },
    {
        "id": "build-html-not-verified-001-lf-doctype",
        "kind": "not-verified",
        "input": {"inner": DOC_LF, "eol": "\n"},
        "note": "the not-verified blocks, same placement",
    },
    {
        "id": "build-html-not-verified-002-crlf-no-doctype",
        "kind": "not-verified",
        "input": {"inner": DOC_CRLF, "eol": "\r\n"},
        "note": "the not-verified blocks, CRLF, no DOCTYPE",
    },
    {
        "id": "build-html-positive-003-markup-without-a-document-element",
        "kind": "positive",
        "input": {"inner": "<p>hello</p>\n", "envelope_id": EID, "verify_url": URL, "eol": "\n"},
        "note": "a part that is markup without a document element: nothing to step over, the "
        "blocks go at its two ends",
    },
]
for v in build_html:
    i = v["input"]
    text = (
        positive_html(i["inner"], i["envelope_id"], i["verify_url"], i["eol"])
        if v["kind"] == "positive"
        else not_verified_html(i["inner"], i["eol"])
    )
    v["expected"] = {"text": text, "utf8_base64": b64(text)}

build = [
    {
        "id": "build-positive-001-lf",
        "kind": "positive",
        "input": {"inner": INNER_LF, "envelope_id": EID, "verify_url": URL, "eol": "\n"},
    },
    {
        "id": "build-positive-002-crlf-non-ascii-content",
        "kind": "positive",
        "input": {"inner": INNER_CRLF, "envelope_id": EID, "verify_url": URL, "eol": "\r\n"},
    },
    {
        "id": "build-not-verified-001-lf",
        "kind": "not-verified",
        "input": {"inner": INNER_LF, "eol": "\n"},
    },
    {
        "id": "build-not-verified-002-crlf-non-ascii-content",
        "kind": "not-verified",
        "input": {"inner": INNER_CRLF, "eol": "\r\n"},
    },
]
for v in build:
    i = v["input"]
    text = (
        positive(i["inner"], i["envelope_id"], i["verify_url"], i["eol"])
        if v["kind"] == "positive"
        else not_verified(i["inner"], i["eol"])
    )
    v["expected"] = {"text": text, "utf8_base64": b64(text)}

quoted_nv = (
    "Paid, thank you.\n\n> "
    + NV_START
    + "\n> "
    + NV_L1
    + "\n>\n> Amount due: 100 EUR\n>\n> "
    + NV_END
)
strip = [
    (
        "strip-positive-001-lf",
        positive(INNER_LF, EID, URL, "\n"),
        INNER_LF,
        "new positive envelope",
    ),
    (
        "strip-positive-002-crlf",
        positive(INNER_CRLF, EID, URL, "\r\n"),
        INNER_CRLF,
        "new positive envelope, CRLF",
    ),
    (
        "strip-legacy-001-lf",
        legacy(INNER_LF, EID, URL, "\n"),
        INNER_LF,
        "legacy positive envelope (signers before v1.4)",
    ),
    (
        "strip-legacy-002-crlf",
        legacy(INNER_CRLF, EID, URL, "\r\n"),
        INNER_CRLF,
        "legacy positive envelope, CRLF",
    ),
    (
        "strip-legacy-003-u2550-markers",
        legacy(INNER_LF, EID, URL, "\n", bar="═" * 7),
        INNER_LF,
        "legacy positive envelope with U+2550 marker characters",
    ),
    (
        "strip-not-verified-001-lf",
        not_verified(INNER_LF, "\n"),
        not_verified(INNER_LF, "\n"),
        "not-verified envelope: recognised, never taken off before hashing",
    ),
    (
        "strip-not-verified-002-crlf",
        not_verified(INNER_CRLF, "\r\n"),
        not_verified(INNER_CRLF, "\r\n"),
        "not-verified envelope, CRLF: recognised, never taken off before hashing",
    ),
    (
        "strip-none-001",
        "Hello,\n\nno envelope in this text.\n",
        "Hello,\n\nno envelope in this text.\n",
        "no envelope: unchanged",
    ),
    (
        "strip-positive-003-quoted-not-verified-inside",
        positive(quoted_nv, EID, URL, "\n"),
        quoted_nv,
        "a not-verified envelope quoted inside signed content stays content: the outer start marker comes first",
    ),
    (
        "strip-positive-004-text-before-start",
        "[EXTERNAL]\n" + positive(INNER_LF, EID, URL, "\n"),
        "[EXTERNAL]\n" + positive(INNER_LF, EID, URL, "\n"),
        "a start marker that is not the head of the part does not open an envelope, so a "
        "message something prepended a line to is not stripped (and goes red) instead of "
        "verifying with a stranger's text above the block",
    ),
    (
        "strip-positive-005-new-end-marker-only",
        POS_START + "\nMessage ID: " + EID + "\n\n" + INNER_LF + "\n",
        POS_START + "\nMessage ID: " + EID + "\n\n" + INNER_LF + "\n",
        "start marker without an end marker: unchanged",
    ),
    (
        "strip-mixed-001-legacy-start-new-end",
        "======= ZEKNOP VERIFIED MESSAGE =======\nID: "
        + EID
        + "\n\n"
        + INNER_LF
        + "\n\n"
        + POS_END
        + "\n",
        "======= ZEKNOP VERIFIED MESSAGE =======\nID: "
        + EID
        + "\n\n"
        + INNER_LF
        + "\n\n"
        + POS_END
        + "\n",
        "an end marker of another kind does not close the envelope: unchanged",
    ),
    (
        "strip-not-verified-003-positive-end-inside",
        NV_START + "\n" + NV_L1 + "\n\n" + INNER_LF + "\n" + POS_END + "\n\n" + NV_END + "\n",
        NV_START + "\n" + NV_L1 + "\n\n" + INNER_LF + "\n" + POS_END + "\n\n" + NV_END + "\n",
        "the not-verified envelope closes only at its own end marker, and is not taken off",
    ),
    (
        "strip-not-verified-004-signed-envelope-inside",
        not_verified(positive(INNER_LF, EID, URL, "\n"), "\n"),
        not_verified(positive(INNER_LF, EID, URL, "\n"), "\n"),
        "a positive envelope inside a not-verified envelope is not taken off either: the outer one decides",
    ),
    (
        "strip-positive-006-no-blank-line",
        POS_START + "\nMessage ID: " + EID + "\n" + INNER_LF + "\n" + POS_END + "\n",
        POS_START + "\nMessage ID: " + EID + "\n" + INNER_LF + "\n" + POS_END + "\n",
        "no blank line after the start marker: unchanged",
    ),
    (
        "strip-p5-001-quoted-with-angle-bracket",
        "Thanks.\n\n> "
        + POS_START
        + "\n> Message ID: "
        + EID
        + "\n>\n> Amount due: 100 EUR\n>\n> "
        + POS_END,
        "Thanks.\n\n> "
        + POS_START
        + "\n> Message ID: "
        + EID
        + "\n>\n> Amount due: 100 EUR\n>\n> "
        + POS_END,
        "an envelope quoted with `>` inside the content is content",
    ),
    (
        "strip-p5-002-indented",
        "See below.\n\n    "
        + POS_START
        + "\n    Message ID: "
        + EID
        + "\n\n    Amount due: 100 EUR\n\n    "
        + POS_END,
        "See below.\n\n    "
        + POS_START
        + "\n    Message ID: "
        + EID
        + "\n\n    Amount due: 100 EUR\n\n    "
        + POS_END,
        "an indented envelope inside the content is content",
    ),
    (
        "strip-p5-003-envelope-at-a-line-start-in-the-middle",
        "Quoting your mail:\n" + positive(INNER_LF, EID, URL, "\n"),
        "Quoting your mail:\n" + positive(INNER_LF, EID, URL, "\n"),
        "an envelope quoted WITHOUT any prefix, deeper in the part, is content too - "
        "a verifier never searches for the markers",
    ),
    (
        "strip-p5-004-text-after-the-closing-line",
        positive(INNER_LF, EID, URL, "\n") + "Sent from my phone\n",
        INNER_LF,
        "text appended BELOW the closing lines does not move the envelope - the end marker "
        "taken is the last line-initial one, and what follows it is outside the markers "
        "- such a message still verifies",
    ),
    (
        "strip-p5-005-content-carrying-an-end-marker",
        positive("Amount due: 100 EUR\n" + POS_END + "\nand more", EID, URL, "\n"),
        "Amount due: 100 EUR\n" + POS_END + "\nand more",
        "the end marker taken is the one at the tail, so content carrying an end marker "
        "is not truncated",
    ),
    (
        "strip-p5-006-not-verified-quoted",
        "Reply.\n\n> " + NV_START + "\n> " + NV_L1 + "\n>\n> body\n>\n> " + NV_END,
        "Reply.\n\n> " + NV_START + "\n> " + NV_L1 + "\n>\n> body\n>\n> " + NV_END,
        "a quoted not-verified envelope is content, so a signed reply that quotes one is green",
    ),
]
KINDS = {
    "strip-positive-001-lf": "positive",
    "strip-positive-002-crlf": "positive",
    "strip-legacy-001-lf": "legacy-positive",
    "strip-legacy-002-crlf": "legacy-positive",
    "strip-legacy-003-u2550-markers": "legacy-positive",
    "strip-not-verified-001-lf": "not-verified",
    "strip-not-verified-002-crlf": "not-verified",
    "strip-none-001": None,
    "strip-positive-003-quoted-not-verified-inside": "positive",
    "strip-positive-004-text-before-start": None,
    "strip-positive-005-new-end-marker-only": None,
    "strip-mixed-001-legacy-start-new-end": None,
    "strip-not-verified-003-positive-end-inside": "not-verified",
    "strip-not-verified-004-signed-envelope-inside": "not-verified",
    "strip-positive-006-no-blank-line": None,
    "strip-p5-001-quoted-with-angle-bracket": None,
    "strip-p5-002-indented": None,
    "strip-p5-003-envelope-at-a-line-start-in-the-middle": None,
    "strip-p5-004-text-after-the-closing-line": "positive",
    "strip-p5-005-content-carrying-an-end-marker": "positive",
    "strip-p5-006-not-verified-quoted": None,
}
strip = [
    {"id": i, "note": n, "delivered": d, "expected": e, "expected_kind": KINDS[i]}
    for i, d, e, n in strip
]

# §6.1, the HTML rule: what every verifier must return for a delivered HTML part.
_HTML_HEAD = _html_block(
    HTML_POS_START_MARK, [POS_START, "Message ID: " + EID, "Verify: " + URL], "\n"
)
_HTML_TAIL = _html_block(HTML_POS_END_MARK, [POS_END, POS_CLOSE], "\n")
_HTML_NV_HEAD = _html_block(HTML_NV_START_MARK, [NV_START, NV_L1, NV_L2], "\n")
_HTML_NV_TAIL = _html_block(HTML_NV_END_MARK, [NV_END], "\n")
_DOC = "<!DOCTYPE html>\n<html><body><p>Amount due: 100 EUR</p></body></html>\n"

strip_html = [
    (
        "strip-html-001-positive-with-a-doctype",
        positive_html(_DOC, EID, URL, "\n"),
        _DOC,
        "positive",
        "the head block sits after the DOCTYPE; the DOCTYPE stays in the content",
    ),
    (
        "strip-html-002-positive-crlf",
        positive_html(DOC_CRLF, EID, URL, "\r\n"),
        DOC_CRLF,
        "positive",
        "CRLF, no DOCTYPE: the head block is the first byte of the part",
    ),
    (
        "strip-html-003-not-verified-is-never-taken-off",
        not_verified_html(_DOC, "\n"),
        not_verified_html(_DOC, "\n"),
        "not-verified",
        "recognised, never taken off before hashing, so it can never recompute to a signature",
    ),
    ("strip-html-004-no-envelope", _DOC, _DOC, None, "no blocks: unchanged"),
    (
        "strip-html-005-quoted-inside",
        _DOC[:-1] + "<blockquote>" + _HTML_HEAD + "<p>older</p>\n" + _HTML_TAIL + "</blockquote>\n",
        _DOC[:-1] + "<blockquote>" + _HTML_HEAD + "<p>older</p>\n" + _HTML_TAIL + "</blockquote>\n",
        None,
        "a block quoted inside the content is content — the comments are never searched for inside the part",
    ),
    (
        "strip-html-006-text-before-the-head",
        "[EXTERNAL]\n" + _HTML_HEAD + _DOC + _HTML_TAIL,
        "[EXTERNAL]\n" + _HTML_HEAD + _DOC + _HTML_TAIL,
        None,
        "a part something prepended a line to does not begin with the head block, so nothing is taken off",
    ),
    (
        "strip-html-007-head-without-a-tail",
        "<!DOCTYPE html>\n" + _HTML_HEAD + _DOC[len("<!DOCTYPE html>\n") :],
        "<!DOCTYPE html>\n" + _HTML_HEAD + _DOC[len("<!DOCTYPE html>\n") :],
        None,
        "a head block with no tail block at the end of the part: unchanged",
    ),
    (
        "strip-html-008-not-verified-quoted-in-a-positive-envelope",
        positive_html(
            "<p>reply</p>\n<blockquote>"
            + _HTML_NV_HEAD
            + "<p>older</p>\n"
            + _HTML_NV_TAIL
            + "</blockquote>\n",
            EID,
            URL,
            "\n",
        ),
        "<p>reply</p>\n<blockquote>"
        + _HTML_NV_HEAD
        + "<p>older</p>\n"
        + _HTML_NV_TAIL
        + "</blockquote>\n",
        "positive",
        "a quoted not-verified block inside signed content is content and stays in the hash",
    ),
]
strip_html = [
    {"id": i, "note": n, "delivered": d, "expected": e, "expected_kind": k}
    for i, d, e, k, n in strip_html
]

doc = {
    "version": "1.0",
    "specification": "delivered-envelope.md v1.4",
    "reference": "spec/delivered-envelope.md",
    "generated_at": "2026-09-17",
    "generated_by": "Literal texts of spec/delivered-envelope.md §3 and §7, rendered by a stand-alone script; no implementation involved",
    "notes": {
        "build": "Each implementation's builder called with input (inner, envelope_id, verify_url, eol) must return expected.text exactly; utf8_base64 is the same text as UTF-8 bytes.",
        "strip": "Each verifier's outer-envelope removal (§6.1) applied to delivered must return expected exactly; expected_kind is the outer envelope it recognises (null: none complete).",
        "build_html": "§3.3.1: each signer's HTML builder called with input (inner, envelope_id, verify_url, eol) must return expected.text exactly. `inner` is the sender's HTML part; the head block goes after a leading DOCTYPE, the tail block after the last byte.",
        "strip_html": "§6.1 (the HTML rule): each verifier's removal applied to delivered must return expected exactly; expected_kind is the outer block it recognises (null: none at the two ends).",
    },
    "html_style": HTML_STYLE,
    "build": build,
    "build_html": build_html,
    "strip": strip,
    "strip_html": strip_html,
}
OUT = Path(__file__).resolve().parent / "delivered-envelope-vectors.json"
rendered = json.dumps(doc, ensure_ascii=False, indent=2) + "\n"
if "--check" in sys.argv[1:]:
    same = OUT.read_text(encoding="utf-8") == rendered
    print(
        f"delivered-envelope vectors: {len(build)} build, {len(build_html)} build_html, "
        f"{len(strip)} strip, {len(strip_html)} strip_html — "
        f"{'match' if same else 'DIFFER FROM'} spec/delivered-envelope.md"
    )
    sys.exit(0 if same else 1)
OUT.write_text(rendered, encoding="utf-8", newline="\n")
print(OUT, len(build), len(build_html), len(strip), len(strip_html))
