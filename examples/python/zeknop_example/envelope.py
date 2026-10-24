# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zeknod OÜ
"""The visible block a signer writes into a delivered part.

Written from `delivered-envelope.md` §3.1, §3.2, §3.3 and §3.3.1, and held to
`../../vectors/delivered-envelope-vectors.json` (`build`, 4 cases, and
`build_html`, 5) by the `conformance` command. The removal side — what a verifier
takes off before it hashes anything — is not here: it is in the copy of the
reference implementation (`canonicalization.canonical.strip_zeknop_envelope` and
`strip_zeknop_html_envelope`), because a verifier and a signer must not read the
same block two ways.

Two things about the block are worth reading twice before writing a signer:

* it is written AFTER signing and is **not** covered by the signature. §2 is why:
  the sender's bytes between the inner markers are the bytes that came in, so a
  verifier takes the block off and finds the hash the signer made;
* the block does not say the message is verified. It names the message and points
  at where it can be checked. Both texts are English only and are not localised,
  which is itself something a reader can recognise (§3).

The not-verified block carries **no link** (§3.2): a reader is never led through a
link out of a message nobody could verify.
"""

import base64
import json

# Imported for `split_leading_doctype` alone: a signer steps over exactly the token a
# verifier's removal steps over, so there is one reading of it and not two.
from .canonicalization import canonical

#: §3.1 — the positive block, byte for byte.
POSITIVE_START = "======= ZEKNOP ======="
POSITIVE_END = "======= END ZEKNOP ======="
POSITIVE_CLOSING = (
    "Text outside these markers is not covered by the signature. "
    "ZEKNOP never confirms authenticity by text inside a message."
)

#: §3.2 — the not-verified block, byte for byte.
NOT_VERIFIED_START = "------- ZEKNOP NOTICE: SENDER NOT VERIFIED -------"
NOT_VERIFIED_LINE_1 = (
    "This message passed through a ZEKNOP signing service but could not be signed."
)
NOT_VERIFIED_LINE_2 = (
    "Treat it as ordinary, unverified e-mail. To check any ZEKNOP message, "
    "open verify.zeknop.org yourself and paste the message."
)
NOT_VERIFIED_END = "------- END ZEKNOP NOTICE -------"

#: §3.3.2 — the `style` attribute every HTML block carries, with `!important` on
#: each declaration. It makes the block hard to cover, which is not the same as
#: impossible: §8 says the verdict belongs to the end point and never to the block.
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

#: §3.3.1 — the marker words inside the comments are the marker lines of §3.1 and
#: §3.2 with one space on each side, so the seven `-` of the not-verified marker
#: never touch the `<!--` and `-->` of the comment.
HTML_MARK_POSITIVE_START = f"<!-- {POSITIVE_START} -->"
HTML_MARK_POSITIVE_END = f"<!-- {POSITIVE_END} -->"
HTML_MARK_NOT_VERIFIED_START = f"<!-- {NOT_VERIFIED_START} -->"
HTML_MARK_NOT_VERIFIED_END = f"<!-- {NOT_VERIFIED_END} -->"


def verify_token(content_hash: str, uuid: str) -> str:
    """The token at the tail of the verification link (§3.1).

    From v1.4 it carries the version, the identity and the fingerprint of the
    content — WHICH message the link was made for — and no signature: a reader of
    the link reads the signature out of the message, where alone it means
    anything. base64url of the compact JSON, without the padding.
    """
    payload = json.dumps({"v": 2, "uuid": uuid, "hash": content_hash}, separators=(",", ":"))
    return base64.urlsafe_b64encode(payload.encode("utf-8")).rstrip(b"=").decode("ascii")


def build_plain(
    kind: str, inner: str, envelope_id: str = "", verify_url: str = "", eol: str = "\r\n"
) -> str:
    """One displayed `text/plain` part with the block around the sender's text (§3.3).

    `eol` is the line ending of the part: CRLF on the wire, LF for a part whose
    payload demonstrably uses bare LF. Every line of the block, the last one
    included, ends with it, and no line of the block carries trailing white space.

    A positive block names the envelope identifier the relay returned and the link
    the portal of the deployment serves. A positive block NEVER names a
    placeholder or an invented identifier (§3.1): a relay answer without a
    signature or without such an identifier is not a signature, and the message is
    then one the signer could not sign.
    """
    if kind == "positive":
        if not envelope_id or not verify_url:
            raise ValueError(
                "a positive block needs the envelope id and the link the relay answered with"
            )
        head = [POSITIVE_START, f"Message ID: {envelope_id}", f"Verify: {verify_url}"]
        tail = [POSITIVE_END, POSITIVE_CLOSING]
    elif kind == "not-verified":
        head = [NOT_VERIFIED_START, NOT_VERIFIED_LINE_1, NOT_VERIFIED_LINE_2]
        tail = [NOT_VERIFIED_END]
    else:
        raise ValueError(f"the block is positive or not-verified, not {kind!r}")
    lines = head + [""] + [inner] + [""] + tail
    return eol.join(lines) + eol


def _html_blocks(kind: str, envelope_id: str, verify_url: str, eol: str):
    """(head block, tail block) for an HTML part (§3.3.1).

    Each block is written twice over: once as an HTML comment carrying the marker
    words, which is the byte marker a verifier removes by (§6.1), and once as a
    `<div>` whose text is the lines a plain-text reader sees. The comment stands on
    both sides of the `<div>`, so each block is delimited by the same words at both
    of its ends. The `<div>` carries no class and no id.
    """
    if kind == "positive":
        head_mark, tail_mark = HTML_MARK_POSITIVE_START, HTML_MARK_POSITIVE_END
        head_lines = [POSITIVE_START, f"Message ID: {envelope_id}", f"Verify: {verify_url}"]
        tail_lines = [POSITIVE_END, POSITIVE_CLOSING]
    elif kind == "not-verified":
        head_mark, tail_mark = HTML_MARK_NOT_VERIFIED_START, HTML_MARK_NOT_VERIFIED_END
        head_lines = [NOT_VERIFIED_START, NOT_VERIFIED_LINE_1, NOT_VERIFIED_LINE_2]
        tail_lines = [NOT_VERIFIED_END]
    else:
        raise ValueError(f"the block is positive or not-verified, not {kind!r}")

    def block(mark, lines):
        inside = eol.join(lines)
        return mark + eol + f'<div style="{HTML_STYLE}">{inside}</div>' + eol + mark + eol

    return block(head_mark, head_lines), block(tail_mark, tail_lines)


def build_html(
    kind: str, inner: str, envelope_id: str = "", verify_url: str = "", eol: str = "\r\n"
) -> str:
    """One displayed `text/html` part with the head and tail blocks around the
    sender's document (§3.3.1).

    The head block is the first content after a leading DOCTYPE declaration when
    the part has one, and the first content of the document when it has none; the
    tail block is appended after the last byte. Nothing is inserted between the
    head block and the sender's first byte or between the sender's last byte and
    the tail block, so the bytes between the inner markers are the bytes that came
    in. The DOCTYPE is stepped over because a document whose first token is our
    `<div>` is parsed with the DOCTYPE dropped and the sender's whole document in
    quirks mode, which changes how the sender's own content is displayed.

    The sender's markup is never entered, not read and not re-serialised.
    """
    if kind == "positive" and (not envelope_id or not verify_url):
        raise ValueError(
            "a positive block needs the envelope id and the link the relay answered with"
        )
    head, tail = _html_blocks(kind, envelope_id, verify_url, eol)
    doctype, rest = split_leading_doctype(inner)
    return doctype + head + rest + tail


def split_leading_doctype(document: str):
    """(the leading DOCTYPE declaration with its line break, the rest) — §3.3.1.

    The declaration is recognised as `<!DOCTYPE` … `>` at the very start of the
    part: leading white space allowed, the name read without regard to case, and
    only when the quotation marks inside it are balanced. Anything else counts as
    the sender's first byte. A verifier steps over the same token, which is why
    this is one function and not two readings.
    """
    return canonical.split_html_doctype(document)
