# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zeknod OÜ
#
# A copy of the ZEKNOP reference implementation of the canonical content
# specification, carried by the Python example so that the example computes the
# same bytes as the service that signed the message. Apart from this header and
# the substitutions recorded with the copy, nothing in this file was changed.
"""
The canonical content of a message and its two hashes.

Normative: canonical-content.md §1-§2 (the strict form), §2b (the free text
form), §9 (the parts manifest) and delivered-envelope.md §6.1 (removing the
visible block before hashing). Every signer and every verifier of this protocol
has to agree with this file byte for byte.
"""

import json
import hashlib
import base64
import re


MAX_BODY_SIZE = 1024 * 1024  # 1 MB

# The characters a canonical field is trimmed by (spec §2 step 4, §5, §9.4):
# exactly the set JavaScript's String.prototype.trim() removes (ECMAScript
# WhiteSpace + LineTerminator). The readers written in JavaScript trim with
# trim(), and every signature issued so far was made that way. Python's bare str.strip() removes a DIFFERENT set — it also
# removes U+001C-U+001F and U+0085 and keeps U+FEFF — so an untouched message
# whose text starts or ends with one of those verified on one surface and not
# on another. No canonical field is trimmed with bare strip().
TRIM_CHARS = (
    "\u0009\u000a\u000b\u000c\u000d\u0020\u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000\ufeff"
)


# Where a line ends for step 3 (spec §2 step 3): exactly the set the production
# signer ends a line at. Step 3 is written as `/[ \t]+$/gm`, and under `m` a
# JavaScript engine ends a line at the ECMAScript LineTerminators — LF, CR,
# U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR — while Python's
# re.MULTILINE ends it at LF alone. Text carrying U+2028 or U+2029 therefore
# hashed differently in the readers written in JavaScript than in those written
# in Python. U+0085 NEXT LINE is NOT in the set:
# it is not an ECMAScript LineTerminator, so a space in front of it stays.
LINE_END_CHARS = "\n\r\u2028\u2029"
_TRAILING_LINE_WS = re.compile("[ \t]+(?=[" + LINE_END_CHARS + "]|\\Z)")


def trim(text: str) -> str:
    """Leading and trailing TRIM_CHARS removed — String.prototype.trim()."""
    return text.strip(TRIM_CHARS)


def strip_trailing_line_whitespace(text: str) -> str:
    """Spec §2 step 3 — spaces and tabs before a line end or the end of the text."""
    return _TRAILING_LINE_WS.sub("", text)


def normalize_body(text: str) -> str:
    if text.startswith("\uFEFF"):
        text = text[1:]
    text = text.replace("\r\n", "\n")
    text = text.replace("\r", "\n")
    text = strip_trailing_line_whitespace(text)
    return trim(text)


def canonical_body_field(body: str, max_body: int = MAX_BODY_SIZE) -> str:
    """The `body` field of the Shape A canonical object, without the timestamp.

    Everything the body costs is in here: the §2 normalisation (BOM, line ends,
    trailing line whitespace, trim) and the truncation to `max_body`. It is
    split out of build_canonical_content so that a signer can do this work
    BEFORE it samples the request timestamp: hashing a large body takes long
    enough that a timestamp taken first can be refused as stale by the time the
    request arrives. The split is output-neutral by construction --
    build_canonical_content is the composition below.
    """
    return normalize_body(body)[:max_body]


def assemble_canonical_content(
    from_addr: str,
    to_addrs: list[str],
    subject: str,
    body_field: str,
    timestamp: str,
) -> dict:
    """The Shape A canonical object from an ALREADY normalised body field.

    Key order MUST be: from, to, subject, body, timestamp. `body_field` is used
    verbatim -- it is what canonical_body_field returned. Nothing here walks the
    message, so this is the only part of Shape A that has to run after the
    timestamp is sampled.
    """
    return {
        "from": from_addr,
        "to": ", ".join(to_addrs),
        "subject": subject,
        "body": body_field,
        "timestamp": timestamp,
    }


def build_canonical_content(
    from_addr: str,
    to_addrs: list[str],
    subject: str,
    body: str,
    timestamp: str,
    max_body: int = MAX_BODY_SIZE,
) -> dict:
    """
    Build the Shape A canonical object (spec v1.3 §1.1): the v1.1 5-key form,
    byte-identical since 2026-04-20, used for a message that is a single
    non-multipart text/plain part. Key order MUST be:
    from, to, subject, body, timestamp.

    The v1.2 conditional fields (attachments/html/inline) are retired — any
    message that would have needed them selects Shape B instead
    (build_canonical_content_v13).
    """
    return assemble_canonical_content(
        from_addr=from_addr,
        to_addrs=to_addrs,
        subject=subject,
        body_field=canonical_body_field(body, max_body),
        timestamp=timestamp,
    )


def build_canonical_content_v13(
    from_addr: str,
    to_addrs: list[str],
    subject: str,
    timestamp: str,
    parts: list[dict],
) -> dict:
    """
    Build the Shape B canonical object (spec v1.3 §1/§9): the ordered parts
    manifest. Key order MUST be: from, to, subject, timestamp, parts — there
    is no `body` key; all text parts live inside `parts` as k:"plain"/"html"
    entries.

    `parts` comes from mime_walk.extract_parts_manifest and is used VERBATIM:
    document order is normative (§9.1), entries are never sorted here.
    """
    return {
        "from": from_addr,
        "to": ", ".join(to_addrs),
        "subject": subject,
        "timestamp": timestamp,
        "parts": parts,
    }


def compute_content_hash(canonical: dict) -> str:
    """
    SHA-256 of JSON-stringified canonical object → standard base64.

    JSON separators: (",", ":") — no spaces.
    Encoding: UTF-8, ensure_ascii=False.
    """
    json_str = json.dumps(canonical, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(json_str.encode("utf-8")).digest()
    return base64.b64encode(digest).decode("ascii")


def compute_free_hash(text: str, is_html: bool = False) -> str:
    """SHA-256 of the FREE text form (§2b) → standard base64, like every other
    hash here. From v1.4 it sits under the signature next to the strict hash
    (spec/signature-input.md §2), so that a copy someone simply forwarded — which
    rewraps lines and re-encodes characters — still carries something a server can
    recognise. Signer and verifier compute it from the same one part, chosen by
    structure (mime_walk.free_form_source)."""
    from .free_form import free_form_text
    digest = hashlib.sha256(free_form_text(text, is_html).encode("utf-8")).digest()
    return base64.b64encode(digest).decode("ascii")


# spec/delivered-envelope.md §6.1 — the kinds of outer envelope a verifier
# takes off. The positive and not-verified markers are literal (spec §3); the
# legacy positive marker of the signers before v1.4 (spec §7) is a pattern, with
# U+2550 or '=' bars, exactly as v1.3 read it.
_LEGACY_ENVELOPE_START_RE = re.compile(r"[\u2550=]{7} ZEKNOP VERIFIED MESSAGE [\u2550=]{7}")
_LEGACY_ENVELOPE_END_RE = re.compile(r"[\u2550=]{7} END ZEKNOP VERIFIED [\u2550=]{7,}")
DELIVERED_ENVELOPE_KINDS = (
    ("positive", "======= ZEKNOP =======", "======= END ZEKNOP ======="),
    ("legacy-positive", _LEGACY_ENVELOPE_START_RE, _LEGACY_ENVELOPE_END_RE),
    ("not-verified", "------- ZEKNOP NOTICE: SENDER NOT VERIFIED -------", "------- END ZEKNOP NOTICE -------"),
)


def _at_line_start(body: str, index: int) -> bool:
    return index == 0 or body[index - 1] == "\n"


def _marker_at_head(body: str, marker):
    """(0, length) when the marker is the very start of the part, else None."""
    if isinstance(marker, str):
        return (0, len(marker)) if body.startswith(marker) else None
    m = marker.match(body)
    return None if m is None else (0, m.end())


def _marker_at_tail(body: str, marker, after: int):
    """
    (index, length) of the LAST occurrence of the marker that begins a line,
    else None.

    The LAST one, so that content carrying an end marker cannot truncate the
    envelope; beginning a LINE, so that a quoted or indented end marker is
    content. The closing lines an envelope writes below its end marker differ
    per kind (the legacy one carries a token in its URL), so what follows the
    marker is not pinned here; text appended below the closing lines is outside
    the markers, which is what the closing sentence says.
    """
    if isinstance(marker, str):
        index = body.rfind(marker)
        while index >= after:
            if _at_line_start(body, index):
                return (index, len(marker))
            index = body.rfind(marker, after, index)
        return None
    matches = [m for m in marker.finditer(body)
               if m.start() >= after and _at_line_start(body, m.start())]
    if not matches:
        return None
    m = matches[-1]
    return (m.start(), m.end() - m.start())


def _outer_delivered_envelope(body: str):
    """
    (kind, content) of the envelope of a delivered text, or None (spec §6.1).

    The markers are read ONLY at the head and the tail of the part, never
    searched for inside it. An envelope quoted in the content — indented, behind
    `>`, or at a line start with nothing in front of it — is the sender's text
    and stays in the hash, so a signed reply that quotes one is green. A verifier
    that searched would let a sender move the boundary of what is hashed by
    writing a marker.
    """
    outer = None
    for kind, start_marker, end_marker in DELIVERED_ENVELOPE_KINDS:
        start = _marker_at_head(body, start_marker)
        if start is not None:
            outer = (kind, start, end_marker)
            break
    if outer is None:
        return None
    kind, (start_index, start_length), end_marker = outer
    end = _marker_at_tail(body, end_marker, start_index + start_length)
    if end is None or end[0] <= start_index:
        return None

    after_start = body[start_index + start_length:]
    # Content begins after the identifier or notice lines and the blank line that follows.
    idx = after_start.find("\n\n")
    blank_len = 2
    if idx == -1:
        idx = after_start.find("\r\n\r\n")
        blank_len = 4
    if idx == -1:
        return None

    content = body[start_index + start_length + idx + blank_len:end[0]]
    # Drop the trailing newline(s) the signer inserts before the END marker.
    return kind, re.sub(r"[\r\n]+$", "", content)


def strip_zeknop_envelope(body: str) -> str:
    """
    Recover the original inner body from a ZEKNOP-wrapped body before hashing
    (spec/delivered-envelope.md §6.1).

    A signer hashes the ORIGINAL (unwrapped) body but DELIVERS it wrapped in a
    visible envelope — since v1.4:

        ======= ZEKNOP =======
        Message ID: xxxxxxxx
        Verify: https://verify.zeknop.org/v1/<token>
        <blank line>
        <original body>
        <blank line>
        ======= END ZEKNOP =======
        ...closing sentence...

    before v1.4 the legacy positive envelope (`ZEKNOP VERIFIED MESSAGE` ...
    `END ZEKNOP VERIFIED`), and around a message it could not sign the
    not-verified envelope (`------- ZEKNOP NOTICE: SENDER NOT VERIFIED -------`
    ... `------- END ZEKNOP NOTICE -------`).

    The verifier MUST strip the outer envelope to recompute the hash the signer
    produced. The kind whose start marker occurs first is the outer one; the
    content runs from the first blank line after it to the end marker of the
    SAME kind, trailing newline(s) dropped. Internal blank lines are preserved
    (no collapsing) so the result matches the signer's normalize step. Mirrors
    the removal every other reader of this protocol performs, byte for byte
    (delivered-envelope.md §6.1, vectors in ../../../../vectors/
    delivered-envelope-vectors.json). For the legacy marker it is
    exactly the v1.3 rule: every message signed before v1.4 recomputes as before.

    Returns the body unchanged when no complete positive envelope is outermost:
    no envelope at all, or the not-verified envelope, which is recognised
    (delivered_envelope_kind) but never taken off before hashing.
    """
    outer = _outer_delivered_envelope(body)
    # A not-verified envelope is recognised but never taken off: the text is
    # hashed as it is, so it does not recompute to a signature (spec §6.1).
    return body if outer is None or outer[0] == "not-verified" else outer[1]


# spec/delivered-envelope.md §3.3.1 — the same envelope in an HTML part, as two
# blocks at the two ends of the part. The byte markers are HTML comments carrying
# the marker words with one space on each side.
HTML_MARK_POSITIVE_START = "<!-- ======= ZEKNOP ======= -->"
HTML_MARK_POSITIVE_END = "<!-- ======= END ZEKNOP ======= -->"
HTML_MARK_NOT_VERIFIED_START = "<!-- ------- ZEKNOP NOTICE: SENDER NOT VERIFIED ------- -->"
HTML_MARK_NOT_VERIFIED_END = "<!-- ------- END ZEKNOP NOTICE ------- -->"
HTML_ENVELOPE_KINDS = (
    ("positive", HTML_MARK_POSITIVE_START, HTML_MARK_POSITIVE_END),
    ("not-verified", HTML_MARK_NOT_VERIFIED_START, HTML_MARK_NOT_VERIFIED_END),
)
_HTML_DOCTYPE_RE = re.compile(r"\A\s*<!DOCTYPE[^>]*>", re.I)


def split_html_doctype(document: str):
    """(the leading DOCTYPE declaration with its line break, the rest) — §3.3.1.
    The head block is written AFTER a leading DOCTYPE, so the removal steps over
    the same token the signer stepped over."""
    m = _HTML_DOCTYPE_RE.match(document)
    if m is None or m.group(0).count('"') % 2:
        return "", document
    end = m.end()
    for brk in ("\r\n", "\n"):
        if document[end:end + len(brk)] == brk:
            end += len(brk)
            break
    return document[:end], document[end:]


def _eol_length(text: str, at: int) -> int:
    if text.startswith("\r\n", at):
        return 2
    if text.startswith("\n", at):
        return 1
    return 0


def strip_html_envelope(body: str):
    """
    Take the outer HTML envelope off an HTML part (spec §6.1, the HTML rule), as
    (text, kind).

    The part must BEGIN with a head block — its opening comment at the very start
    or right after a leading DOCTYPE — and END with the matching tail block. The
    comments are never searched for inside the part, exactly as the plain markers
    are not: a block quoted in a reply or an inline forward is content and
    stays in the hash. A not-verified envelope is recognised and NEVER taken off,
    so such a part does not recompute to a signature.

    Byte for byte the removal every signer of this protocol performs (§6.1).
    """
    text = "" if body is None else str(body)
    doctype, rest = split_html_doctype(text)
    kind = next((k for k in HTML_ENVELOPE_KINDS if rest.startswith(k[1])), None)
    if kind is None:
        return text, None
    name, start, end = kind
    if name == "not-verified":
        return text, "not-verified"
    second = rest.find(start, len(start))
    if second == -1:
        return text, None
    head_end = second + len(start)
    head_end += _eol_length(rest, head_end)
    last_end = rest.rfind(end)
    if last_end < head_end:
        return text, None
    # The tail block must be what ENDS the part: nothing but line breaks after it.
    if rest[last_end + len(end):].replace("\r", "").replace("\n", "") != "":
        return text, None
    tail_start = rest.rfind(end, 0, last_end)
    if tail_start < head_end:
        return text, None
    return doctype + rest[head_end:tail_start], name


def strip_zeknop_html_envelope(body: str) -> str:
    """The §6.1 HTML removal as a str→str transform, for mime_walk's html_transform."""
    return strip_html_envelope(body)[0]


def html_envelope_kind(body: str):
    """Which HTML envelope a part carries outermost (spec §6.1), or None."""
    return strip_html_envelope(body)[1]


def delivered_envelope_kind(body: str):
    """
    Which envelope a delivered text carries outermost (spec §6.1): "positive",
    "legacy-positive", "not-verified", or None when none is complete. A text
    whose outer envelope is "not-verified" is never shown as verified (spec §6).
    """
    outer = _outer_delivered_envelope(body)
    return None if outer is None else outer[0]
