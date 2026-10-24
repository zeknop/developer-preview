# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zeknod OÜ
"""Writing the signed message out: the header fields, and the visible block.

Order matters here for one reason that is worth stating plainly: the block is
written AFTER the relay has answered, and the fields are written after the block.
A message that shows the markers without the fields would look checked and be
uncheckable — the markers are text, and `delivered-envelope.md` §8 is explicit
that the verdict belongs to the end point and never to the block.

What this example writes the block into, and what it does not
-------------------------------------------------------------
It writes the block into a message that is ONE non-multipart displayed part — a
`text/plain` part (§3.3) or a `text/html` part (§3.3.1) — whose transfer encoding
is `7bit`, `8bit`, `binary` or absent, whose charset is UTF-8 or US-ASCII, and
whose payload is in fact that charset. An EMPTY part is written into like any
other: §4 says an empty message body carries the envelope around empty content.

Anything else is signed and delivered WITHOUT the block, and says so. That is not
a gap this example papers over: §4 names exactly that case (a part whose transfer
encoding the signer does not decode exactly, a charset it cannot write ASCII bytes
into, no displayed part at all) and says the message is signed, it verifies, and
it shows no markers. A production signer writes into more than this one does; what
neither may do is write a block it cannot write exactly.
"""

import re

from . import envelope, message

#: §4 — the transfer encodings this example writes a block under. A base64 or
#: quoted-printable payload would have to be re-encoded, and a block written into
#: a payload that was not decoded exactly is a changed message.
WRITABLE_ENCODINGS = ("", "7bit", "8bit", "binary")

#: §4, §3.3.1 — the charsets this example writes ASCII marker bytes into.
WRITABLE_CHARSETS = ("", "utf-8", "utf8", "us-ascii", "ascii")

_HEADER_SEPARATOR = re.compile(rb"\r?\n\r?\n")


def split_message(raw: bytes):
    """(header block, the separator, payload). The payload is the exact wire slice."""
    match = _HEADER_SEPARATOR.search(raw)
    if match is None:
        return raw, b"", b""
    return raw[: match.start()], raw[match.start() : match.end()], raw[match.end() :]


def strip_zeknop_fields(header_block: bytes) -> tuple[bytes, int]:
    """Every `X-ZEKNOP-*` field a sender wrote, removed, with its continuations.

    A signer controls these field names, so a value already in the message is a
    value somebody else wrote. It goes before anything is signed: one of them is
    the field a verifier reads the signature out of.
    """
    kept = []
    removed = 0
    dropping = False
    for line in header_block.split(b"\n"):
        stripped = line.rstrip(b"\r")
        if stripped[:1] in (b" ", b"\t"):
            if dropping:
                continue
            kept.append(line)
            continue
        dropping = stripped.lower().startswith(b"x-zeknop-")
        if dropping:
            removed += 1
            continue
        kept.append(line)
    return b"\n".join(kept), removed


def _eol_of(payload: bytes) -> str:
    """The line ending of the part: CRLF on the wire, LF for a payload that
    demonstrably uses bare LF (§3.3).

    A payload with no line break in it at all demonstrates nothing — an empty
    part, or one line with no ending — so it gets the CRLF of the wire rather than
    a block in an ending the rest of the message does not use.
    """
    return "\n" if b"\n" in payload and b"\r\n" not in payload else "\r\n"


def block_refusal(part) -> str:
    """Why this example writes no block into `part`, or '' when it writes one.

    Every condition it refuses on is decided HERE, before the relay is asked, so
    that nothing is discovered half way through writing a message out. An empty
    part is not one of them: §4 says an empty message body carries the envelope
    around empty content, and this example only ever writes into a message that
    is one non-multipart part.
    """
    if part.content_type not in ("text/plain", "text/html"):
        return f"the message is not one displayed text part ({part.content_type})"
    if (part.cte or "") not in WRITABLE_ENCODINGS:
        return f"the transfer encoding is {part.cte!r}, which this example does not re-encode"
    if (part.charset or "").lower() not in WRITABLE_CHARSETS:
        return f"the charset is {part.charset!r}, which this example does not write into"
    if _undecodable(part.body_raw):
        # §4: a display text is decoded exactly or not at all. The label says
        # UTF-8 (or US-ASCII, which these bytes are not) and the payload is not
        # that, so writing the block would mean writing bytes back through a
        # decoding that is not exact — a changed message. The hashes are unaffected
        # either way: §2 step 0 reads a part that does not decode with replacement
        # characters, which is a reading and not a rewriting of the part.
        return "the payload is not the charset it declares, so it is not decoded exactly"
    return ""


def _undecodable(payload: bytes) -> bool:
    """Whether `payload` is NOT the UTF-8 (or US-ASCII) its label claims.

    It is the same decoding `wrap` does, asked where the decision is made rather
    than where the bytes are written.
    """
    try:
        payload.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def wrap(raw: bytes, part, envelope_id: str, verify_url: str) -> bytes:
    """The same message with the positive block around the content of its one part.

    A plain part's trailing line breaks come off before the block goes on. §3.3 is
    byte for byte: `content` EOL EOL `======= END ZEKNOP =======`, so the content
    handed to the block ends with its last line and not with that line's ending —
    one blank line between the two, never two. The removal of §6.1 takes the same
    blank line off again, so a round trip ends where it started. Neither hash
    moves either way (§2 trims the ends of the body), which is exactly why this
    has to be got right on purpose: the delivered bytes would differ from every
    other signer's and nothing local would complain.

    An HTML part is passed through untouched: §3.3.1 inserts nothing between a
    block and the sender's markup.
    """
    header_block, separator, payload = split_message(raw)
    eol = _eol_of(payload)
    if part.content_type == "text/html":
        wrapped = envelope.build_html(
            "positive", payload.decode("utf-8"), envelope_id, verify_url, eol
        )
    else:
        wrapped = envelope.build_plain(
            "positive", payload.decode("utf-8").rstrip("\r\n"), envelope_id, verify_url, eol
        )
    return header_block + separator + wrapped.encode("utf-8")


def header_lines(
    version,
    algorithm,
    signature: str,
    content_hash: str,
    uuid: str,
    timestamp: str,
    relay_id: str,
    level: str,
    envelope_id,
    verify_url,
) -> list:
    """The fields of `signature-input.md` §1 and `delivered-envelope.md` §3.1.

    `X-ZEKNOP-Version` is the version the relay signed under — the one inside the
    signed bytes — and not the newest this example knows. `X-ZEKNOP-Hash` is the
    strict hash; the free hash is not a field, because a verifier recomputes it
    from the message rather than being told it.
    """
    fields = []
    if version:
        fields.append((message.HEADER_VERSION, version))
        fields.append((message.HEADER_SIG_ALG, algorithm))
    fields += [
        (message.HEADER_SIGNATURE, signature),
        (message.HEADER_HASH, content_hash),
        (message.HEADER_UUID, uuid),
        (message.HEADER_TIMESTAMP, timestamp),
    ]
    if relay_id:
        fields.append((message.HEADER_RELAY, relay_id))
    if level:
        fields.append((message.HEADER_LEVEL, level))
    if envelope_id:
        fields.append((message.HEADER_ENVELOPE_ID, envelope_id))
    if verify_url:
        fields.append((message.HEADER_VERIFY, verify_url))
    for name, value in fields:
        if "\r" in str(value) or "\n" in str(value):
            raise ValueError(f"{name} carries a line break and would forge a second field")
    return [f"{name}: {value}" for name, value in fields]


def with_fields(raw: bytes, lines: list) -> bytes:
    """The message with those fields at the top of its header block, and every
    `X-ZEKNOP-*` field that was already there removed first."""
    header_block, separator, payload = split_message(raw)
    cleaned, _removed = strip_zeknop_fields(header_block)
    eol = b"\r\n" if b"\r\n" in header_block or not header_block else b"\n"
    written = eol.join(line.encode("utf-8") for line in lines)
    return written + eol + cleaned + separator + payload
