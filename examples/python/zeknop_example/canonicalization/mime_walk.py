# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zeknod OÜ
#
# A copy of the ZEKNOP reference implementation of the canonical content
# specification, carried by the Python example so that the example computes the
# same bytes as the service that signed the message. Apart from this header and
# the substitutions recorded with the copy, nothing in this file was changed.
"""
An offset-based MIME walker (canonical-content.md §9).

Why this exists instead of email.message.walk(): the v1.3 parts manifest binds
`message/rfc822` as an OPAQUE LEAF — the hash covers the attached message's
wire bytes exactly as delivered. Python's email package parses the nested
message into an object tree and can only re-serialize it (as_bytes), which is
NOT byte-identical to the wire form (line endings, header folding), so a hash
over the round-trip would diverge from a signer's hash over the raw stream.
This walker splits the raw bytes itself — multipart boundaries by
offset, headers via BytesHeaderParser (which never touches payloads) — so
every leaf's payload is the exact wire slice, and message/rfc822 is simply
never descended into.

The walker is used for Shape B (parts manifest) only. Shape A (single
text/plain message) is read through the standard library's email package
instead (message_fields.extract_plain_text).
"""

import base64
import binascii
import hashlib
import quopri
import re
from dataclasses import dataclass, field
from email.parser import BytesHeaderParser
from email import policy
from urllib.parse import unquote

# RELATIVE import on purpose: this module and canonical.py are ONE
# implementation, and an absolute import would pin them to one package name
# and force anything else that needs the same canonicalisation to fork a copy.
from .canonical import normalize_body, trim, MAX_BODY_SIZE
# The shared reading of a legacy single-byte charset (generated table). Every
# reader of this protocol reads such a part with the same table.
from .single_byte import single_byte_encoding, decode_single_byte, encode_single_byte  # noqa: F401
from .multi_byte import multi_byte_encoding, decode_multi_byte  # noqa: F401


@dataclass
class Part:
    content_type: str          # lowercased "type/subtype"
    disposition: str           # lowercased or ""
    filename: str | None       # RFC 2047/2231-decoded, raw casing
    content_id: str | None
    charset: str | None
    cte: str                   # lowercased Content-Transfer-Encoding or ""
    body_raw: bytes            # exact wire slice of the payload
    children: list["Part"] = field(default_factory=list)


_HEADER_SEP = re.compile(rb"\r?\n\r?\n")


def _split_headers(raw: bytes) -> tuple[bytes, bytes]:
    """Split a part into (header block incl. trailing newline, payload)."""
    m = _HEADER_SEP.search(raw)
    if not m:
        # Header-only part (no blank line): everything is headers, empty body.
        return raw, b""
    return raw[: m.start()] + b"\n", raw[m.end():]


def _parse_header_fields(header_bytes: bytes):
    """Parse ONLY the header block. BytesHeaderParser never reads payloads, so
    this is safe for byte-fidelity — the payload stays an untouched slice."""
    return BytesHeaderParser(policy=policy.default).parsebytes(header_bytes)


# ── §9.2a: the ONE reading of a boundary parameter ───────────────────────────
#
# RFC 2231 lets a parameter be written in numbered segments (`boundary*0`,
# `boundary*1`). A reader that puts them back together finds the parts the sender
# wrote; one that does not finds ONE opaque leaf where the sender wrote two — and
# the two readers then hash different messages. One reading is therefore
# normative, and §9.2a is it.
#
# The reading below is the SIGNER's, which is the canonical one because the
# signature covers the manifest the signer built: a verifier that reads a boundary
# the signer did not is a verifier that cannot verify. A walker used on both sides
# is a signer too, so the same rule closes a signer-against-signer gap as well.
#
# What it means in words (spec/canonical-content.md §9.2a):
#   1. a segment is `attribute*N` (or `attribute*`, or `attribute*N*`) with NO white
#      space between the segment name and the `=`;
#   2. segments are joined by their literal spelling `*0`, `*1`, `*2`, … and the join
#      stops at the first spelling that is absent — `*01` is not `*1`;
#   3. segment names group by exact case; the parameter is then looked up
#      case-insensitively;
#   4. a plain `boundary=` written in the same field wins over the segments;
#   5. the joined value is percent-decoded;
#   6. and when nothing usable comes out, the container has NO boundary and becomes
#      one opaque leaf (§9.2, fail-closed).
_ATTR_CHARS = frozenset("!#$%&'+.^_`{|}~-0123456789"
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
# The signer's own pattern, as JavaScript spells it: `new RegExp(`${key}\\s*=\\s*"([^"]+)"|${key}\\s*=\\s*"?([^";]+)"?`, 'i')`
_BOUNDARY_RE = re.compile(r'boundary\s*=\s*"([^"]+)"|boundary\s*=\s*"?([^";]+)"?', re.I)


def _parameter_segments(value: str):
    """Every RFC 2231 segment in `value`, as the signer's tokenizer finds them:
    `(attribute, section, raw value)` with `section` the digits AS WRITTEN."""
    n = len(value)
    i = 0
    while i < n:
        start = i
        while i < n and value[i] in _ATTR_CHARS:
            i += 1
        if i <= start or i >= n or value[i] != "*":
            if i == start:
                i += 1
            continue
        attribute = value[start:i]
        i += 1                                   # the mandatory "*"
        digits_start = i
        while i < n and value[i].isdigit() and value[i].isascii():
            i += 1
        section = value[digits_start:i] if i > digits_start else "0"
        if i < n and value[i] == "*":
            i += 1                               # the optional encoded flag
        if i >= n or value[i] != "=":
            continue                             # white space here = not a segment
        i += 1
        j = i
        while j < n and value[j].isspace():
            j += 1
        raw = None
        if j < n and value[j] == '"':
            k = j + 1
            while k < n:
                if value[k] == "\\":
                    k += 2
                    continue
                if value[k] == '"':
                    raw = value[j + 1:k]
                    i = k + 1
                    if i < n and value[i] == ";":
                        i += 1
                    break
                k += 1
        if raw is None:
            value_start = i
            while i < n and not value[i].isspace():
                i += 1
            raw = value[value_start:i]
            if raw.endswith(";"):
                raw = raw[:-1]
        yield attribute, section, raw


def _percent_decode(text: str) -> str:
    """`decodeURIComponent`, and on a broken escape the text as it stands (the signer
    logs the failure and keeps the merged text)."""
    try:
        return unquote(text, encoding="utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError):
        return text


def _folded_parameters(value: str) -> str:
    """`value` with every continued parameter folded and appended, exactly as the
    signer's header decoder appends them before the boundary is read."""
    merged_of: dict[str, dict[str, str]] = {}
    charset_of: dict[str, str] = {}
    cur_key = ""
    cur_lang = ""
    cur_enc = ""
    for attribute, section, raw in _parameter_segments(value):
        piece = raw
        lang = re.match(r"^(.*?)'(.*?)'(.*)", piece, re.S)
        if lang:
            if attribute == cur_key and lang.group(2) != cur_lang:
                continue
            cur_enc, cur_lang = lang.group(1), lang.group(2)
            piece = lang.group(3)
        elif attribute != cur_key:
            cur_enc, cur_lang = "", ""
        cur_key = attribute
        charset_of[attribute] = cur_enc
        merged_of.setdefault(attribute, {})[section] = piece
    out = value
    for attribute, sections in merged_of.items():
        merged = ""
        index = 0
        while str(index) in sections:
            merged += sections[str(index)]
            index += 1
        merged = _percent_decode(merged)
        charset = charset_of.get(attribute) or ""
        if charset:
            try:
                merged = merged.encode("utf-8", "surrogateescape").decode(charset, "replace")
            except LookupError:
                pass
        out += f' {attribute}="{merged}";'
    return out


def usable_boundary(content_type: str) -> str:
    """The boundary of a `multipart/*` container, or "" when the field has none the
    signer can use (§9.2a). "" means ONE opaque leaf, never a silent descend."""
    match = _BOUNDARY_RE.search(_folded_parameters(unfold_header(content_type or "")))
    if not match:
        return ""
    return (match.group(1) or match.group(2) or "").strip()


def _split_multipart(body: bytes, boundary: bytes) -> list[bytes]:
    """RFC 2046 boundary split. The CRLF preceding a delimiter belongs to the
    delimiter, so each returned chunk is the exact wire slice of one part."""
    delim = b"--" + boundary
    chunks: list[bytes] = []
    pos = 0
    start = None  # start offset of the current (not yet appended) part
    closed = False
    while True:
        idx = body.find(delim, pos)
        if idx == -1:
            break
        # Delimiter must sit at the start of a line.
        if idx > 0 and body[idx - 1: idx] != b"\n":
            pos = idx + len(delim)
            continue
        after = idx + len(delim)
        # RFC 2046 §5.1.1: the delimiter is `--boundary`, then either "--"
        # (close) or optional transport padding, each followed by a line break
        # (or end of body — a truncated final line, as a signer's parser reads it).
        # A trailing character that is NOT padding/CRLF means `boundary` is only
        # a PREFIX of a LONGER boundary token — NOT a delimiter here:
        #   "--BND1"    (longer name)          → neither close nor part
        #   "--BND--1"  (close tail is "1")     → NOT the close of BND
        # Missing this splits nested boundaries that extend the outer one at the
        # wrong level and the manifest diverges from RFC-correct parsers.
        _term = rb"[ \t]*(?:\r?\n|\Z)"
        is_close = (
            body[after: after + 2] == b"--"
            and re.match(_term, body[after + 2:]) is not None
        )
        is_part = re.match(_term, body[after:]) is not None
        if not is_close and not is_part:
            pos = after
            continue
        # End of the previous part: strip the ONE line ending that belongs
        # to the delimiter line.
        if start is not None:
            end = idx
            if body[end - 1: end] == b"\n":
                end -= 1
                if body[end - 1: end] == b"\r":
                    end -= 1
            chunks.append(body[start:end])
            start = None
        if is_close:
            closed = True
            break
        # Skip transport padding and the line ending after the delimiter.
        m = re.match(rb"[ \t]*\r?\n", body[after:])
        start = after + (m.end() if m else 0)
        pos = start
    if start is not None and not closed:
        # Unterminated multipart (closing delimiter never arrived) — take the
        # rest as the final part. Fail-open on structure, but every byte still
        # lands in some leaf's hash, so tampering cannot hide here.
        chunks.append(body[start:])
    return chunks


def decode_cte(body_raw: bytes, cte: str) -> bytes:
    """Remove the Content-Transfer-Encoding. Unknown encodings fall back to
    identity — the bytes still get hashed, nothing is silently dropped."""
    enc = (cte or "").strip().lower()
    if enc == "base64":
        try:
            return base64.b64decode(re.sub(rb"\s+", b"", body_raw), validate=False)
        except (binascii.Error, ValueError):
            return body_raw
    if enc == "quoted-printable":
        try:
            return quopri.decodestring(body_raw)
        except Exception:
            return body_raw
    return body_raw


def decode_text(data: bytes, charset: str | None) -> str:
    """A text part's bytes -> its text, through the charset it declares.

    spec/canonical-content.md §2: the label names an encoding of the WHATWG
    Encoding Standard, and the bytes are read by that encoding's decoder over the
    tables pinned in this repository — a legacy single-byte one (single_byte.py)
    or a multi-byte one (multi_byte.py). A label that names no encoding, and a
    part that declares no charset, are read as UTF-8.

    No codec of the runtime decides this. Python reads iso-8859-1 0x93 as U+0093
    and leaves windows-1250 0x81 undefined where the recipient's client shows a
    quotation mark and U+0081, and its multi-byte codecs differ from the standard
    in where an error falls and how many characters it costs. Reading never
    fails: a byte the encoding cannot use is U+FFFD, so no charset label can make
    a message unverifiable or undeliverable.
    """
    encoding = single_byte_encoding(charset)
    if encoding:
        return decode_single_byte(data, encoding)
    encoding = multi_byte_encoding(charset)
    if encoding:
        return decode_multi_byte(data, encoding)
    return bytes(data).decode("utf-8", errors="replace")


_ENCODED_WORD = re.compile(r"=\?([^?]+)\?([bBqQ])\?([^?]*)\?=")
_HEX_PAIR = re.compile(r"[0-9a-fA-F]{2}")
_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_B64_VALUE = {c: i for i, c in enumerate(_B64_ALPHABET)}
_B64_STRIP = re.compile(r"[^A-Za-z0-9+/=]")
_B64_PADDING = re.compile(r"=+$")


def _encoded_word_base64(text: str) -> bytes | None:
    """The bytes of a B encoded word, or None when the word is not one."""
    clean = _B64_PADDING.sub("", _B64_STRIP.sub("", text))
    if len(clean) % 4 == 1:
        return None
    out = bytearray()
    buffer = bits = 0
    for ch in clean:
        value = _B64_VALUE.get(ch)
        if value is None:          # an '=' that is not padding
            return None
        buffer = (buffer << 6) | value
        bits += 6
        if bits >= 8:
            bits -= 8
            out.append((buffer >> bits) & 0xFF)
    return bytes(out)


def _encoded_word_quoted(text: str) -> bytes:
    """The bytes of a Q encoded word. Nothing here can fail."""
    out = bytearray()
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "_":
            out.append(0x20)
            i += 1
            continue
        if ch == "=" and i + 2 < n and _HEX_PAIR.fullmatch(text[i + 1:i + 3]):
            out.append(int(text[i + 1:i + 3], 16))
            i += 3
            continue
        out.append(ord(ch) & 0xFF)
        i += 1
    return bytes(out)


def decode_header_bytes(data: bytes) -> str:
    """Header bytes -> text. An 8-bit header is UTF-8 in practice; latin-1 never
    fails, so a header block can always be read."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def first_raw_header(raw: bytes, name: str) -> str:
    """The first instance of a header field, exactly as it stands on the wire.

    Parsed here rather than by Python's email package on purpose: policy.default
    would hand back a value Python has already decoded with its own RFC 2047
    reading, and compat32 would hand back an 8-bit header as surrogate escapes.
    Section 5 is decided by decode_encoded_words over this text, which is the
    text the portal's parseHeaderBlock builds from the same bytes.
    """
    header_bytes, _ = _split_headers(raw)
    lower = name.lower()
    fields: list[list[str]] = []
    for line in decode_header_bytes(header_bytes).replace("\r\n", "\n").split("\n"):
        if not line:
            continue
        if line[0] in " \t" and fields:
            fields[-1][1] += "\n" + line
            continue
        idx = line.find(":")
        if idx <= 0:
            continue
        fields.append([line[:idx].strip().lower(), line[idx + 1:]])
    for field_name, value in fields:
        if field_name == lower:
            return value
    return ""


def unfold_header(value: str) -> str:
    """RFC 5322 2.2.3: delete the line break, keep the folding whitespace."""
    return re.sub(r"\r?\n", "", value or "")


def decode_encoded_words(value: str) -> str:
    """spec/canonical-content.md 5: RFC 2047 encoded words -> text.

    The charset of an encoded word is read by exactly the rule of section 2
    (decode_text), so a Subject and a text part that declare the same charset are
    read by the same table. A word whose syntax is broken - a B payload that is
    not base64 - is not an encoded word and stays in the Subject exactly as it
    stands; nothing here raises, so no Subject can make a message undeliverable.
    Whitespace between two adjacent encoded words is removed (RFC 2047 6.2);
    everything else is kept.
    """
    value = unfold_header(value)
    if "=?" not in value:
        return value
    out = []
    last = 0
    previous_was_word = False
    for match in _ENCODED_WORD.finditer(value):
        charset = match.group(1).split("*")[0]
        kind = match.group(2).lower()
        payload = (_encoded_word_base64(match.group(3)) if kind == "b"
                   else _encoded_word_quoted(match.group(3)))
        if payload is None:
            previous_was_word = False
            continue
        between = value[last:match.start()]
        if not (previous_was_word and between.strip(" \t") == ""):
            out.append(between)
        out.append(decode_text(payload, charset))
        last = match.end()
        previous_was_word = True
    out.append(value[last:])
    return "".join(out)


def parse_part(raw: bytes) -> Part:
    header_bytes, payload = _split_headers(raw)
    hdr = _parse_header_fields(header_bytes)

    content_type = (hdr.get_content_type() or "text/plain").lower()
    disposition = (hdr.get_content_disposition() or "").lower()
    filename = hdr.get_filename()
    content_id = hdr.get("Content-ID")
    charset = hdr.get_content_charset()
    cte = (hdr.get("Content-Transfer-Encoding") or "").strip().lower()

    part = Part(
        content_type=content_type,
        disposition=disposition,
        filename=filename,
        content_id=str(content_id) if content_id else None,
        charset=charset,
        cte=cte,
        body_raw=payload,
    )

    # message/rfc822 is an OPAQUE LEAF (§9.2) — never descend.
    if content_type == "message/rfc822":
        return part

    if content_type.startswith("multipart/"):
        # §9.2a, ONE reading — over the RAW field, not over the value Python's
        # policy has already read with its own parameter rules: those differ from the
        # signer's for a continuation spelled `*01` or `*00`.
        boundary = usable_boundary(first_raw_header(raw, "Content-Type"))
        if boundary:
            for chunk in _split_multipart(payload, boundary.encode("utf-8")):
                part.children.append(parse_part(chunk))
        # A multipart without a boundary parameter is malformed and has no
        # children; extract_parts_manifest binds its raw body as a single
        # opaque leaf (§9.2 fail-closed) so the manifest is never empty.
    return part


def _sha_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


def _text_part_hash(text: str) -> str:
    return _sha_b64(normalize_body(text)[:MAX_BODY_SIZE].encode("utf-8"))


def _norm_name(s: str) -> str:
    return trim(s).lower()


def extract_parts_manifest(root: Part, plain_transform=None, collect=None,
                           html_transform=None) -> list[dict]:
    """§9.1–§9.4: depth-first pre-order walk; every leaf contributes exactly
    one `{"k", ["n",] "h"}` entry, in document order, never sorted.

    plain_transform: optional str→str applied to decoded text/plain leaves
    before normalization — the verifier passes strip_zeknop_envelope here so
    the recomputed hash covers the ORIGINAL text the signer hashed, not the
    delivered envelope-wrapped one (no-op on parts without markers).

    html_transform: the same for decoded text/html leaves (spec/delivered-envelope.md
    §3.3.1: an HTML part carries the envelope as a head and a tail block since
    v1.5). A signer passes the §6.2 removal, a verifier the §6.1 one; both recover
    the text that was hashed. No-op on a part without the blocks.

    collect: optional callback(kind, text) for every displayed text leaf —
    "plain" (after plain_transform) and "html" — in document order. It is how
    free_form_source picks the ONE part the free text form is taken from
    without a second walk that could classify a leaf differently from this one.
    """
    parts: list[dict] = []
    rfc822_counter = [0]

    def visit(p: Part):
        if p.content_type == "message/rfc822":
            i = rfc822_counter[0]
            rfc822_counter[0] += 1
            parts.append({
                "k": "rfc822",
                "n": f"rfc822[{i}]",
                "h": _sha_b64(decode_cte(p.body_raw, p.cte)),
            })
            return
        if p.content_type.startswith("multipart/"):
            if not p.children:
                # Malformed multipart with no usable boundary → no leaves. Fail
                # CLOSED (spec §9.2): bind the container's raw body as a single
                # opaque leaf so the manifest is never empty and the body stays
                # cryptographically bound (the k:"opaque" fallback of §9.2).
                parts.append({"k": "opaque", "h": _sha_b64(p.body_raw)})
                return
            for child in p.children:
                visit(child)
            return

        # Leaf classification — §9.3, first match wins.
        if p.disposition == "attachment" or (p.filename and p.disposition != "inline"):
            entry = {"k": "attachment"}
            if p.filename:
                entry["n"] = _norm_name(p.filename)
            entry["h"] = _sha_b64(decode_cte(p.body_raw, p.cte))
            parts.append(entry)
            return
        if p.content_type == "text/plain" and not p.filename:
            text = decode_text(decode_cte(p.body_raw, p.cte), p.charset)
            if plain_transform:
                text = plain_transform(text)
            if collect:
                collect("plain", text)
            parts.append({"k": "plain", "h": _text_part_hash(text)})
            return
        if p.content_type == "text/html" and not p.filename:
            text = decode_text(decode_cte(p.body_raw, p.cte), p.charset)
            if html_transform:
                text = html_transform(text)
            if collect:
                collect("html", text)
            parts.append({"k": "html", "h": _text_part_hash(text)})
            return
        if p.disposition == "inline" or (not p.disposition and p.content_id):
            entry = {"k": "inline"}
            if p.filename:
                entry["n"] = _norm_name(p.filename)
            elif p.content_id:
                value = trim(p.content_id)
                if value.startswith("<") and value.endswith(">"):
                    value = value[1:-1]
                entry["n"] = "cid:" + _norm_name(value)
            entry["h"] = _sha_b64(decode_cte(p.body_raw, p.cte))
            parts.append(entry)
            return
        # §9.3 rule 6 — catch-all keeps the manifest total.
        entry = {"k": "attachment"}
        if p.filename:
            entry["n"] = _norm_name(p.filename)
        entry["h"] = _sha_b64(decode_cte(p.body_raw, p.cte))
        parts.append(entry)

    visit(root)
    return parts


def free_form_source(root: Part, strip=None, html_strip=None) -> tuple[str, bool]:
    """Which text the FREE form is taken from (canonical-content.md §2b.1), as
    (text, is_html).

    One message has exactly one free hash, so the part is chosen by STRUCTURE and
    never by what a reader happens to be shown: the first displayed text/plain
    leaf in document order with our envelope removed, and only when the message
    has none, the first displayed text/html leaf. A message with neither has the
    empty text — a defined answer rather than a missing one.

    `strip` is the envelope remover (canonical.strip_zeknop_envelope); it is
    passed in so this module keeps no dependency of its own on the envelope.
    """
    found: dict[str, str] = {}

    def collect(kind: str, text: str) -> None:
        found.setdefault(kind, text)

    extract_parts_manifest(root, plain_transform=strip, collect=collect, html_transform=html_strip)
    if "plain" in found:
        return found["plain"], False
    if "html" in found:
        # `html_strip` has already run in the walk; `strip` is the plain-text
        # remover and is applied for the shapes it knows (a part without the
        # HTML blocks that carries the plain envelope as its text).
        return (strip(found["html"]) if strip else found["html"]), True
    return "", False


def is_shape_a(root: Part) -> bool:
    """§1.1: a single non-multipart text/plain part with no filename."""
    return (
        not root.content_type.startswith("multipart/")
        and root.content_type == "text/plain"
        and not root.filename
    )
