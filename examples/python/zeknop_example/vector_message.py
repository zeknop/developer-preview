# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zeknod OÜ
"""A vector of `vectors.json` rendered to the raw bytes of a message.

The vectors describe a message declaratively — the header fields, and either a
body or a MIME tree. A verifier never sees that description: it sees the bytes a
mail client hands a person as "show original". So the conformance run renders
each vector to exactly those bytes and then walks them, which is the path an
implementation is actually measured on. Synthetic part objects would prove
nothing about a walker.

Two wire rules decide the bytes and are worth naming, because getting either
wrong moves a hash:

* a part's payload is followed by CRLF and then the `--boundary` line, and that
  CRLF belongs to the delimiter (RFC 2046 §5.1.1), so a walker takes exactly one
  off;
* a `message/rfc822` payload is written verbatim: its own trailing CRLF is part
  of the attached message and IS hashed (`canonical-content.md` §9.2).

The signing timestamp is written where a delivered message carries it,
`X-ZEKNOP-Timestamp`, which is where a verifier reads it from.
"""

import base64

CRLF = b"\r\n"


def body_from_recipe(parts) -> str:
    """A body given as a RECIPE → the text it stands for.

    `{"literal": s}` and `{"repeat": s, "count": n}` pieces, joined in order. A body
    over the §2 size limit is a megabyte, which neither `vectors.json` nor
    `differential/cases.json` writes out: `e2e-004` carries it as `input.body_parts`
    and a `cut` case of the differential as `parts`, in this one vocabulary. A length
    alone would not do, because it cannot say WHICH code point sits in front of the
    cut, and that is the whole question those cases ask.
    """
    return "".join(
        piece["literal"] if "literal" in piece else piece["repeat"] * piece["count"]
        for piece in parts
    )


def _wrap_base64(text: str) -> bytes:
    """Base64 as a mail client writes it: lines of at most 76 characters."""
    return CRLF.join(text[at : at + 76].encode("ascii") for at in range(0, len(text), 76)) or b""


def _render_node(node: dict, boundary_prefix: str) -> bytes:
    content_type = (node.get("content_type") or "text/plain").lower()
    headers = []
    parameters = []
    if content_type.startswith("text/"):
        parameters.append(f"charset={node.get('charset') or 'utf-8'}")
    if node.get("filename") and not node.get("disposition"):
        parameters.append(f'name="{node["filename"]}"')

    if content_type.startswith("multipart/"):
        boundary = f"{boundary_prefix}x"
        headers.append(f'Content-Type: {node["content_type"]}; boundary="{boundary}"')
        body = [("\r\n".join(headers) + "\r\n\r\n").encode("utf-8")]
        for index, child in enumerate(node.get("children") or []):
            body.append(f"--{boundary}\r\n".encode("utf-8"))
            body.append(_render_node(child, f"{boundary}_{index}_"))
            body.append(CRLF)
        body.append(f"--{boundary}--\r\n".encode("utf-8"))
        return b"".join(body)

    suffix = ("; " + "; ".join(parameters)) if parameters else ""
    headers.append(f'Content-Type: {node["content_type"]}{suffix}')
    if node.get("disposition"):
        name = f'; filename="{node["filename"]}"' if node.get("filename") else ""
        headers.append(f'Content-Disposition: {node["disposition"]}{name}')
    if node.get("content_id"):
        headers.append(f'Content-ID: {node["content_id"]}')

    if "payload_base64" in node:
        # A text leaf in a declared charset: the exact wire payload, already
        # transfer-encoded, so the vector can fix the bytes and not the text.
        headers.append(f'Content-Transfer-Encoding: {node["transfer_encoding"]}')
        payload = base64.b64decode(node["payload_base64"])
    elif "content_base64" in node:
        headers.append("Content-Transfer-Encoding: base64")
        payload = _wrap_base64(node["content_base64"])
    elif "raw" in node:
        payload = node["raw"].encode("utf-8")
    else:
        payload = (node.get("text") or "").encode("utf-8")
    return ("\r\n".join(headers) + "\r\n\r\n").encode("utf-8") + payload


def render(vector: dict, timestamp_header: bool = True) -> bytes:
    """The raw bytes of the message one vector describes.

    A vector may fix the whole header block (`raw_headers`), one field as it
    arrives (`to_header`, `cc_header`, `subject_raw_mime`) or the addresses as a
    list (`to`, `cc`) — a field written explicitly wins over the list, and a field
    already named in `raw_headers` is not written a second time.
    """
    data = vector["input"]
    lines = []
    named = set()
    for name, value in data.get("raw_headers") or []:
        lines.append(f"{name}: {value}")
        named.add(name.lower())
    if "from" not in named and data.get("from") is not None:
        lines.append(f"From: {data['from']}")
    if "to" not in named:
        if data.get("to_header") is not None:
            lines.append(f"To: {data['to_header']}")
        elif isinstance(data.get("to"), list) and data["to"]:
            lines.append("To: " + ", ".join(data["to"]))
    if "cc" not in named:
        if data.get("cc_header") is not None:
            lines.append(f"Cc: {data['cc_header']}")
        elif isinstance(data.get("cc"), list) and data["cc"]:
            lines.append("Cc: " + ", ".join(data["cc"]))
    if "subject" not in named:
        subject = data.get("subject_raw_mime", data.get("subject"))
        if subject is not None:
            lines.append(f"Subject: {subject}")
    lines.append("MIME-Version: 1.0")
    if timestamp_header and data.get("timestamp"):
        lines.append(f"X-ZEKNOP-Timestamp: {data['timestamp']}")

    if data.get("mime_tree"):
        head = ("\r\n".join(lines) + "\r\n").encode("utf-8")
        return head + _render_node(data["mime_tree"], "zb_")

    if isinstance(data.get("body"), str):
        body = data["body"]
    elif isinstance(data.get("body_parts"), list):
        # A body over the maximum of §2 whose last code point before the cut is the
        # point of the vector: given as a recipe, so the file carries no megabyte and
        # still says exactly which code point that is.
        body = body_from_recipe(data["body_parts"])
    elif isinstance(data.get("body_length"), int):
        # The other vector that stores no body: `body_length` characters A, over the
        # maximum of §2, so the truncation is reproducible without a megabyte of
        # JSON in the file.
        body = "A" * data["body_length"]
    else:
        body = ""
    lines.append("Content-Type: text/plain; charset=utf-8")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8") + body.encode("utf-8")
