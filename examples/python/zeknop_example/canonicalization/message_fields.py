# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zeknod OÜ
#
# A copy of the ZEKNOP reference implementation of the canonical content
# specification, carried by the Python example so that the example computes the
# same bytes as the service that signed the message. Apart from this header and
# the substitutions recorded with the copy, nothing in this file was changed.

"""The canonical fields of a message, read off a parsed message.

`From` and the recipients as `canonical-content.md` §3 and §4 define them, and
the text of a Shape A message as §1.1 does. A copy of the reference
implementation; see NOTICE.
"""

from email.message import EmailMessage

from . import mime_walk


def _strip_local_quotes(addr: str) -> str:
    """Strip quotes from local-part for cross-component consistency (spec §3)."""
    if "@" not in addr:
        return addr
    local, domain = addr.rsplit("@", 1)
    if local.startswith('"') and local.endswith('"') and len(local) > 1:
        local = local[1:-1]
    return f"{local}@{domain}"

def extract_from_addr(msg: EmailMessage) -> str:
    """
    Canonical From (canonical-content.md §3): FIRST From instance, FIRST
    mailbox, bare lowercase, quotes stripped.

    getaddresses (not parseaddr): strict-mode parseaddr (the CVE-2023-27043
    fix) returns '' for a multi-mailbox From instead of taking the first
    mailbox, which is not what §3 says and not what the other readers of
    this protocol do.
    """
    value = msg.get("From")
    if not value:
        return ""
    from email.utils import getaddresses

    parsed = [addr for _, addr in getaddresses([str(value)]) if addr]
    if not parsed:
        return ""
    return _strip_local_quotes(parsed[0].lower())

def extract_recipients(msg: EmailMessage) -> list[str]:
    """
    Extract recipient addresses from To and Cc headers.

    canonical-content.md §4: ALL header instances contribute — every To
    value first, then every Cc value. Reading one instance per name would
    silently drop a duplicate field, which every other reader of this
    protocol includes, and the two would then hash different messages.
    """
    from email.utils import getaddresses

    recipients = []
    for header_name in ("To", "Cc"):
        values = msg.get_all(header_name) or []
        if values:
            addrs = getaddresses([str(v) for v in values])
            recipients.extend(
                _strip_local_quotes(addr.lower()) for _, addr in addrs if addr
            )
    return recipients

def _text_of(part: EmailMessage) -> str:
    """One text part's text. A legacy single-byte charset is read by the shared
    table (canonical-content.md §2 step 0), as every other reader of the message
    reads it; any other charset through the email package."""
    encoding = mime_walk.single_byte_encoding(part.get_content_charset())
    if encoding:
        return mime_walk.decode_single_byte(part.get_payload(decode=True) or b"", encoding)
    payload = part.get_content()
    return payload if isinstance(payload, str) else ""

def extract_plain_text(msg: EmailMessage) -> str:
    """
    Extract text/plain body from an email message.
    Handles multipart/* messages by walking MIME parts.
    Returns empty string if no text/plain part found.
    """
    content_type = msg.get_content_type()

    if content_type == "text/plain":
        return _text_of(msg)

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                return _text_of(part)

    return ""
