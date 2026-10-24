#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zeknod OÜ
"""Sign and check one message against a real relay, end to end.

The tests in `tests/` need nobody: they run against a stand-in that makes a keyed
digest instead of a signature. This script is the other half — the same four steps
against a relay that holds a key — and it therefore needs a relay, its address and
an identity on it.

    RELAY_URL=https://relay.example.org \
    SIGNER_UUID=<the identity> \
    SIGNER_API_KEY=<its key> \
    PORTAL_URL=https://verify.example.org/v1 \
    SIGNER_FROM=sender@example.org \
    python3 e2e_local_relay.py

Every value comes from the environment; nothing here has a default relay or a
default portal — the link in the visible block is written into a delivered
message, so an example address in it would be a link nobody serves — and the
example values in this package are `example.org` and `192.0.2.x`. The identity's
key is read from the environment and is not written into any output.

What it does, in order:

1. `GET /v1/capabilities` — what the relay can sign;
2. `sign` a message built here, and write it out;
3. `verify` it against the same relay: the hashes agree and the signature holds;
4. change one character of the body and `verify` again: invalid.

Exit code 0 when all four came out as above, 1 when one of them did not, 2 when
the environment is incomplete. The messages are written into a directory of their
own and the script says where.
"""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from zeknop_example import cli  # noqa: E402

NEEDED = ("RELAY_URL", "SIGNER_UUID", "SIGNER_API_KEY", "PORTAL_URL")

MESSAGE = (
    "From: {sender}\r\n"
    "To: recipient@example.com\r\n"
    "Subject: Invoice 2026-09\r\n"
    "MIME-Version: 1.0\r\n"
    "Content-Type: text/plain; charset=utf-8\r\n"
    "\r\n"
    "Amount due: 100 EUR\r\n"
    "Please pay by Friday.\r\n"
)


def main() -> int:
    missing = [name for name in NEEDED if not os.environ.get(name)]
    if missing:
        print(f"not run: {', '.join(missing)} is not set — see the header of this file")
        return 2
    relay_url = os.environ["RELAY_URL"]
    uuid = os.environ["SIGNER_UUID"]
    api_key = os.environ["SIGNER_API_KEY"]
    sender = os.environ.get("SIGNER_FROM", "sender@example.org")
    portal = os.environ["PORTAL_URL"]

    work = Path(tempfile.mkdtemp(prefix="zeknop-example-"))
    print(f"messages in {work}")
    unsigned = work / "unsigned.eml"
    unsigned.write_bytes(MESSAGE.format(sender=sender).encode("utf-8"))
    signed = work / "signed.eml"

    print("\n1-2. capabilities, then sign")
    code = cli.main(
        [
            "sign",
            str(unsigned),
            "--uuid",
            uuid,
            "--api-key",
            api_key,
            "--relay",
            relay_url,
            "--portal",
            portal,
            "--from",
            sender,
            "--out",
            str(signed),
        ]
    )
    if code != cli.OK:
        print("the message was not signed; nothing further was asked")
        return 1

    print("\n3. verify the signed message")
    if cli.main(["verify", str(signed), "--relay", relay_url]) != cli.OK:
        print("a message straight from the relay did not verify")
        return 1

    print("\n4. verify a message changed after signing")
    tampered = work / "tampered.eml"
    tampered.write_bytes(signed.read_bytes().replace(b"100 EUR", b"900 EUR"))
    if cli.main(["verify", str(tampered), "--relay", relay_url]) != cli.NEGATIVE:
        print("a changed message was not reported as changed")
        return 1

    print("\nall four steps came out as the header of this file says they should")
    return 0


if __name__ == "__main__":
    sys.exit(main())
