# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zeknod OÜ
"""A stand-in for a relay, for the tests of this example. Standard library only.

It is NOT a relay and must not be mistaken for one. A relay holds a signing key
and makes an Ed25519 signature; nothing in the standard library does Ed25519, so
this stand-in makes a keyed digest instead. What that still proves is the part the
example is responsible for:

* the example asks what the relay can sign before it writes a version;
* the bytes the example assembled as the signature input are the bytes the
  "signature" was made over — a client that built a different input, or named a
  different version, gets `valid: false` here exactly as it would from a relay;
* a message changed after signing recomputes to another hash, so the triple is a
  different triple and the answer is `valid: false` with `signature-mismatch`.

What it does NOT prove is anything about Ed25519, about a real relay's storage, or
about any of its refusals. The run against a relay is a separate test.
"""

import base64
import hashlib
import hmac
import json
import secrets
import string
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Chosen per process and used for nothing but the keyed digest below. It is not a
# key of anything and it leaves the process in no answer.
_SECRET = secrets.token_bytes(32)

#: The versions this stand-in says it can sign, as a relay of contract 1.8 does.
SIGNS = ["1.4", "1.5"]
CONTRACT = "1.8"
RELAY_ID = "relay.example.org"

#: The one identity it knows, and its key. Example values only.
IDENTITY = "11111111-2222-3333-4444-555555555555"
API_KEY = "example-key-not-a-real-credential"
IDENTITY_ADDRESS = "sender@example.org"

#: When a test sets this to a status code, `POST /v1/verify` answers it instead of
#: a verdict. It stands in for something in front of a relay — a gateway, a proxy
#: — rather than for anything a relay does: that path asks for no credential.
VERIFY_ANSWERS_INSTEAD = None


def _signature(version, algorithm, strict_b64: str, free_b64) -> str:
    """The keyed digest over the signature input the request describes."""
    # Imported here so that the stand-in builds the input with the example's own
    # module: if the example assembles §2 wrongly, both sides are wrong together
    # and the test would pass. The test that holds §2 to its vectors is the
    # conformance run, and that one does not use this file.
    from zeknop_example import signature_input

    strict = base64.b64decode(strict_b64)
    free = base64.b64decode(free_b64) if free_b64 else None
    data = signature_input.for_message(version, algorithm, strict, free)
    return base64.b64encode(hmac.new(_SECRET, data, hashlib.sha256).digest()).decode("ascii")


def _envelope_id() -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(8))


class Handler(BaseHTTPRequestHandler):
    """The three public paths this example calls, and nothing else."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # the tests are the output, not the access log
        pass

    def _send(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(length) or b"{}")

    def do_GET(self):  # noqa: N802 — the name the standard library dispatches on
        if self.path == "/v1/capabilities":
            self._send(
                200,
                {
                    "contract": CONTRACT,
                    "relay_id": RELAY_ID,
                    "signs": SIGNS,
                    "verifies": SIGNS,
                    "signature_input_version": SIGNS[-1],
                },
            )
            return
        if self.path == "/health":
            self._send(200, {"status": "ok"})
            return
        self._send(404, {"detail": "no such path on this stand-in"})

    def do_POST(self):  # noqa: N802
        if self.path == "/v1/sign":
            self._sign()
            return
        if self.path == "/v1/verify":
            self._verify()
            return
        self._send(404, {"detail": "no such path on this stand-in"})

    def _sign(self) -> None:
        if self.headers.get("X-API-Key") != API_KEY:
            self._send(401, {"detail": "the key is not one this relay holds"})
            return
        body = self._body()
        if body.get("uuid") != IDENTITY:
            self._send(404, {"detail": "no record of that identity"})
            return
        if body.get("version") and body["version"] not in SIGNS:
            self._send(400, {"detail": "this relay does not sign that version"})
            return
        self._send(
            200,
            {
                "signature": _signature(
                    body.get("version"),
                    body.get("alg"),
                    body["content_hash"],
                    body.get("free_hash"),
                ),
                "relay_id": RELAY_ID,
                "relay_timestamp": body["timestamp"],
                "envelope_id": _envelope_id(),
                "version": body.get("version"),
                "alg": body.get("alg") or "ed25519",
            },
        )

    def _verify(self) -> None:
        if VERIFY_ANSWERS_INSTEAD is not None:
            self._body()
            self._send(VERIFY_ANSWERS_INSTEAD, {"detail": "not from the relay"})
            return
        body = self._body()
        if body.get("uuid") != IDENTITY:
            self._send(
                200, {"valid": False, "uuid": body.get("uuid", ""), "reason": "unknown-identity"}
            )
            return
        expected = _signature(
            body.get("version"), body.get("alg"), body["message_hash"], body.get("free_hash")
        )
        if not hmac.compare_digest(expected, body.get("signature", "")):
            self._send(
                200,
                {"valid": False, "uuid": body["uuid"], "reason": "signature-mismatch"},
            )
            return
        self._send(
            200,
            {
                "valid": True,
                "uuid": body["uuid"],
                "email": IDENTITY_ADDRESS,
                "verification_level": "mailbox",
                "status": "active",
            },
        )


class StandIn:
    """Start it, read `url`, stop it. Only the thread it started is ever stopped."""

    def __init__(self):
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_exc):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
        return False
