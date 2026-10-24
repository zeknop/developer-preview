# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zeknod OÜ
"""`sign` and then `verify`, against the stand-in in `mock_relay.py`.

The stand-in is not a relay and makes no Ed25519 signature — `mock_relay.py` says
what that does and does not prove. What these tests hold is the client's side of
the exchange: the version is asked for before it is written, the bytes under the
signature are the bytes this example assembled, the written message recomputes to
the hash that was signed, and a message changed afterwards comes back invalid.

The run against a real relay is `../e2e_local_relay.py`, which needs one.
"""

import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import mock_relay  # noqa: E402
from zeknop_example import cli, compose, message, relay  # noqa: E402
from zeknop_example.canonicalization import canonical  # noqa: E402

UNSIGNED = (
    b"From: sender@example.org\r\n"
    b"To: recipient@example.com\r\n"
    b"Subject: Invoice 2026-09\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"Amount due: 100 EUR\r\n"
    b"Please pay by Friday.\r\n"
)

UNSIGNED_HTML = (
    b"From: sender@example.org\r\n"
    b"To: recipient@example.com\r\n"
    b"Subject: Invoice 2026-09\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n"
    b"\r\n"
    b"<!DOCTYPE html>\r\n<html><body><p>Amount due: 100 EUR</p></body></html>\r\n"
)


def run(*argv) -> tuple:
    out = io.StringIO()
    with redirect_stdout(out):
        code = cli.main(list(argv))
    return code, out.getvalue()


class SignThenVerify(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.relay = mock_relay.StandIn()
        cls.relay.__enter__()
        cls.url = cls.relay.url

    @classmethod
    def tearDownClass(cls):
        cls.relay.__exit__(None, None, None)

    def setUp(self):
        # A directory of the system's, not one inside the example: the example may be read from
        # a read-only copy, and a test leaves nothing behind in the package either way.
        self._workdir = tempfile.TemporaryDirectory(prefix="zeknop-example-test-")
        self.tmp = Path(self._workdir.name)

    def tearDown(self):
        self._workdir.cleanup()

    def sign(self, source: bytes, name: str = "message.eml"):
        unsigned = self.tmp / name
        unsigned.write_bytes(source)
        out = self.tmp / f"signed-{name}"
        code, text = run(
            "sign",
            str(unsigned),
            "--uuid",
            mock_relay.IDENTITY,
            "--api-key",
            mock_relay.API_KEY,
            "--relay",
            self.url,
            "--portal",
            "https://verify.example.org/v1",
            "--out",
            str(out),
        )
        return code, text, out

    def test_a_signed_message_verifies_against_the_relay_that_signed_it(self):
        code, text, out = self.sign(UNSIGNED)
        self.assertEqual(code, cli.OK, text)
        self.assertIn("visible block written", text)
        self.assertIn("it recomputes to the hashes the relay signed", text)

    def test_the_delivered_bytes_are_the_bytes_3_3_prescribes(self):
        """§3.3 is byte for byte: `content` EOL EOL `======= END ZEKNOP =======`.

        One blank line between the sender's last line and the end marker, never
        two. The hashes do not notice the difference — §2 trims the ends of the
        body — so nothing local complains about it and the only thing that can
        hold it is a comparison against the delivered bytes themselves.
        """
        _code, _text, out = self.sign(UNSIGNED)
        _head, _sep, payload = out.read_bytes().partition(b"\r\n\r\n")
        self.assertIn(b"Please pay by Friday.\r\n\r\n======= END ZEKNOP =======\r\n", payload)
        self.assertNotIn(b"\r\n\r\n\r\n======= END ZEKNOP =======", payload)
        # The block is the form of the `strip` vectors, so the removal of §6.1
        # gives the content back and a round trip ends where it started.
        inner = canonical.strip_zeknop_envelope(payload.decode("utf-8"))
        self.assertEqual(inner, "Amount due: 100 EUR\r\nPlease pay by Friday.")

    def test_an_empty_body_carries_the_block_around_empty_content(self):
        """§4: an empty display text is a display text, and an empty message body
        carries the envelope around empty content."""
        code, text, out = self.sign(UNSIGNED.split(b"\r\n\r\n")[0] + b"\r\n\r\n", "empty.eml")
        self.assertEqual(code, cli.OK, text)
        self.assertIn("visible block written", text)
        payload = out.read_bytes().partition(b"\r\n\r\n")[2]
        self.assertIn(b"\r\n\r\n\r\n\r\n======= END ZEKNOP =======\r\n", payload)
        # An empty part demonstrates no line ending of its own, so the block is
        # written in the CRLF of the wire and not in a second ending (§3.3).
        self.assertNotIn(b"\n", payload.replace(b"\r\n", b""))
        code, text = run("verify", str(out), "--relay", self.url)
        self.assertEqual(code, cli.OK, text)

    def test_a_part_that_is_not_the_charset_it_declares_is_refused_before_signing(self):
        """A `charset=utf-8` part whose payload is not UTF-8 is not written into:
        the block would be written through a decoding that is not exact (§4). The
        decision is taken where the conditions are checked, so nothing fails half
        way through writing a message out — and a fault in here could never print
        a verdict, because only 2 comes out of one."""
        broken = self.tmp / "broken-charset.eml"
        broken.write_bytes(UNSIGNED.replace(b"Amount due: 100 EUR", b"Amount \xff\xfe due"))
        out = self.tmp / "signed-broken.eml"
        code, text = run(
            "sign",
            str(broken),
            "--uuid",
            mock_relay.IDENTITY,
            "--api-key",
            mock_relay.API_KEY,
            "--relay",
            self.url,
            "--portal",
            "https://verify.example.org/v1",
            "--out",
            str(out),
        )
        self.assertEqual(code, cli.OK, text)
        self.assertIn("no visible block: the payload is not the charset it declares", text)
        self.assertNotIn("Traceback", text)
        self.assertNotIn(b"ZEKNOP =======", out.read_bytes())

        code, text = run("verify", str(out), "--relay", self.url)
        self.assertEqual(code, cli.OK, text)
        self.assertIn("valid                True", text)
        self.assertIn("sender@example.org", text)

    def test_the_version_written_is_the_newest_both_sides_can_build(self):
        _code, text, out = self.sign(UNSIGNED)
        self.assertIn(f"signing as  {mock_relay.SIGNS[-1]}", text)
        fields = message.claimed(message.parse(out.read_bytes()))
        self.assertEqual(fields.version, mock_relay.SIGNS[-1])
        self.assertEqual(fields.sig_alg_values, ["ed25519"])

    def test_the_written_message_carries_the_block_and_the_link(self):
        _code, _text, out = self.sign(UNSIGNED)
        raw = out.read_bytes()
        self.assertIn(b"======= ZEKNOP =======", raw)
        self.assertIn(b"======= END ZEKNOP =======", raw)
        fields = message.claimed(message.parse(raw))
        self.assertIn("https://verify.example.org/v1/", fields.verify_url)
        self.assertEqual(len(fields.envelope_id), 8)
        self.assertIn(f"Message ID: {fields.envelope_id}".encode(), raw)

    def test_an_html_message_gets_the_head_and_tail_blocks_and_keeps_its_doctype(self):
        code, text, out = self.sign(UNSIGNED_HTML, "html.eml")
        self.assertEqual(code, cli.OK, text)
        raw = out.read_bytes()
        _head, _sep, payload = raw.partition(b"\r\n\r\n")
        self.assertTrue(payload.startswith(b"<!DOCTYPE html>"), payload[:80])
        self.assertIn(b"<!-- ======= ZEKNOP ======= -->", payload)
        self.assertTrue(payload.rstrip().endswith(b"<!-- ======= END ZEKNOP ======= -->"))
        code, text = run("verify", str(out), "--relay", self.url)
        self.assertEqual(code, cli.OK, text)

    def test_one_character_changed_after_signing_comes_back_invalid(self):
        _code, _text, out = self.sign(UNSIGNED)
        changed = out.read_bytes().replace(b"100 EUR", b"900 EUR")
        tampered = self.tmp / "tampered.eml"
        tampered.write_bytes(changed)
        code, text = run("verify", str(tampered), "--relay", self.url)
        self.assertEqual(code, cli.NEGATIVE, text)
        self.assertIn("Something changed after signing", text)

    def test_the_signature_presented_for_another_message_is_invalid_at_the_relay(self):
        """A hash the relay never signed is a different triple, and the answer is a
        verdict about the signature rather than a refusal."""
        _code, _text, out = self.sign(UNSIGNED)
        fields = message.claimed(message.parse(out.read_bytes()))
        recomputed = message.recompute(out.read_bytes())
        other = "A" * 43 + "="
        answer = relay.verify(
            self.url,
            uuid=fields.uuid,
            signature=fields.signature,
            message_hash=other,
            timestamp=fields.timestamp,
            version=recomputed.accepted_version,
            algorithm=recomputed.algorithm,
            free_hash=recomputed.free_hash,
        )
        self.assertFalse(answer["valid"])
        self.assertEqual(answer["reason"], "signature-mismatch")

    def test_a_version_the_relay_did_not_sign_under_does_not_verify(self):
        """The version is INSIDE the signed bytes. Naming another one makes the
        relay rebuild a different input, which is why a verifier sends the version
        the message announces and never its own newest."""
        _code, _text, out = self.sign(UNSIGNED)
        fields = message.claimed(message.parse(out.read_bytes()))
        recomputed = message.recompute(out.read_bytes())
        answer = relay.verify(
            self.url,
            uuid=fields.uuid,
            signature=fields.signature,
            message_hash=recomputed.content_hash,
            timestamp=fields.timestamp,
            version="1.4",
            algorithm=recomputed.algorithm,
            free_hash=recomputed.free_hash,
        )
        self.assertFalse(answer["valid"])

    def test_a_key_the_relay_does_not_hold_is_a_refusal_and_not_a_verdict(self):
        """A `401` from `POST /v1/sign` is the relay's deterministic answer about
        the request (`api/README.md`): asking again with the same key changes
        nothing, so it is printed as a refusal and not as an outage. Both are
        UNANSWERED — neither says anything about the message — which is why the
        sentence is asserted and not only the code."""
        unsigned = self.tmp / "nokey.eml"
        unsigned.write_bytes(UNSIGNED)
        code, text = run(
            "sign",
            str(unsigned),
            "--uuid",
            mock_relay.IDENTITY,
            "--api-key",
            "not-the-key",
            "--relay",
            self.url,
            "--portal",
            "https://verify.example.org/v1",
            "--out",
            str(self.tmp / "never-written.eml"),
        )
        self.assertEqual(code, cli.UNANSWERED, text)
        self.assertIn("The relay would not sign: 401", text)
        self.assertNotIn("could not be asked", text)
        self.assertFalse((self.tmp / "never-written.eml").exists())

    def test_a_401_on_verify_is_an_outage_because_that_path_sends_no_credential(self):
        """`POST /v1/verify` asks for no credential, so a `401` there is something
        in front of the relay turning this caller away — nobody checked anything.
        `delivered-envelope.md` §2 names 401/403 among the answers that must never
        become a verdict about a message."""
        self.assertIn(401, relay.SIGN_REFUSALS)
        self.assertNotIn(401, relay.DETERMINISTIC_REFUSALS)
        _code, _text, out = self.sign(UNSIGNED)
        fields = message.claimed(message.parse(out.read_bytes()))
        recomputed = message.recompute(out.read_bytes())
        mock_relay.VERIFY_ANSWERS_INSTEAD = 401
        try:
            for code in (401, 403):
                mock_relay.VERIFY_ANSWERS_INSTEAD = code
                with self.subTest(code), self.assertRaises(relay.RelayUnavailable):
                    relay.verify(
                        self.url,
                        uuid=fields.uuid,
                        signature=fields.signature,
                        message_hash=recomputed.content_hash,
                        timestamp=fields.timestamp,
                    )
            mock_relay.VERIFY_ANSWERS_INSTEAD = 403
            exit_code, text = run("verify", str(out), "--relay", self.url)
            self.assertEqual(exit_code, cli.UNANSWERED, text)
            self.assertIn("The relay could not be asked", text)
            self.assertIn("An outage is not a verdict", text)
        finally:
            mock_relay.VERIFY_ANSWERS_INSTEAD = None

    def test_a_relay_that_cannot_be_reached_is_an_outage_and_not_a_verdict(self):
        with self.assertRaises(relay.RelayUnavailable):
            # 192.0.2.0/24 is the reserved documentation range: nothing answers there.
            relay.capabilities("http://192.0.2.10:9", timeout=0.3)


class FieldsASenderWrote(unittest.TestCase):
    """A signer controls the `X-ZEKNOP-*` names, so a value already in the message
    is somebody else's. It goes before anything is signed — and it goes with its
    folded continuations, or the second line of a forged field survives as a field
    of its own."""

    def test_a_field_a_sender_wrote_is_removed_with_its_continuations(self):
        header_block = (
            b"From: sender@example.org\r\n"
            b"X-ZEKNOP-Signature: forged\r\n"
            b"\tand folded over a second line\r\n"
            b"Subject: Invoice\r\n"
            b"X-ZEKNOP-Verified: pass"
        )
        cleaned, removed = compose.strip_zeknop_fields(header_block)
        self.assertEqual(removed, 2)
        self.assertNotIn(b"forged", cleaned)
        self.assertNotIn(b"folded over a second line", cleaned)
        self.assertNotIn(b"pass", cleaned)
        self.assertIn(b"From: sender@example.org", cleaned)
        self.assertIn(b"Subject: Invoice", cleaned)

    def test_a_folded_field_of_the_senders_own_is_kept_whole(self):
        header_block = b"Subject: a subject\r\n folded over two lines\r\nTo: b@example.com"
        cleaned, removed = compose.strip_zeknop_fields(header_block)
        self.assertEqual(removed, 0)
        self.assertEqual(cleaned, header_block)

    def test_a_value_with_a_line_break_in_it_is_refused_rather_than_written(self):
        with self.assertRaises(ValueError):
            compose.header_lines(
                version="1.5",
                algorithm="ed25519",
                signature="abc\r\nBcc: somebody@example.com",
                content_hash="x",
                uuid="u",
                timestamp="t",
                relay_id="",
                level="",
                envelope_id=None,
                verify_url=None,
            )


if __name__ == "__main__":
    unittest.main()
