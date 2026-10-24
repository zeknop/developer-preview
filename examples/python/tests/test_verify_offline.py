# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zeknod OÜ
"""`verify --offline` over messages built here, including the ones it must refuse.

Offline is the half of verification that needs nobody: it says whether the hash in
the message is the hash of the message. The tests below are as much about what it
must NOT say — a refusal of the question is not a verdict, and a reader that has
read nothing says so.
"""

import base64
import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from zeknop_example import cli, envelope, message  # noqa: E402
from zeknop_example.canonicalization import sig_alg  # noqa: E402

UUID = "11111111-2222-3333-4444-555555555555"
TIMESTAMP = "2026-04-20T12:00:00.000Z"
BODY = "Amount due: 100 EUR\r\nPlease pay by Friday.\r\n"


def plain_message(body: str, **changes) -> bytes:
    """A delivered Shape A message whose fields are the hashes of its own bytes.

    Built the way a signer builds one: the hashes are computed over the message
    WITHOUT the visible block, the block is written afterwards, and the fields name
    what was hashed.
    """
    head = (
        "From: sender@example.org\r\n"
        "To: recipient@example.com\r\n"
        "Subject: Invoice 2026-09\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
    )
    unsigned = (head + f"X-ZEKNOP-Timestamp: {TIMESTAMP}\r\n" + "\r\n" + body).encode("utf-8")
    recomputed = message.recompute(unsigned, timestamp=TIMESTAMP, algorithm="ed25519")
    fields = {
        "X-ZEKNOP-Version": sig_alg.SIGNATURE_INPUT_VERSION,
        "X-ZEKNOP-Sig-Alg": "ed25519",
        "X-ZEKNOP-Signature": base64.b64encode(
            b"not a signature, 64 bytes of nothing" * 2
        ).decode(),
        "X-ZEKNOP-Hash": recomputed.content_hash,
        "X-ZEKNOP-UUID": UUID,
        "X-ZEKNOP-Timestamp": TIMESTAMP,
        "X-ZEKNOP-Envelope-ID": "Ab12Cd34",
    }
    fields.update(changes)
    wrapped = envelope.build_plain(
        "positive", body, "Ab12Cd34", "https://verify.example.org/v1/abc", "\r\n"
    )
    written = "".join(f"{name}: {value}\r\n" for name, value in fields.items() if value is not None)
    return (head + written + "\r\n" + wrapped).encode("utf-8")


def run(*argv) -> tuple:
    out = io.StringIO()
    with redirect_stdout(out):
        code = cli.main(list(argv))
    return code, out.getvalue()


class Offline(unittest.TestCase):
    def setUp(self):
        # A directory of the system's, not one inside the example: the example may be read from
        # a read-only copy, and a test leaves nothing behind in the package either way.
        self._workdir = tempfile.TemporaryDirectory(prefix="zeknop-example-test-")
        self.tmp = Path(self._workdir.name)

    def tearDown(self):
        self._workdir.cleanup()

    def write(self, name: str, raw: bytes) -> Path:
        path = self.tmp / name
        path.write_bytes(raw)
        return path

    def test_a_message_nobody_touched_recomputes_to_the_hash_it_carries(self):
        path = self.write("good.eml", plain_message(BODY))
        code, text = run("verify", str(path), "--offline")
        self.assertEqual(code, cli.OK, text)
        self.assertIn("the content hash of the bytes is the hash in the message", text)
        # And it is explicit about the half it did not answer.
        self.assertIn("is a question for a relay", text)

    def test_the_visible_block_is_not_part_of_the_hash(self):
        """The block is written after signing, so taking it off is what a verifier
        does first. A reader that hashed it would call this very message changed."""
        raw = plain_message(BODY)
        self.assertIn(b"======= ZEKNOP =======", raw)
        recomputed = message.recompute(raw)
        self.assertEqual(recomputed.envelope_kinds, ["positive"])
        self.assertEqual(recomputed.content_hash, message.claimed(message.parse(raw)).content_hash)

    def test_one_character_changed_in_the_body_is_a_different_hash(self):
        raw = plain_message(BODY).replace(b"100 EUR", b"900 EUR")
        path = self.write("tampered.eml", raw)
        code, text = run("verify", str(path), "--offline")
        self.assertEqual(code, cli.NEGATIVE, text)
        self.assertIn("Something changed after signing", text)
        self.assertIn("No relay was asked", text)

    def test_a_subject_changed_after_signing_is_a_different_hash(self):
        raw = plain_message(BODY).replace(b"Subject: Invoice 2026-09", b"Subject: Invoice 2026-10")
        path = self.write("subject.eml", raw)
        code, _text = run("verify", str(path), "--offline")
        self.assertEqual(code, cli.NEGATIVE)

    def test_the_block_saying_the_message_could_not_be_signed_is_never_verified(self):
        body = envelope.build_plain("not-verified", BODY, eol="\r\n")
        raw = plain_message(BODY).split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n" + body.encode("utf-8")
        path = self.write("notice.eml", raw)
        code, text = run("verify", str(path), "--offline")
        self.assertEqual(code, cli.NEGATIVE, text)
        self.assertIn("could not be signed", text)

    def test_fields_that_are_not_the_right_shape_are_not_a_verdict(self):
        raw = plain_message(BODY, **{"X-ZEKNOP-UUID": "not-a-uuid"})
        path = self.write("malformed.eml", raw)
        code, text = run("verify", str(path), "--offline")
        self.assertEqual(code, cli.UNANSWERED, text)
        self.assertIn("not a statement about the message", text)

    def test_a_version_this_reader_cannot_build_is_not_a_verdict_either(self):
        raw = plain_message(BODY, **{"X-ZEKNOP-Version": "9.9"})
        path = self.write("future.eml", raw)
        code, text = run("verify", str(path), "--offline")
        self.assertEqual(code, cli.UNANSWERED, text)
        self.assertIn("Could not check", text)

    def test_a_message_with_no_zeknop_fields_at_all_is_not_a_verdict(self):
        raw = b"From: a@example.org\r\nTo: b@example.com\r\nSubject: hi\r\n\r\nplain mail\r\n"
        path = self.write("unsigned.eml", raw)
        code, text = run("verify", str(path), "--offline")
        self.assertEqual(code, cli.UNANSWERED, text)
        self.assertIn("nothing to check", text)

    def test_a_result_field_a_sender_wrote_is_removed_before_anything_is_read(self):
        raw = plain_message(BODY).replace(
            b"From: sender@example.org",
            b"X-ZEKNOP-Content-Verified: pass\r\nFrom: sender@example.org",
        )
        parsed = message.parse(raw)
        self.assertIsNone(parsed.get("X-ZEKNOP-Content-Verified"))

    def test_the_signature_input_is_the_length_prefixed_form_for_this_version(self):
        raw = plain_message(BODY)
        recomputed = message.recompute(raw)
        data = recomputed.signature_input()
        self.assertTrue(data.startswith(b"ZEKNOP-SIG"))
        self.assertEqual(len(data), 10 + 1 + 3 + 1 + 7 + 1 + 32 + 1 + 32)


if __name__ == "__main__":
    unittest.main()
