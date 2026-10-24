# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zeknod OÜ
"""The canonicalisation, as the reference implementation computes it.

Every module beside this one is a copy of the reference implementation and is
marked as such in its own header; see `NOTICE` at the root of this example for
what that means and for the list. They are here, and not rewritten, because the
two hashes of a message have exactly one right answer and an example that
computed a second one would be worse than no example at all.

What they do, in the order a verifier needs them:

* `mime_walk` reads the raw bytes of a message — the header block, the parts, the
  transfer encodings, the declared charsets — and answers which shape the message
  is (`canonical-content.md` §1.1), what its parts manifest is (§9) and which one
  displayed part the free text form is taken over (§2b.1);
* `single_byte` and `multi_byte` are the decoding tables a declared legacy charset
  is read with (§2 step 0). They are generated from the index data of the WHATWG
  Encoding Standard;
* `canonical` builds the canonical object of either shape, hashes it (§2), takes
  the visible block off a delivered part (`delivered-envelope.md` §6.1) and
  computes the hash over the free text form (§2b);
* `free_form` is that free text form: the algorithm of §2b, with the Unicode data
  it needs;
* `sig_alg` is the registry of `signature-input.md` §1 and §3 — which versions of
  the signature input exist and which algorithm names are in which state;
* `message_fields` reads the canonical `From`, the recipients and the text of a
  Shape A message off a parsed message (§3, §4, §1.1).

The `conformance` command of this example is what holds all of it to the vectors.
"""

from . import canonical, free_form, message_fields, mime_walk, sig_alg  # noqa: F401

__all__ = ["canonical", "free_form", "message_fields", "mime_walk", "sig_alg"]
