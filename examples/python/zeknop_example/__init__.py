# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zeknod OÜ
"""An example ZEKNOP client: check a signature, sign through a relay, report agreement.

This is an example, not a library. It exists to be read beside the specification
in `../../spec/` and to be run against the vectors in `../../vectors/`. It makes
no claim about the security, the performance or the privacy of anything, and it
comes with no warranty — see `LICENSE` and `README.md`.

Standard library only, Python 3.11 or newer. Three entry points:

    python3 -m zeknop_example verify <file.eml> [--relay URL] [--offline]
    python3 -m zeknop_example sign <file.eml> --uuid U --api-key K --relay URL --portal URL
    python3 -m zeknop_example conformance [--vectors DIR]
"""

__all__ = ["canonicalization", "conformance", "envelope", "message", "relay", "signature_input"]
