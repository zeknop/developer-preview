# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zeknod OÜ
"""Every vector file, every case, and the shape of the report.

    python3 -m unittest discover -s tests

This is the test that matters most in this directory: it is what says the copy of
the canonicalisation in this example answers what the reference implementation
answers, over every vector the package ships. A run that measured fewer cases than
it says would be worse than no run, so the counts are asserted by number and not
only "greater than zero".
"""

import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from zeknop_example import conformance  # noqa: E402

VECTORS = HERE.parents[2] / "vectors"

#: What each file is expected to ask, in the units CONFORMANCE.md §1 counts.
EXPECTED_COUNTS = {
    "vectors.json": 72,
    "free-form-vectors.json": 53,
    "charset-vectors.json": 54,
    "parts-manifest-vectors.json": 20,
    "signature-input-vectors.json": 10,
    "timestamp-vectors.json": 6,
    "delivered-envelope-vectors.json": 38,
    "differential/cases.json": 10575,
}


class Conformance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = conformance.run(VECTORS)
        cls.by_name = {result.name: result for result in cls.results}

    def test_every_vector_file_is_read(self):
        self.assertEqual(list(self.by_name), conformance.VECTOR_FILES)

    def test_every_comparison_matches(self):
        for result in self.results:
            with self.subTest(result.name):
                self.assertEqual(
                    result.mismatches,
                    [],
                    f"{result.name}: {result.compared - result.matched} mismatch(es)",
                )
                self.assertEqual(result.matched, result.compared)

    def test_the_number_of_comparisons_is_the_number_the_package_states(self):
        for name, count in EXPECTED_COUNTS.items():
            with self.subTest(name):
                self.assertEqual(self.by_name[name].compared, count)

    def test_the_differential_is_the_seed_and_the_case_count_it_says(self):
        note = self.by_name["differential/cases.json"].note
        self.assertIn("5329 cases", note)
        self.assertIn("seed 20260923", note)

    def test_the_report_carries_the_counts_the_digests_and_the_versions(self):
        text = conformance.report(self.results, VECTORS, "a test")
        self.assertIn("ZEKNOP conformance report", text)
        for name, count in EXPECTED_COUNTS.items():
            self.assertIn(f"{count}/{count}", text)
            self.assertIn(name, text)
        for result in self.results:
            self.assertIn(result.digest, text)
        self.assertIn("canonical-content.md 1.4", text)

    def test_the_report_is_the_shape_CONFORMANCE_md_fixes(self):
        """§1 of `CONFORMANCE.md` fixes the format so that two reports can be read
        side by side. Four header lines, the runtime inside the name of the
        implementation, the specification broken after `signature-input.md`, and
        the digests in the order of the counts above them — so a difference
        between two reports is a difference in the numbers.
        """
        lines = conformance.report(self.results, VECTORS, "a test (CPython 3.11.0)").split("\n")
        self.assertEqual(lines[0], "ZEKNOP conformance report")
        self.assertEqual(lines[1], "  implementation   a test (CPython 3.11.0)")
        self.assertTrue(lines[2].startswith("  date             "), lines[2])
        self.assertEqual(
            lines[3],
            "  specification    canonical-content.md 1.4, signature-input.md 1.4/1.5,",
        )
        self.assertEqual(lines[4], "                   delivered-envelope.md 1.4")
        self.assertEqual(lines[5], "")
        self.assertNotIn("  runtime ", "\n".join(lines))
        digests = [line for line in lines if line.startswith("    ") and "  " in line.strip()]
        self.assertEqual(
            [line.strip().split("  ")[1] for line in digests],
            conformance.VECTOR_FILES,
        )

    def test_the_two_fields_CONFORMANCE_md_calls_reproducible_are_compared(self):
        """`truncated_body_length` and `must_differ_from`: the first is the length
        of the body after §2 truncated it, the second says a pair of messages a
        reader could collapse into one must not hash to the same thing. Neither is
        in the counts twice — a vector is one comparison whatever it carries — and
        a run that quietly left them out would not be the "nothing is skipped
        silently" the module says it is.
        """
        vectors = json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))
        carried = [
            (vector["id"], name)
            for vector in vectors["vectors"]
            for name in ("truncated_body_length", "must_differ_from")
            if vector["expected"].get(name) is not None
        ]
        self.assertEqual(
            carried,
            [
                ("e2e-003-body-truncation", "truncated_body_length"),
                ("parts-002b-html-joined", "must_differ_from"),
                ("parts-005-order-swap", "must_differ_from"),
            ],
        )
        # That the run MATCHES them is the test above, which found no mismatch
        # anywhere. That it ASKS them at all is this: each is given a value that
        # cannot be right, and a comparison that is made says so. `must_differ_from`
        # pointing a vector at itself is the "must not" of the field.
        for vector in vectors["vectors"]:
            if vector["expected"].get("truncated_body_length") is not None:
                vector["expected"]["truncated_body_length"] = 1
            if vector["expected"].get("must_differ_from") is not None:
                vector["expected"]["must_differ_from"] = vector["id"]
        probe = conformance.FileResult(name="probe")
        conformance._canonical_content(vectors, probe)
        self.assertEqual(
            sorted({name for _case, name, _mine, _want in probe.mismatches}),
            ["must_differ_from", "truncated_body_length"],
        )
        # And the counts do not move: a vector is one comparison, whatever it carries.
        self.assertEqual(probe.compared, EXPECTED_COUNTS["vectors.json"])

    def test_a_vector_file_that_is_not_there_stops_the_run(self):
        with self.assertRaises(FileNotFoundError):
            conformance.run(HERE / "nowhere")


class TimestampRule(unittest.TestCase):
    """§8, at the anchor the vectors fix, including the two cases they do not hold.

    The vectors cover one context at a time; these two are the corners where the
    two rules meet, and an implementation that reads §8 as "age first" gets them
    wrong without any vector noticing.
    """

    NOW = "2026-04-20T12:00:00.000Z"

    def test_the_future_guard_comes_before_the_outbound_window(self):
        self.assertEqual(
            conformance.timestamp_decision("2026-04-20T12:00:31.000Z", self.NOW, "outbound"),
            ("reject", "future_skew_exceeded"),
        )

    def test_inbound_has_no_maximum_age(self):
        self.assertEqual(
            conformance.timestamp_decision("2019-01-01T00:00:00.000Z", self.NOW, "inbound"),
            ("accept", "permanent_verifiability"),
        )


if __name__ == "__main__":
    unittest.main()
