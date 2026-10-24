# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zeknod OÜ
"""Run this implementation over every vector file and report the result.

The report is the format `../../vectors/CONFORMANCE.md` §1 fixes, so that the
result of an implementation nobody here has seen can be put beside the result of
this one and read without a translation step. The counts are `matched / compared`
per file; a file with one mismatch is reported as a mismatch and not rounded
away.

There is no certification behind this. Nobody grants a mark, a badge or a licence
for a matching report. The report is evidence about bytes.

What is compared, and what is not, said here rather than left to be inferred:

* every file is compared on the values `CONFORMANCE.md` §2 names as the output of
  that file — for `vectors.json` the shape and the content hash of every vector,
  the canonical JSON string wherever the file stores one, the parts manifest and
  the truncated body length wherever a vector carries them, and
  `must_differ_from` as a comparison between two hashes of this run's own;
* **one comparison is skipped**, with its reason printed beside the count: the
  canonical JSON STRING of the one vector whose input is a body over the maximum
  size, which the file does not store. Its hash is compared. The validator
  shipped with the vectors skips that vector for the same reason;
* **two kinds of field are not compared, by the file's own instruction.**
  `warning_logged` is about one of our readers writing a line in a log and not
  about any bytes; `CONFORMANCE.md` §2 says an implementation is not held to it
  and to leave it out of the counts, or the totals would not be comparable. The
  intermediate fields `canonical_body`, `canonical_subject`, `canonical_from` and
  `canonical_to` are there to localise a mismatch when the hash differs (§2),
  and the hash and the canonical JSON string they are intermediate to are both
  compared here.

Nothing else is left out, and nothing is skipped without printing why.
"""

import base64
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import envelope, message, signature_input, vector_message
from .canonicalization import canonical, free_form, mime_walk

#: The files the run reads, in the order they are reported.
VECTOR_FILES = [
    "vectors.json",
    "free-form-vectors.json",
    "charset-vectors.json",
    "parts-manifest-vectors.json",
    "signature-input-vectors.json",
    "timestamp-vectors.json",
    "delivered-envelope-vectors.json",
    "differential/cases.json",
]

#: §8 — the moment the timestamp vectors are evaluated against. The file fixes it,
#: and it is injected as "now": using the system clock would make the vectors drift
#: with the day they are run.
_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%f%z"


@dataclass
class FileResult:
    """What one vector file was asked and what it answered.

    `compared` counts the units `CONFORMANCE.md` §1 counts, which are not the same
    unit in every file: a vector file is counted per VECTOR — every field of a
    vector has to match for that vector to be a match — and `differential/cases.json`
    is counted per FORM, which is what makes its total 10 575 over 5 329 cases.
    The two diagnostics the differential carries are compared and reported, and
    are not in the totals, which the file's own notes ask for.
    """

    name: str
    compared: int = 0
    matched: int = 0
    note: str = ""
    digest: str = ""
    diagnostics_compared: int = 0
    diagnostics_matched: int = 0
    mismatches: list = field(default_factory=list)

    def case(self, case_id: str, fields: dict) -> None:
        """One vector: a match when every field of it matches."""
        self.compared += 1
        wrong = [(name, mine, want) for name, (mine, want) in fields.items() if mine != want]
        if not wrong:
            self.matched += 1
            return
        for name, mine, want in wrong:
            self.mismatches.append((case_id, name, mine, want))

    def form(self, case_id: str, name: str, mine, want) -> None:
        """One form of one case: the unit the differential is counted in."""
        self.compared += 1
        if mine == want:
            self.matched += 1
        else:
            self.mismatches.append((case_id, name, mine, want))

    def diagnostic(self, case_id: str, name: str, mine, want) -> None:
        """A field that localises a mismatch and is not part of the totals."""
        self.diagnostics_compared += 1
        if mine == want:
            self.diagnostics_matched += 1
        else:
            self.mismatches.append((case_id, f"{name} (diagnostic)", mine, want))


def _sha(text: str) -> str:
    """The hash every form in these files uses: SHA-256 of the text as UTF-8, base64."""
    return base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


def _read(path: Path):
    data = path.read_bytes()
    return json.loads(data), hashlib.sha256(data).hexdigest()


# ── the files, one function each ─────────────────────────────────────────────


def _canonical_content(data, result: FileResult) -> None:
    """`vectors.json` — the canonical object and its hash, from the raw bytes.

    Each vector is rendered to the bytes of a message and those bytes are walked,
    which is the path a verifier is on. The shape is compared as well: it is chosen
    from the structure of the message and a reader that chose it from a header
    would agree on the hash of this vector and disagree on the next one.
    """
    mine: dict = {}
    for vector in data["vectors"]:
        case = vector["id"]
        expected = vector["expected"]
        try:
            recomputed = message.recompute(vector_message.render(vector))
        except Exception as exc:  # noqa: BLE001 — a reader that cannot read it says so
            result.case(case, {"read": (f"error:{type(exc).__name__}", "the message")})
            continue
        mine[case] = recomputed.content_hash
        fields = {
            "shape": (recomputed.shape, expected.get("shape", "A")),
            "content_hash": (recomputed.content_hash, expected["content_hash"]),
        }
        if expected.get("canonical_json") is not None:
            fields["canonical_json"] = (recomputed.canonical_json, expected["canonical_json"])
        if expected.get("parts") is not None:
            fields["parts"] = (recomputed.canonical_object.get("parts"), expected["parts"])
        if expected.get("truncated_body_length") is not None:
            # §2: a body over the maximum is truncated to it before anything is
            # hashed, and the length after that is in the object this run built.
            fields["truncated_body_length"] = (
                len(recomputed.canonical_object.get("body") or ""),
                expected["truncated_body_length"],
            )
        if expected.get("must_differ_from") is not None:
            fields["must_differ_from"] = (
                _own_hash(mine, expected["must_differ_from"], recomputed.content_hash),
                "a hash of its own",
            )
        result.case(case, fields)
    result.note = (
        "e2e-003 on the hash: the file stores no canonical JSON for a body over the maximum"
    )


def _own_hash(mine: dict, other: str, hash_now: str) -> str:
    """`must_differ_from`: whether this vector hashed to something of its own.

    The pair is two messages a reader could collapse into one — a two-part tree
    joined into one part, two parts in the other order — and the file says they
    must not have the same hash. The comparison is between two hashes THIS run
    made: comparing against the stored hash of the other vector would be the
    content_hash comparison again, which says nothing about the pair.
    """
    if other not in mine:
        return f"{other} is not above this vector in the file, so nothing was compared"
    if mine[other] == hash_now:
        return f"the same hash as {other}"
    return "a hash of its own"


def _free_form(data, result: FileResult) -> None:
    """`free-form-vectors.json` — the free text form of §2b, and its hash."""
    for vector in data["vectors"]:
        text = free_form.free_form_text(vector["input"], vector["kind"] == "html")
        result.case(
            vector["id"],
            {"text": (text, vector["text"]), "hash": (_sha(text), vector["hash"])},
        )


def _charset(data, result: FileResult) -> None:
    """`charset-vectors.json` — reading declared bytes (§2 step 0) and encoded words (§5).

    Two arrays and two readings: the bytes of a text part through the decoding
    table its label names, and a Subject field through the encoded-word rule. The
    expected values are typed from the WHATWG Encoding Standard, so a disagreement
    here is about reading bytes, before any hashing is involved.
    """
    for vector in data["text_parts"]:
        text = mime_walk.decode_text(bytes.fromhex(vector["bytes_hex"]), vector["charset"])
        result.case(
            vector["id"],
            {
                "text": (text, vector["text"]),
                "text_sha256_base64": (_sha(text), vector["text_sha256_base64"]),
            },
        )
    for vector in data["subjects"]:
        text = mime_walk.decode_encoded_words(vector["raw"])
        result.case(
            vector["id"],
            {
                "text": (text, vector["text"]),
                "text_sha256_base64": (_sha(text), vector["text_sha256_base64"]),
            },
        )
    result.note = f"{len(data['text_parts'])} text parts, {len(data['subjects'])} subjects"


def _parts_manifest(data, result: FileResult) -> None:
    """`parts-manifest-vectors.json` — the boundary parameter (§9.2a) and the walk (§9.1).

    `boundary` says whether the field was read the same way; `manifest` says
    whether that changed the message that was seen.
    """
    for vector in data["vectors"]:
        raw = bytes.fromhex(vector["message_hex"])
        try:
            leaves = [
                entry["k"] for entry in mime_walk.extract_parts_manifest(mime_walk.parse_part(raw))
            ]
        except Exception as exc:  # noqa: BLE001
            leaves = f"error:{type(exc).__name__}"
        result.case(
            vector["id"],
            {
                "boundary": (mime_walk.usable_boundary(vector["content_type"]), vector["boundary"]),
                "manifest": (leaves, vector["manifest"]),
            },
        )


def _signature_input(data, result: FileResult) -> None:
    """`signature-input-vectors.json` — the bytes a signature is made over.

    The file asks about the ASSEMBLY of §2, not about the registry of §3: two of
    its vectors name a version and an algorithm nothing signs with, to show that
    the form does not change when the registry grows. So the length-prefixed input
    is built for every vector but `legacy`, whatever the names are, and `legacy` is
    the strict hash on its own (§4).
    """
    for vector in data["vectors"]:
        strict = signature_input.decode_hash(vector["strict_hash_b64"])
        if vector["version"] == "legacy":
            mine = strict
        else:
            mine = signature_input.build(
                vector["version"],
                vector["algorithm"],
                strict,
                signature_input.decode_hash(vector["free_hash_b64"]),
            )
        result.case(
            vector["id"],
            {"signature_input_hex": (mine.hex(), vector["signature_input_hex"])},
        )


def timestamp_decision(timestamp: str, now: str, context: str):
    """(decision, reason tag) for one timestamp, as `canonical-content.md` §8 decides it.

    The future guard comes first and applies in both contexts: a timestamp more
    than 30 seconds ahead of the reader's clock is rejected, because larger skew
    than that is a misconfigured system and not a message. Inbound verification
    then has NO maximum age — integrity rests on the hash over the content, on the
    binding of the identity and on revocation, not on the age of the signature —
    while an outbound mail server signs fresh mail and refuses a message that has
    been in a queue for more than 24 hours.

    `now` is injected rather than read from the clock, which is what makes the
    vectors reproducible on any day.
    """
    at = datetime.strptime(timestamp, _TIMESTAMP_FORMAT)
    reference = datetime.strptime(now, _TIMESTAMP_FORMAT)
    ahead = (at - reference).total_seconds()
    if ahead > 30:
        return "reject", "future_skew_exceeded"
    if context == "outbound":
        if -ahead > 24 * 60 * 60:
            return "reject", "outbound_stale"
        return "accept", "within_outbound_window"
    if ahead > 0:
        return "accept", "within_clock_skew"
    return "accept", "permanent_verifiability"


def _timestamp(data, result: FileResult) -> None:
    """`timestamp-vectors.json` — the decision of §8 at the file's own anchor."""
    now = data["reference_now"]
    for vector in data["vectors"]:
        decision, tag = timestamp_decision(vector["timestamp"], now, vector["context"])
        result.case(
            vector["id"],
            {
                "expected_decision": (decision, vector["expected_decision"]),
                "expected_reason_tag": (tag, vector["expected_reason_tag"]),
            },
        )
    result.note = f"now injected as {now}"


def _delivered_envelope(data, result: FileResult) -> None:
    """`delivered-envelope-vectors.json` — writing the block and taking it off.

    Four arrays, four questions, four counts. The two `build` arrays measure this
    example's own signer side; the two `strip` arrays measure the removal in the
    copy of the reference implementation. A block quoted inside a reply is content
    and stays — that is a rule and not an edge case, and the `strip` vectors pin it.
    """
    for vector in data["build"]:
        data_in = vector["input"]
        mine = envelope.build_plain(
            vector["kind"],
            data_in["inner"],
            data_in.get("envelope_id", ""),
            data_in.get("verify_url", ""),
            data_in["eol"],
        )
        result.case(vector["id"], {"text": (mine, vector["expected"]["text"])})
    for vector in data["build_html"]:
        data_in = vector["input"]
        mine = envelope.build_html(
            vector["kind"],
            data_in["inner"],
            data_in.get("envelope_id", ""),
            data_in.get("verify_url", ""),
            data_in["eol"],
        )
        result.case(vector["id"], {"text": (mine, vector["expected"]["text"])})
    for vector in data["strip"]:
        result.case(
            vector["id"],
            {
                "expected": (
                    canonical.strip_zeknop_envelope(vector["delivered"]),
                    vector["expected"],
                ),
                "expected_kind": (
                    canonical.delivered_envelope_kind(vector["delivered"]),
                    vector["expected_kind"],
                ),
            },
        )
    for vector in data["strip_html"]:
        text, kind = canonical.strip_html_envelope(vector["delivered"])
        result.case(
            vector["id"],
            {
                "expected": (text, vector["expected"]),
                "expected_kind": (kind, vector["expected_kind"]),
            },
        )
    result.note = (
        f"{len(data['build'])} build, {len(data['build_html'])} build_html, "
        f"{len(data['strip'])} strip, {len(data['strip_html'])} strip_html"
    )


def _differential(data, result: FileResult) -> None:
    """`differential/cases.json` — the same questions over seeded inputs.

    Only the forms `expected` carries for a case are compared: a field it does not
    carry is not asked. `decoded_text_sha256_b64` is a diagnostic — it says whether
    a disagreement is about reading the bytes or about hashing the text — and is
    not counted, exactly as the file's own note says.
    """
    diagnostics = ("decoded_text_sha256_b64", "unwrapped_text")
    counted = {form: 0 for form in data["forms"]}
    for case in data["cases"]:
        kind = case["kind"]
        expected = case["expected"]
        if kind == "manifest":
            raw = bytes.fromhex(case["hex"])
            try:
                leaves = mime_walk.extract_parts_manifest(mime_walk.parse_part(raw))
                mine = {"manifest": "|".join(entry["k"] for entry in leaves)}
            except Exception as exc:  # noqa: BLE001 — a reader that cannot read it says so
                mine = {"manifest": f"error:{type(exc).__name__}"}
        else:
            if kind == "bytes":
                text = mime_walk.decode_text(bytes.fromhex(case["hex"]), case["label"] or None)
            elif kind == "subject":
                text = mime_walk.decode_encoded_words(case["value"])
            elif kind == "html-envelope":
                text = canonical.strip_html_envelope(case["text"])[0]
            else:
                text = case["text"]
            is_html = kind in ("html", "html-envelope")
            mine = {"free": _sha(free_form.free_form_text(text, is_html))}
            if not is_html:
                mine["strict"] = _sha(canonical.normalize_body(text))
            if kind == "html-envelope":
                mine["html"] = _sha(text)
                mine["unwrapped_text"] = text
            if kind in ("bytes", "subject"):
                try:
                    mine["decoded_text_sha256_b64"] = _sha(text)
                except UnicodeEncodeError:
                    # A reading that cannot be written back as UTF-8 has no such
                    # hash, and the file carries null there; the two forms above
                    # are the comparison, over the same text.
                    mine["decoded_text_sha256_b64"] = None
        for form, want in expected.items():
            if form not in mine or want is None:
                # Not asked of this kind, or a diagnostic the file leaves null.
                continue
            if form in diagnostics:
                result.diagnostic(case["id"], form, mine[form], want)
                continue
            counted[form] = counted.get(form, 0) + 1
            result.form(case["id"], form, mine[form], want)
    shape = ", ".join(f"{n} {form}" for form, n in counted.items() if n)
    result.note = f"{data['case_count']} cases, seed {data['seed']}; {shape}"


RUNNERS = {
    "vectors.json": _canonical_content,
    "free-form-vectors.json": _free_form,
    "charset-vectors.json": _charset,
    "parts-manifest-vectors.json": _parts_manifest,
    "signature-input-vectors.json": _signature_input,
    "timestamp-vectors.json": _timestamp,
    "delivered-envelope-vectors.json": _delivered_envelope,
    "differential/cases.json": _differential,
}


# ── the report ───────────────────────────────────────────────────────────────


def _specification_versions(vectors_dir: Path) -> list:
    """The version each specification document declares, read from the documents.

    Printed in the report so that a report over one version of the specification
    cannot be read as a report over another. When the documents are not beside the
    vectors, the line says so rather than naming a version nobody read.

    Returned as the lines of the report, because `CONFORMANCE.md` §1 breaks this
    field after `signature-input.md` and the format is the point of the file.
    """
    spec_dir = vectors_dir.parent / "spec"
    found = []
    for name in ("canonical-content.md", "signature-input.md", "delivered-envelope.md"):
        path = spec_dir / name
        if not path.is_file():
            continue
        head = path.read_text(encoding="utf-8").split("\n---", 1)[0]
        match = re.search(r"Version ([0-9][0-9.]*(?: and [0-9][0-9.]*)*)", head)
        if match:
            found.append(f"{name} {match.group(1).replace(' and ', '/')}")
    if not found:
        return ["not read: the documents are not beside the vectors"]
    if len(found) < 3:
        return [", ".join(found)]
    return [f"{found[0]}, {found[1]},", found[2]]


def run(vectors_dir: Path) -> list:
    """Every vector file, in order. Raises when one of them is not there: a run
    that measures less than it says it measured is worse than a run that stops.
    """
    results = []
    for name in VECTOR_FILES:
        path = vectors_dir / name
        if not path.is_file():
            raise FileNotFoundError(f"no vector file at {path}")
        data, digest = _read(path)
        result = FileResult(name=name, digest=digest)
        RUNNERS[name](data, result)
        results.append(result)
    return results


def report(results: list, vectors_dir: Path, implementation: str) -> str:
    """The report of `CONFORMANCE.md` §1, in that shape and no other.

    Four header lines, not five: the runtime belongs inside the name of the
    implementation, which is how the example in §1 writes it and how the sibling
    client in this package writes it. The digests are printed in the order the
    files were run, which is the order of the counts above them, so the two lists
    can be read down the page together.
    """
    width = max(len(result.name) for result in results) + 2
    specification = _specification_versions(vectors_dir)
    lines = [
        "ZEKNOP conformance report",
        f"  implementation   {implementation}",
        f"  date             {datetime.now(timezone.utc).date().isoformat()}",
        f"  specification    {specification[0]}",
    ]
    lines += [f"                   {more}" for more in specification[1:]]
    lines.append("")
    for result in results:
        counts = f"{result.matched}/{result.compared}"
        note = f"  ({result.note})" if result.note else ""
        lines.append(f"  {result.name:<{width}}{counts:>12}{note}")
    lines += ["", "  vector files as read, sha256:"]
    for result in results:
        lines.append(f"    {result.digest}  {result.name}")

    mismatches = [(result, row) for result in results for row in result.mismatches]
    compared = sum(result.compared for result in results)
    matched = sum(result.matched for result in results)
    diagnosed = sum(result.diagnostics_compared for result in results)
    diagnoses_matched = sum(result.diagnostics_matched for result in results)
    lines += ["", f"  {matched}/{compared} compared and matched"]
    if diagnosed:
        lines.append(
            f"  {diagnoses_matched}/{diagnosed} diagnostic fields also matched "
            f"(not part of the counts above, as the files ask)"
        )
    if mismatches:
        lines.append("")
        for result, (case_id, form, mine, want) in mismatches[:50]:
            lines.append(f"  x {result.name} {case_id} {form}")
            lines.append(f"      got      {mine!r}")
            lines.append(f"      expected {want!r}")
        if len(mismatches) > 50:
            lines.append(f"  ... and {len(mismatches) - 50} more")
    return "\n".join(lines) + "\n"
