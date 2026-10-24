<!--
Licence: Creative Commons Attribution 4.0 International (CC BY 4.0)
          https://creativecommons.org/licenses/by/4.0/
Publisher: Zeknod OÜ
Part of: the ZEKNOP Signed Email specification, Developer Preview
Date: 2026-10-24
-->

# How to show your implementation agrees

**Developer Preview — the protocol and the API may change; nothing on this page is a
security guarantee.**

This file says, per vector file, what the input is, what the output is, and what to
compare; and it fixes one report format, so that the result of an implementation nobody
here has seen can be put beside the result of one of ours and read without a translation
step.

There is no certification behind this. Nobody is granting a mark, a badge or a licence
for a matching report. The report is evidence about bytes, and what anyone does with it
is their own decision.

## 1. The report format

One block, in this shape. The counts are `matched / compared`, per file, and a file with
one mismatch is reported as a mismatch, not rounded away.

```
ZEKNOP conformance report
  implementation   my-verifier 0.3.0 (Rust 1.83)
  date             2026-11-04
  specification    canonical-content.md 1.4, signature-input.md 1.4/1.5,
                   delivered-envelope.md 1.4

  vectors.json                      73/73   (e2e-003 and e2e-004 on the hash: no canonical JSON stored)
  free-form-vectors.json            53/53
  charset-vectors.json              54/54   (40 text parts, 14 subjects)
  parts-manifest-vectors.json       27/27
  signature-input-vectors.json      10/10
  timestamp-vectors.json             6/6
  delivered-envelope-vectors.json   38/38   (4 build, 5 build_html, 21 strip, 8 strip_html)
  differential/cases.json       10587/10587 (5341 cases, seed 20260923)

  vector files as read, sha256:
    4636b194b9f2d1980fba75dcbf5242d4c45fa0974b402aa788724354fd9a88e5  charset-vectors.json
    906a1723cdde6cd3bb169182870d58d44adad98b932d708cd443b4e6a19b35a9  delivered-envelope-vectors.json
    6c0f9af9c08c2c0f1e0984e2d0ff41015efb6217849c41ece6c3b5fdfc1cee49  free-form-vectors.json
    d961eda92fca6ca4587cb7b6c1042baaf94ad4197e80eca5befdbda5415e62b8  parts-manifest-vectors.json
    35f968e0011122e9e7a39a3661d7fe91b794248866c5f6e60592ee77b48734c2  signature-input-vectors.json
    025e4f3406d862cf02cd68c7007efefd64e85edfc8a69d5bd67d7fea28d73abf  timestamp-vectors.json
    7da6baa7702f2356ca34197be3614ce3f050becbc7e7ba60b49c1e30113d4e5d  vectors.json
    3cee4d2dce18239ebf1de0b270835fb0865405a17c58aee58bcfa2afd6115c20  differential/cases.json
```

The digests above are the files as published with this preview. Print the digests of the
files **you actually read**, not these: a report over edited vectors is a report about
nothing, and the two lists differing is the fastest way to see it.

```sh
cd vectors && sha256sum *.json differential/cases.json
```

A mismatch is reported with the case id, the field, your value and the expected value —
nothing else is needed to reproduce it.

## 2. Per file: input, output, what to compare

### `vectors.json` — the canonical content object and its hash

- **Input** `input`: `from`, `to`, `subject`, `timestamp`, and then whichever of `body`,
  `mime_tree`, `raw_headers`, `body_bytes_hex` + `body_encoding`, `subject_raw_mime`,
  `cc`, `to_header`, `cc_header`, `raw_to_header`, `body_description`, `body_length`,
  `body_parts` the vector carries. The header list at the top of the file fixes the field
  order, the JSON separators (`,` and `:`), the encoding and the maximum body size.
- **Which field is the input, where a vector carries two.** Several vectors state the same
  message twice, once as bytes or as the wire form and once as something already read. The
  **unread** one is the input, every time:

  | the input | the other field | what the other field is |
  |---|---|---|
  | `mime_tree.payload_base64` | `mime_tree.text` | a reading of those bytes, written down to localise a difference |
  | `body_bytes_hex` + `body_encoding` | `body` | the same, for the two UTF-16 vectors (`body-012`, `body-013`) |
  | `raw_headers` | `to`, `cc`, `subject`, `from` | the fields as a parser should end up with them |

  Take the read field as an input and you can pass these vectors without implementing
  §2 step 0, §5 or the header parsing at all — which is the one thing they are for. The
  read field is also not a stage you can feed a pipeline from: in `shape-a-002` the `text`
  already has its line ends normalised (§2 step 2), in `shape-a-010` it does not.
- **`mime_tree`**, per node: `content_type`; `charset` and `transfer_encoding` (the labels
  of §2 step 0 and of the transfer encoding to undo first); `payload_base64` (the part's
  bytes) or `content_base64` for a non-text leaf; `text` (see above); `children` (an
  ordered list of nodes, which makes the node a container); `disposition`, `filename` and
  `content_id` (what `../spec/canonical-content.md` §9.3 classifies a leaf by and what §9.4
  names it by); and `raw`, the body of a `message/rfc822` leaf as one string, in the three
  vectors that carry such a leaf (`parts-003`, `parts-004`, `parts-005`). A node with
  `children` is read as a container, one without is a leaf.
- **Output** `expected.canonical_json`: the canonical JSON as one string.
  `expected.content_hash`: SHA-256 of those bytes as UTF-8, base64. Some vectors also
  carry `canonical_body`, `canonical_subject`, `canonical_from`, `canonical_to`, `parts`
  or `shape`, which are the intermediate results; two carry `must_differ_from`; two carry
  `truncated_body_length`, one of them also `truncated_body_last_code_point`; and two
  carry `warning_logged`.
- **Compare** your canonical JSON string against `expected.canonical_json` byte for byte,
  and your hash against `expected.content_hash`. The intermediate fields are there to
  localise a mismatch; compare them when the hash differs.
- **`shape-a-013`, `shape-a-014` and `parts-011` are the trim vectors.** §2 step 4 of
  `../spec/canonical-content.md` writes the trim set out — what `String.prototype.trim()`
  removes, and nothing else — and Python's bare `str.strip()` is not that set (it removes
  U+001C–U+001F and U+0085 as well, and leaves U+FEFF). Swap the
  set for `str.strip()` in the Python example client and exactly these three of the 73
  come out different, along with 13 comparisons of `differential/cases.json`. If one of
  the three is your only mismatch, that is where to look.
- **`warning_logged`** (`body-012`, `body-013`, both a UTF-16 byte order mark) is about
  our own readers saying something in a log, not about the bytes. Your implementation is
  not held to it. Leave it out of your counts, or the totals here and yours will not be
  the same number.
- **`e2e-003-body-truncation` and `e2e-004-body-cut-code-points` are the two vectors with
  no `body`**, because their bodies are over the 1 048 576-code-point maximum and a
  megabyte does not belong in a vector file. `e2e-003` gives its body as a length:
  `body_length` characters `A` — 1 049 000 of them, which `body_description` also says in
  words. `e2e-004` gives it as a RECIPE, `input.body_parts`: pieces of the form
  `{"literal": "s"}` and `{"repeat": "s", "count": n}`, joined in order — 1 048 575 `A`,
  then U+1F642, then 1 000 `B`. A length could not say WHICH code point sits in front of
  the cut, and that is the whole question `e2e-004` asks: the cut counts code points, so
  the hashed body ends in U+1F642 and not in half of its surrogate pair. (The vector's
  `note` carries the hash a cut by UTF-16 code units gives, so a reader that gets that
  value knows exactly what is wrong.) Build each body from what the vector gives, and the
  `content_hash` and the `truncated_body_length` are both reproducible and both worth
  comparing — the length in CODE POINTS, which is the unit §2 counts in. Only the
  **string** comparison has to be skipped for both: the file does not store the megabyte
  of canonical JSON the hash was taken over. Report them as compared on the hash.
  (`validate_vectors.py` recomputes hashes out of the stored canonical JSON rather than
  out of the input, so it reports `e2e-003` as skipped for that same reason; `e2e-004` it
  builds from the recipe, applies the one §2 rule the vector is about, and compares.)

### `free-form-vectors.json` — the free text form (§2b)

- **Input** `input`, with `kind` saying whether it is `text` or `html`. It is the text of a
  part **after** the delivered envelope has been removed (§2b.5); the removal itself is
  not measured here, because no input in this file starts with a block to remove. What
  pins the removal is the `strip` and `strip_html` cases of
  `delivered-envelope-vectors.json` and the `html-envelope` cases of the differential.
  `ff-080` and `ff-081` pin the other half of the same rule: a block quoted or indented
  inside a reply is content, and stays.
- **Output** `text`, the text §2b makes of the input; `hash`, SHA-256 of that text as
  UTF-8, base64.
- **Compare** both. Compare `text` first: a mismatch there says which rule of §2b you
  read differently, where the hash only says that you did.

### `charset-vectors.json` — reading bytes and encoded words (§2 step 0, §5)

- **Input** `text_parts[]`: `charset` (the declared label) and `bytes_hex`.
  `subjects[]`: `raw`, a Subject field as it arrives.
- **Output** `text`, the text the bytes or the field are read to, and
  `text_sha256_base64`, SHA-256 of that text as UTF-8, base64.
- **Compare** both, for each of the two arrays, and report the two counts separately
  (40 and 14). The expected values are typed from the WHATWG Encoding Standard's decoder
  algorithms and index data, so a disagreement here is about reading bytes, before any
  hashing is involved.

### `parts-manifest-vectors.json` — the boundary and the manifest (`canonical-content.md` §9.1, §9.2a)

- **Input** `content_type`, a whole `Content-Type` field, and `message_hex`, the message
  it belongs to — the fixed two-part message the file's `message` block describes, with
  that field in its head.
- **Output** `boundary`, what §9.2a reads out of the field (`""` means none, so the
  container is one opaque leaf), and `manifest`, the `k` of each leaf the §9.1 walk then
  finds, in order.
- **Compare** both. `boundary` says whether you read the parameter the same way;
  `manifest` says whether that changed the message you saw.
- **The last seven (`pm-021` to `pm-027`) are the trim vectors of this file.** §9.2a
  reads a boundary parameter with the white space of §2 step 4 — the 25 code points
  `String.prototype.trim()` removes, and no others. A reader that uses its own language's
  white space instead reads a DIFFERENT container: Python's `\s` and `str.strip()` also
  hold U+001C–U+001F and U+0085, and do not hold U+FEFF. These seven put such a character
  where the parameter is written — quoted, before the `=`, inside a segment, and in the
  extended form — and the answers say which way it was read: in `pm-021`, `pm-023` and
  `pm-024` the character (U+001F, U+0085) is NOT white space to §2 step 4 and stays in
  the boundary, which then matches no delimiter in the message, so the container is one
  `opaque` leaf; `pm-022` writes it between the attribute and the `=`, where it makes the
  parameter unreadable and the boundary is `""`, again one `opaque` leaf; in `pm-025` and
  `pm-026` the character is U+FEFF, which IS in the set and comes off, so the walk finds
  `plain` and `html`. `pm-027` is the control: U+00A0 is white space to both sets, so its
  answer must come out the same whichever one a reader used — a reader that gets `pm-027`
  right and the other six wrong has not read §9.2a.
- **One thing these 27 do not decide: percent-decoding outside the extended form.** Four
  `content_type` values here carry a `%` (`pm-024` to `pm-027`) and every one of them is
  written in the extended form `boundary*=charset''value`, which §9.2a point 4
  percent-decodes — so that half of the rule the file does hold. None carries a `%` in a
  continuation group (`attribute*N=`) or in a plain parameter, so a reading that
  percent-decodes every continuation group and one that percent-decodes only the extended
  form both pass all 27. §9.2a point 4 of `../spec/canonical-content.md` is the rule, and
  it is the first: a parameter written in
  segments — any group spelled `attribute*N=`, `attribute*N*=` or `attribute*=` — is
  percent-decoded after its segments are joined, and a parameter written without a `*` is
  not. Both example clients answer that way, and it takes one command to see it:

  ```sh
  cd examples/python && python3 -c 'from zeknop_example.canonicalization.mime_walk import usable_boundary as b; \
    print(b("multipart/mixed; boundary=\"a%41b\""), b("multipart/mixed; boundary*0=\"a%41b\""))'
  # => a%41b aAb
  ```

### `signature-input-vectors.json` — the bytes under the signature

- **Input** `version`, `algorithm`, `strict_hash_b64`, and `free_hash_b64` (null for
  `legacy`).
- **Output** `signature_input_hex`, the exact bytes a signature is made over.
- **Compare** your assembled bytes, as hex, against it. `version` `legacy` is the input of
  every message before v1.4 — the strict hash alone, with nothing around it. Every other
  vector is the length-prefixed form of `../spec/signature-input.md` §2, with the separator the
  file names.

### `timestamp-vectors.json` — the timestamp decision (§8)

- **Input** `timestamp`, `context` (`inbound` or the outbound MTA), and `offset_seconds`
  relative to `reference_now`, which the file fixes at `2026-04-20T12:00:00.000Z`.
  Inject `reference_now` as "now"; do not use the system clock, or the vectors drift with
  the day you run them.
- **Output** `expected_decision` (`accept` or `reject`) and `expected_reason_tag`.
  `spec_condition` quotes the condition of §8 the vector sits on.
- **Compare** the decision and the reason tag.
- **There is no inbound age window.** `ts-003b` (eight days old) and `ts-004b` (a year
  old) are both `accept`, with the reason tag `permanent_verifiability`, and the file's own
  `notes` says why they carry a `b`: a seven-day inbound window existed once and does not
  now. §8 of `../spec/canonical-content.md` is the rule, and these two vectors are what
  holds it. What is left for an inbound verifier is the future-timestamp guard:
  `now + 30 s`.

### `delivered-envelope-vectors.json` — writing and removing the block

Four arrays, four questions. Report the four counts.

- **`build` (4)** — **input** `input`: `inner`, `envelope_id`, `verify_url`, `eol`.
  **Output** `expected.text`, the block your builder must produce exactly, and
  `expected.utf8_base64`, the same text as UTF-8 bytes. **Compare** the text.
- **`build_html` (5)** — the same for an HTML part. The head block is written after a
  leading DOCTYPE when there is one, which `note` says per vector.
- **`strip` (21)** — **input** `delivered`, a delivered plain part. **Output** `expected`,
  the text left after the removal, and `expected_kind` — `positive`, `not-verified`,
  `legacy-positive`, or `null` when there was no complete block to remove. The key is
  always present, in all 21 cases and in all 8 of `strip_html`; it is its value that is
  `null`, which is what the file's own `notes.strip` says. **Compare** both.
- **`strip_html` (8)** — the same for a delivered HTML part.

A block quoted inside a reply is content, and stays. That is a rule, not an edge case:
the `strip` vectors pin it, and so do the `html-envelope` cases of the differential.

### `differential/cases.json` — the same questions, 5 341 seeded inputs

Read `cases`. Each case has an `id`, a `kind`, its input, and `expected`. Compare only
the fields `expected` carries for that kind; a field it does not carry is not asked.
The file's own `kinds` block says the same thing, machine-readably, and its `forms` block
defines each form in one line.

| `kind` | n | Input fields | Compare | Which part of the specification |
|---|---|---|---|---|
| `text` | 4 337 | `text` | `strict`, `free` | `../spec/canonical-content.md` §2 and §2b |
| `bytes` | 812 | `hex`, `label` | `strict`, `free` | §2 step 0, then §2 and §2b over the text that was read |
| `subject` | 72 | `value` | `strict`, `free` | §5, then §2 and §2b over the text that was read |
| `html` | 66 | `text` | `free` | §2b over an HTML part |
| `html-envelope` | 25 | `text` | `html`, `free` | `../spec/delivered-envelope.md` §6.1, then §2b over what is left |
| `manifest` | 24 | `hex` | `manifest` | `../spec/canonical-content.md` §9.1 and §9.2a |
| `cut` | 5 | `parts` (a recipe), `value` | `cut` | §2 "Body Size Limit": the cut to the first 1 048 576 CODE POINTS |

The forms:

- `strict` — SHA-256 of the strict form of the text (§2), UTF-8, base64.
- `free` — SHA-256 of the free text form of the text (§2b), UTF-8, base64.
- `html` — SHA-256 of the text left after the §6.1 removal, UTF-8, base64. For an
  `html-envelope` case this is the hash of the unwrapped text, and the case also carries
  that text under `expected.unwrapped_text`, so a mismatch can be read instead of
  guessed.
- `manifest` — the `k` of each leaf, in order, joined with `|`. A structure, not a hash:
  a disagreement about where a container ends has to be readable as a structure. A reader
  that cannot read the message at all answers `error:<exception class name>`; if yours
  refuses differently, say so in the report rather than matching the string.
- `cut` — SHA-256 of the body a text leaf would be hashed with, UTF-8, base64: the strict
  form of the text, cut to the §2 size limit. Ask your own implementation through the
  entry point it really hashes a text leaf with, so that what is compared is the body it
  WOULD hash. The body is built from `parts`, a recipe — `{"literal": "s"}` and
  `{"repeat": "s", "count": n}` pieces, joined in order — and `value` says the same recipe
  in words, which is what a report of a mismatch can print. The limit is 1 048 576 CODE
  POINTS: in a language whose strings are UTF-16, cutting by code units ends a body in
  half of a surrogate pair, or cuts a body a code-point count leaves whole. Three of
  these five cases answer differently when they are cut that way: the two with a
  character outside the BMP in front of the cut, and the one whose body is under the
  limit in code points and over it in code units. The other two — the ASCII control, and
  the one whose astral character sits after the cut — answer the same either way, and
  carry the same hash as each other.

A `bytes` or `subject` case also carries `expected.decoded_text_sha256_b64`: SHA-256 of
the text the bytes or the field were read to, before any canonicalisation. It is a
diagnostic — compare it when `strict` and `free` both differ, and it will tell you
whether you read the bytes differently or hashed the text differently. In this file it is
present for all 884 of those cases. The field is nullable: a reading that cannot be
written back as UTF-8 has no such hash, and there `strict` and `free` are the comparison.
It is not counted in the totals below.

**That is 10 587 comparisons** over the 5 341 cases: 5 221 `strict`, 5 312 `free`, 25
`html`, 24 `manifest` and 5 `cut`. Report that number, and the number that matched.

## 3. Run your implementation over the cases

The whole loop, in any language, is this:

1. Read `vectors/differential/cases.json`.
2. For each entry of `cases`, take its input by `kind` (`text`, or `hex` + `label`, or
   `value`, or `hex` for a whole message, or `parts` for a body given as a recipe).
3. Compute the forms `expected` carries for that kind.
4. Compare, and keep the id and the field of every mismatch.

Sketched in Python, with no dependency on anything of ours:

```python
import base64, hashlib, json

def sha(text):                      # the hash every form uses
    return base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode()

cases = json.load(open("vectors/differential/cases.json"))["cases"]
compared = mismatches = 0
for c in cases:
    if c["kind"] == "text":
        text = c["text"]
    elif c["kind"] == "bytes":
        text = my_read_bytes(bytes.fromhex(c["hex"]), c["label"])      # §2 step 0
    elif c["kind"] == "subject":
        text = my_read_encoded_words(c["value"])                       # §5
    elif c["kind"] == "html-envelope":
        text = my_strip_delivered_block(c["text"])                     # §6.1
    elif c["kind"] == "html":
        text = c["text"]
    elif c["kind"] == "cut":                                           # §2 size limit
        body = "".join(p["literal"] if "literal" in p else p["repeat"] * p["count"]
                       for p in c["parts"])
        mine = {"cut": sha(my_text_leaf_body(body))}   # §2 form, cut to 1 048 576 code points
        text = None
    else:                                                              # manifest
        mine = {"manifest": "|".join(my_leaves(bytes.fromhex(c["hex"])))}
        text = None
    if text is not None:
        is_html = c["kind"] in ("html", "html-envelope")
        mine = {"free": sha(my_free_form(text, is_html))}
        if not is_html:
            mine["strict"] = sha(my_strict_form(text))                 # §2
        if c["kind"] == "html-envelope":
            mine["html"] = sha(text)
    for form, want in c["expected"].items():
        if form not in mine or want is None:
            continue                       # not asked, or a diagnostic you skipped
        compared += 1
        if mine[form] != want:
            mismatches += 1
            print(c["id"], form, "expected", want, "got", mine[form])
print(compared, "compared,", mismatches, "mismatches")
```

With `compared` at 10 587 and `mismatches` at 0, your implementation answers every
question in this file the way the reference implementation does, for this seed. That is
the claim the report makes, and it is the only one it makes.
