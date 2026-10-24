<!-- Developer Preview copy of the ZEKNOP Signed Email specification. -->
**`canonical-content.md`** — what is hashed. Version 1.4 (2026-09-23).
Publisher: Zeknod OÜ. Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
Source digest (SHA-256 of the file this copy was made from): `9841d3c929c2cbf51008d10e10e149f55c09e9ff616f1d699f593b25f22ae4b8`.
This copy differs from that file in this header and in the reference rewrites described in
[README.md](README.md): a pointer to something a reader outside the publisher's repository
cannot open becomes a pointer inside this package or is dropped. No normative sentence is
changed.
Under this header stand notes from the publisher, marked as such: new text, normative
for nothing, each about one sentence of this document.

---

**Notes from the publisher on this copy.** They are not part of the specification and no
rule is changed by them. Each one names a sentence of this document that a reader outside
the publisher's repository can read two ways, or that rests on something this package does
not carry, and says which reading the implementations are held to and where in this package
you can check it.

* **On the word “measured”.** Where this document says something was measured, the measurement
  is the publisher's and its evidence is not part of this package. What you can rerun here is
  `../vectors/` — every file, with `../vectors/validate_vectors.py` and each generator's
  `--check` — and `../vectors/differential/cases.json` through either example client.

* **§12's ticks are about the publisher's tests.** The checklist says a box is ticked only
  where a test holds an implementation to the rule, and those tests are not part of this
  package, so no tick here is one you can verify. What you can rerun is `../vectors/`, and
  `../vectors/CONFORMANCE.md` says what each file compares. The four unticked boxes are
  statements about those tests and not gaps in the protocol, which §12 says itself.

---

# ZEKNOP Canonical Content Specification

**Version:** 1.4 (2026-09-23 — §2 step 0 declared charsets, §2b free text form, §5 encoded words, §9.5 milter scope rewritten, §2 line ends, §13 vectors; see `CHANGELOG.md`)
**Status:** Normative
**Date:** 2026-09-23 (v1.3.1: 2026-09-09, v1.3: 2026-08-09, v1.2: 2026-08-07, v1.1: 2026-04-20)
**Scope:** Defines canonical content construction, normalization, hashing, timing, and BCC handling for the ZEKNOP email signing protocol. All implementations (Thunderbird plugin, Haraka plugin, Shield, postfix-milter) MUST conform to this specification.

---

## §1 Canonical Content Object

The canonical content object is the input to the content hash. v1.3 defines exactly TWO
shapes, and the shape is chosen deterministically from the STRUCTURE of the message
(§1.1) — never from a header, flag, or version marker, so the choice cannot be
downgraded by an attacker.

**Shape A — plain (v1.1, unchanged byte-for-byte):**

```json
{
  "from": "<normalized sender>",
  "to": "<normalized recipients>",
  "subject": "<trimmed subject>",
  "body": "<normalized body>",
  "timestamp": "<ISO 8601 timestamp>"
}
```

**Shape B — parts manifest (v1.3):**

```json
{
  "from": "<normalized sender>",
  "to": "<normalized recipients>",
  "subject": "<trimmed subject>",
  "timestamp": "<ISO 8601 timestamp>",
  "parts": [
    {"k": "plain", "h": "<base64 SHA-256 of §2-normalized UTF-8>"},
    {"k": "html", "h": "<base64 SHA-256 of §2-normalized UTF-8>"},
    {"k": "attachment", "n": "invoice.pdf", "h": "<base64 SHA-256 of decoded bytes>"},
    {"k": "inline", "n": "cid:logo@x", "h": "<base64 SHA-256 of decoded bytes>"},
    {"k": "rfc822", "n": "rfc822[0]", "h": "<base64 SHA-256 of decoded bytes>"}
  ]
}
```

### §1.1 Shape selection (normative)

- The message consists of a SINGLE non-multipart MIME part whose content type is
  `text/plain` (explicit, or absent and therefore `text/plain` by RFC 2045 default),
  with no filename → **Shape A**. Its decoded text is the `body` (§2). This keeps every
  already-signed plain message, and the whole plain-mail beta, verifying byte-identically.
- ANY other structure (any `multipart/*` root, any non-`text/plain` root, a root
  carrying a filename) → **Shape B**. The `body` key is NOT used; all text parts are
  bound inside `parts` (§9).

Verifiers MUST derive the shape from the delivered message's structure by this same
rule and MUST NOT accept the other shape for that structure.

**Compatibility note (pre-launch):** messages signed under v1.2 (the retired
`attachments`/`html`/`inline` fields) that contain anything beyond plain text no longer
verify. Deliberate fail-closed, accepted in the v1.3 decision — pre-launch, no real
signed HTML traffic exists.

**Key order** MUST be as shown per shape: `from`, `to`, `subject`, `body`, `timestamp`
(Shape A) / `from`, `to`, `subject`, `timestamp`, `parts` (Shape B). Implementations
MUST use insertion-ordered dictionaries (Python 3.7+, JavaScript objects).

**JSON serialization:**
- Separators: `(",", ":")` — no spaces after separators
- Encoding: UTF-8, `ensure_ascii=false` (Python) / native (JavaScript)
- No trailing newline
- `parts` entries serialize with key order `k`[, `n`], `h` (insertion order)

---

## §2 Body Normalization

Body text MUST be normalized in this exact order before inclusion in the canonical object. All implementations MUST apply these steps identically.

### Step 0: Reading the bytes (normative since v1.4)

A text part arrives as BYTES and a charset label. Before any step below, the
bytes are read to text by exactly this rule, in every implementation:

1. Take the label, remove leading and trailing ASCII whitespace
   (U+0009, U+000A, U+000C, U+000D, U+0020) and ASCII-lowercase it.
2. If the label names a **legacy single-byte encoding** of the WHATWG Encoding
   Standard, read every byte through that encoding's index.
3. Otherwise, if the label names a **multi-byte encoding** of that standard
   (Big5, EUC-JP, EUC-KR, GBK, gb18030, ISO-2022-JP, Shift_JIS, UTF-16BE,
   UTF-16LE, x-user-defined, and the labels the standard maps to `replacement`),
   run that encoding's **decoder algorithm** of the standard over the index data
   pinned per the paragraph below.
4. Otherwise — **including a label that names no encoding at all** (`utf-32`,
   `x-unknown`, `cp437`, an empty label) and a part that declares no charset —
   read the bytes as **UTF-8**.

Reading never fails. A byte an encoding cannot use is exactly one U+FFFD where
the standard's decoder says so; no charset label may make a message
unverifiable, and none may make it undeliverable (no permanent 4xx).

No implementation may use a decoder of its own runtime for steps 2 and 3.
Measured over 308000 byte sequences, node 22's
`TextDecoder` is ICU rather than this standard: it maps unassigned Big5 and GBK
pointers into the private use area where the standard has an error, it counts
errors differently for EUC-JP, EUC-KR and Shift_JIS, it drops a UTF-16 byte
order mark the standard's decoder returns as U+FEFF, and it refuses
`x-user-defined` and the `replacement` labels outright. Python's codecs and
iconv-lite differ again, and iconv-lite has no ISO-2022-JP codec at all. UTF-8
is the single exception: CPython's and every JavaScript runtime's UTF-8 decoders
were measured to agree, including on every class of invalid sequence, and the
differential harness keeps measuring it (kind `bytes`).

**Pinned index data.** The published index files of the WHATWG Encoding
Standard, identifier and date per file, fetched from
`https://encoding.spec.whatwg.org/` and committed:
`index-big5.txt`, `index-euc-kr.txt`, `index-gb18030.txt`,
`index-gb18030-ranges.txt`, `index-jis0208.txt`, `index-jis0212.txt`, all
dated **2024-09-18**. Their identifiers are pinned in one committed manifest
file; the decoder modules are generated from that file and nothing else.

**No byte order mark sniffing.** The label decides; a byte order mark in the
bytes is read as U+FEFF like any other character. It is then removed by step 1
when it is at the start and by step 4 when it is at either end, so a mark never
survives into the hash in the ordinary case, and the implementations never have
to agree on a guess.

### Step 1: BOM Stripping

This step works on the text step 0 produced, never on bytes: step 0 decides nothing from
the bytes. Where step 0 read the part as UTF-8, a leading `EF BB BF` is now the character
`U+FEFF`; where it read the part as UTF-16BE or UTF-16LE, a leading byte order mark in that
same byte order (`FE FF`, `FF FE`) is. Under every other label, and in the other byte
order, those bytes were read the way the label says and are content like any other.

If the first character of the text is `U+FEFF`, remove it. Only at position 0: a `U+FEFF`
(zero-width no-break space) appearing later in the text MUST be preserved.

When the part was read as UTF-16, an implementation SHOULD log a warning (email SHOULD be
UTF-8). The warning is a log line; it changes nothing that is hashed.

### Step 2: Line Ending Normalization

1. Replace all `CRLF` (`\r\n`) with `LF` (`\n`)
2. Replace all remaining lone `CR` (`\r`) with `LF` (`\n`)

Step order matters: CRLF first, then lone CR. This prevents `\r\n` from becoming `\n\n`.

### Step 3: Trailing Whitespace

Remove trailing spaces and tabs from each line:

```
/[ \t]+$/gm  →  ""
```

**Where a line ends (normative since v1.4).** The expression above is the
production signer's, and under `m` a JavaScript engine ends a line at the
ECMAScript LineTerminators. That set is the rule for every implementation:

| ends a line for step 3 | does NOT end a line for step 3 |
|---|---|
| U+000A LINE FEED | U+0085 NEXT LINE |
| U+000D CARRIAGE RETURN (removed by step 2, listed for completeness) | U+000B LINE TABULATION |
| U+2028 LINE SEPARATOR | U+000C FORM FEED |
| U+2029 PARAGRAPH SEPARATOR | every other code point |

plus the **end of the string**: spaces and tabs at the very end of the text are
removed even when no line end follows.

Python's `re.MULTILINE` ends a line at U+000A alone, so a Python implementation
MUST write the set out rather than lean on `$`:

```python
re.sub(r"[ \t]+(?=[\n\r\u2028\u2029]|\Z)", "", text)
```

Note that U+000B and U+000C are in the step 4 trim set (they are ECMAScript
WhiteSpace for `trim()`) but are **not** line ends for step 3: a space in front
of one of them is content and stays. U+0085 is in **neither** set: `trim()` does
not remove it (Python's bare `str.strip()` does, which is why step 4 writes its
set out) and step 3 does not end a line at it. The two sets are deliberately
different and neither may be derived from the other.

### Step 4: Trim

Remove leading and trailing characters of the **trim set** from the entire string. The trim
set is exactly what JavaScript's `String.prototype.trim()` removes (ECMAScript WhiteSpace and
LineTerminator), and nothing else:

U+0009, U+000A, U+000B, U+000C, U+000D, U+0020, U+00A0, U+1680, U+2000–U+200A, U+2028,
U+2029, U+202F, U+205F, U+3000, U+FEFF.

```
text.trim()  // JavaScript — exactly the trim set
```

Python's bare `str.strip()` removes a **different** set: it also removes U+001C–U+001F and
U+0085, and it does not remove U+FEFF. A Python implementation MUST write the set out, as
step 3 does for its own:

```python
TRIM_CHARS = (
    "\u0009\u000a\u000b\u000c\u000d\u0020\u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000\ufeff"
)
text.strip(TRIM_CHARS)
```

The same set is meant wherever this document says a field is trimmed, or that white
space is removed, and never the white space of the reading language (§5, §9.2a, §9.4).

### Preservation Rules

- **Blank lines MUST be preserved.** Multiple consecutive `\n\n\n` MUST NOT be collapsed. (Collapsing blank lines was a historical bug.)
- **Internal whitespace MUST be preserved.** Only trailing whitespace per line is stripped.

### Body Size Limit

After normalization, the body is truncated to its first 1,048,576 **characters**, counted as
Unicode code points (`MAX_BODY_SIZE`; the constant's name once said bytes, the limit is not a
byte count). The canonical object carries text, and its UTF-8 encoding is the JSON
serialization's business.

A JavaScript string counts UTF-16 code units, so `text.substring(0, MAX_BODY_SIZE)` cuts a
different text from this rule when the body is longer than the limit and carries a character
outside the Basic Multilingual Plane before the cut. A JavaScript implementation counts code
points (for example `Array.from(text).slice(0, MAX_BODY_SIZE).join("")`).

### Empty Body

An empty body (after normalization) produces `"body": ""` in the canonical object. This is valid and MUST hash correctly.

---

## §2b Free Text Form (v1.4 — the second hash under the signature)

§2 hashes the sender's bytes as they were sent. That hash is what makes a byte
of a message provable, and it is also why it cannot survive an ordinary
forward: a forward rewraps lines, re-encodes characters, may change the charset
and prefixes a header block. The **free text form** is a second, weaker
derivation of the same displayed text, made so that a reader who simply presses
Forward still carries something a server can recognise.

The free form is NOT a replacement for §2 and never stands alone: a verdict
built on it says what it is worth ("the text matches what mailbox Y sent;
formatting and attachments not verified").

### §2b.1 Which text (normative)

The free form of a message is computed over **one** part, chosen by structure:

1. the first `text/plain` part in document order that the signer writes an
   envelope into (§4 of `delivered-envelope.md`), **with our envelope removed**
   (§2b.5);
2. if the message has no such part, the first displayed `text/html` part in
   document order, with our envelope removed and §2b.3 applied.

Rule 1 wins whenever a `text/plain` part exists, **even when the reader is
shown the HTML alternative**. The two alternatives of one message are written
independently by the sending client and their texts are not guaranteed to be
equal; taking whichever one the reader happens to see would make the free hash
depend on the reader. One message has exactly one free hash.

The parenthesis in rule 1 names WHICH parts are displayed parts, not which ones
an envelope was in fact written into. A verifier sees the delivered message and
cannot know what the signer managed to write — under §4 a signer may deliver a
message signed without an envelope — so the choice is made from the structure
alone: the first displayed `text/plain` part in document order, envelope or no
envelope. A message with neither a displayed `text/plain` nor a displayed
`text/html` part has the empty text, which is a defined answer and not a
missing one.

### §2b.2 The steps (normative, in this order)

1. **Markup** — if the part is HTML, resolve it to text by §2b.3. Otherwise the
   text is used as it is.
2. **Zero width** — remove every U+FEFF. It is invisible, so it is not part of
   what the reader reads.
3. **Whitespace** — replace every run of one or more whitespace characters with
   a single U+0020 SPACE. The whitespace set is the Unicode `White_Space`
   property of the pinned version, written out so no implementation may ask a
   regular-expression engine (`\s` names a different set in every engine):

   ```
   U+0009 U+000A U+000B U+000C U+000D U+0020 U+0085 U+00A0 U+1680
   U+2000 U+2001 U+2002 U+2003 U+2004 U+2005 U+2006 U+2007 U+2008 U+2009 U+200A
   U+2028 U+2029 U+202F U+205F U+3000
   ```

4. **Trim** — remove a leading and a trailing U+0020 (after step 3 there is at
   most one of each).
5. **NFC** — Unicode Normalization Form C, computed from the tables of the
   **pinned Unicode version** (§2b.4), never from the runtime's own data.
6. **UTF-8, SHA-256** — encode and hash. The hash is carried base64-encoded,
   like every other hash in this specification.

Note the difference from §2: the free form flattens ALL whitespace, including
blank lines, which §2 deliberately preserves. The two forms answer two
different questions and neither may be derived from the other.

### §2b.3 HTML to text (normative)

No implementation may use its platform's HTML parser. `DOMParser` (Chromium),
`jsdom`/`parse5` (node), Thunderbird's parser and Python's `html.parser` answer
differently for malformed markup, for an attribute containing `>`, and for a
character reference without its semicolon — and they change between versions.
The source is scanned left to right by these rules:

| input | behaviour |
|---|---|
| `<!--` | a comment: everything up to the next `-->` is dropped. With no `-->`, the rest of the input is dropped. |
| `<!` or `<?` not followed by `--` | a bogus comment: everything up to the next `>` is dropped (this is what a `<![CDATA[…]]>` block and a `<!DOCTYPE>` are). With no `>`, the rest of the input is dropped. |
| `<` or `</` followed by an ASCII letter | a tag. The name runs to the next TAB, LF, FF, SPACE, `/` or `>`, ASCII-lowercased. The tag then runs to the `>` that ends it, scanned attribute-aware so a `>` inside a quoted attribute value does not end it; an unclosed quote swallows the rest of the input. |
| `<` not followed by an ASCII letter, `/` + letter, `!` or `?` | a literal `<`. |
| `&` | a character reference (§2b.3.1) when one can be read there, a literal `&` otherwise. |
| anything else | itself. |

A tag whose name is in the **line-breaking set** emits U+000A (which step 3 then
turns into a space, so the distinction between one break and several does not
reach the hash). The set is `br` plus:

```
address article aside blockquote body caption center col colgroup dd details
dialog dir div dl dt fieldset figcaption figure footer form frame frameset
h1 h2 h3 h4 h5 h6 head header hgroup hr html legend li listing main menu nav
ol optgroup option p plaintext pre section summary table tbody td tfoot th
thead title tr ul xmp
```

Every other tag emits nothing, so `a<b>c` is `ac` and `a<div>c` is `a c`.

A **start** tag named `script`, `style` or `template` additionally drops
everything up to and including the matching close tag (`</name` followed by
TAB, LF, FF, SPACE, `/`, `>` or the end of the input, case-insensitive). With no
close tag, the rest of the input is dropped. No other element's content is
dropped: an implementation does not build a tree, so it cannot know what a
`<head>` contains.

#### §2b.3.1 Character references

- `&#` followed by at least one decimal digit, or `&#x`/`&#X` followed by at
  least one hexadecimal digit, is a numeric reference. A following `;` is
  consumed when present and is not required. With no digit it is not a
  reference and the `&` is literal.
- Otherwise the **longest** name in the HTML5 named character reference table
  (§2b.4) that matches at this position is taken, semicolon included when the
  name has one. The table carries both the names that require a semicolon and
  the 106 legacy names that do not, so `&notit;` is `¬it;` and `&noti` is `¬i`.
  No name matches → the `&` is literal.
- A numeric reference's value maps to a character thus:

  | value | character |
  |---|---|
  | `0`, or greater than `0x10FFFF` | U+FFFD |
  | a surrogate (`0xD800`–`0xDFFF`) | U+FFFD |
  | `0x80`–`0x9F` | the windows-1252 character of that byte (the WHATWG table) |
  | anything else, including noncharacters and controls | that code point |

### §2b.4 The pinned tables (normative)

**Unicode 15.1.0.** The canonical decomposition mappings, the canonical
combining classes and the composition pairs of that version, and the HTML5
named character references, are generated once and pinned as one committed table file; the four
implementation modules are generated from it by one generator and are not
edited by hand. NFC itself is the Unicode algorithm (full canonical decomposition,
canonical ordering, canonical composition, with the Hangul syllables handled
arithmetically) run over those tables.

Why pinned: normalisation is version-dependent at the edges, and the runtimes we
ship into carry different versions. Measured 2026-09-23: node 22 carries
Unicode 16.0, CPython 3.13 carries 15.1.0, and the two
order a combining sequence differently for **12 code points** assigned in 16.0
(U+0897, U+10D69–U+10D6D, U+113CE–U+113D0, U+1612F, U+1E5EE, U+1E5EF). Asking
the runtime would mean a signer and a verifier disagreeing about a message
nobody had touched, on a schedule set by whoever updates a base image.

Raising the pinned version is a protocol change: it MUST be made in all
implementations at once, and messages signed before it keep verifying only
because the Unicode normalisation stability policy forbids changing an existing
mapping — a newly assigned character can still change the order of a sequence,
which is exactly the 12 above.

### §2b.5 Removing our envelope (normative, §6.1 of `delivered-envelope.md`)

Both hashes are taken over the sender's text, so our own envelope comes off
first — and **only at the head and the tail of the part**. A verifier removes a
marker line only when it is the first line of the part (for a start marker) or
the last (for an end marker), together with the fixed lines that belong to it.
A marker that appears anywhere else is the sender's content: an envelope quoted
in a reply, indented, or prefixed with `>` stays in the text and the message
verifies green. Searching the body for a marker would let a sender move the
boundary of what is hashed by writing one.

### §2b.6 What the free form does not do

It does not cover attachments, HTML structure, the subject or any header; it
cannot tell a damaged forward from an altered one, so a verdict built on it
never says "changed". Those are properties of the verification surface, not of
this section.

### §2b.7 What later releases must keep (normative)

Two things about §2b are decided here because they would otherwise be decided
twice, differently, in two later releases. Both follow from the one rule that
**one message has exactly one free hash**.

**The envelope in the HTML alternative.** When a signer writes our
envelope into the `text/html` alternative as well, that envelope gets **no free
hash of its own**. §2b.1 does not move: a message that has a displayed
`text/plain` part takes its free form from that part and from nothing else, so
a second envelope in the HTML changes nothing about which text is hashed. The
HTML is read for the free form only in a message that has no displayed
`text/plain` part at all. Giving the HTML alternative a hash of its own would
give one message two answers, and a reader shown one alternative would get a
different verdict from a reader shown the other — which is exactly what §2b.1
was written to prevent.

**Finding the markers in a forwarded copy.** Where the free form is
taken from an HTML part, our envelope has to come off, and its markers are
**not lines of the markup**: in HTML they sit inside elements, may be split
across them, and their characters may be written as references. A copy is
therefore resolved to text by §2b.3 **before** §6.1 of `delivered-envelope.md`
looks for the markers at the head and the tail; looking for them in the markup
finds nothing and leaves our own envelope inside the hashed text.

Today every implementation removes the envelope from the HTML **source** and
resolves the markup afterwards — all four the same way, so there is no
difference between them to close. While no signer writes an envelope into HTML
the two orders give the same answer for every message that exists, because
there is nothing there to remove. Where a signer does write one, that stops
being true and the order has to be turned around, with the vectors and the
differential cases run against messages that actually carry an HTML
envelope. It is not done here: this document was written while no signer
wrote an envelope into an HTML part, and moving what is hashed without a
message to move it for would be a change nobody could test.

---

## §3 Sender Normalization (From)

The `from` field MUST contain exactly one email address, normalized as follows:

1. Parse using the platform's RFC 5322 parser:
   - Python: `email.utils.parseaddr()`
   - JavaScript (Node/Haraka): `email-addresses` npm package, `parseOneAddress()`
   - JavaScript (Thunderbird): extract from `<angle brackets>`, fallback to bare address
2. Extract the `addr-spec` (local-part@domain)
3. Convert to lowercase
4. Strip all whitespace

**Quoted local parts:** If the local-part is surrounded by double quotes (e.g. `"foo bar"@example.com`), the quotes MUST be stripped: `foo bar@example.com`. This ensures cross-component consistency — some RFC 5322 parsers preserve quotes (`email.utils.getaddresses` in Python) while others strip them (`email-addresses` npm). Stripping is the normalization rule.

**Output format:** `local@domain` — no display name, no angle brackets, no comments, no local-part quotes.

**Invalid addresses** (unparseable) MUST produce an empty string `""`.

---

## §4 Recipient Normalization (To)

The `to` field contains recipients from the `To` and `Cc` headers (see §6 for BCC).

### Parsing

1. Concatenate `To` and `Cc` header values
2. Parse each address using the platform's RFC 5322 parser:
   - Python: `email.utils.getaddresses([to_header, cc_header])`
   - JavaScript (Node/Haraka): `email-addresses` npm, `parseAddressList()`
   - JavaScript (Thunderbird): Thunderbird API provides pre-parsed arrays; extract bare addresses
3. For each address: extract `addr-spec`, strip quotes from local-part (see §3), convert to lowercase, strip whitespace
4. Filter out empty/invalid addresses

### Ordering

Preserve original order from headers. Do NOT sort alphabetically.

### Serialization

Join addresses with `", "` (comma + space):

```
"alice@example.com, bob@example.org"
```

Single recipient has no separator:
```
"alice@example.com"
```

Empty recipient list produces `""`.

---

## §5 Subject Normalization

The `subject` field is the FIRST `Subject` header of the message, unfolded,
with its RFC 2047 encoded words decoded, trimmed with the trim set of §2 step 4:

```
subject.trim()
```

**Unfolding (RFC 5322 §2.2.3).** Delete the line break, KEEP the folding
whitespace: `Subject: Hello\r\n    World` is `Hello    World`.

**Header bytes to text.** An 8-bit header is read as UTF-8; when that fails, as
ISO-8859-1, which cannot fail. (This is the header block only; §2 step 0 is the
rule for a part's payload.)

**Encoded words (normative since v1.4 — §11 point 4).** An encoded word is
`=?charset?encoding?text?=` where `charset` and `text` contain no `?` and
`encoding` is `B`, `b`, `Q` or `q`. Each one is read as follows:

1. `charset` is everything before the first `*` (an RFC 2231 language tag is
   dropped). The payload bytes are read to text by **exactly the rule of §2
   step 0** — the same labels, the same pinned tables, the same decoder. A
   Subject and a text part that declare the same charset are therefore read the
   same way, and a charset name no table knows is UTF-8 rather than a failure.
2. `B`: remove every character outside `A-Za-z0-9+/=`, then the trailing `=`
   padding. If what is left has a length of 1 modulo 4, or still contains an
   `=`, the word is **not an encoded word** (see 4). Otherwise take six bits per
   character, most significant first, and emit a byte per eight bits; a trailing
   partial group is dropped.
3. `Q`: `_` is one 0x20 byte; `=` followed by two hexadecimal digits is that
   byte; every other character is its own code unit masked to eight bits.
4. A word whose syntax is broken — a `B` payload that is not base64, an encoding
   letter that is neither B nor Q — is **not an encoded word**. It stays in the
   Subject exactly as it stands. Nothing here raises, so no Subject may make a
   message undeliverable (this closes a permanent 451 the milter used to answer
   for an unknown charset name).
5. Whitespace (spaces and tabs) between two ADJACENT encoded words is removed
   (RFC 2047 §6.2). Everything else between and around the words is kept.

Only the first `Subject` instance participates; later instances are ignored
entirely, whatever they say.

---

## §6 BCC Handling

**BCC is EXCLUDED from canonical content.**

The canonical content hash covers `To + Cc + Subject + Body`. BCC recipients are intentionally omitted because:

1. MTAs strip BCC headers before delivery — the Shield cannot see them
2. Including BCC would require per-recipient signing, which breaks the single-signature model

### Signing with BCC Present

The plugin MUST sign the email even when BCC recipients are present. The signature covers To+Cc+Subject+Body only. BCC recipients receive a validly signed email, but the BCC header itself is not integrity-protected.

### Per-Recipient Signing (Enterprise, NOT in MVP)

A future Enterprise feature MAY add per-recipient signing via `X-ZEKNOP-Recipient-Binding` header. This is opt-in and requires Haraka/milter cooperation. It is explicitly OUT OF SCOPE for the current protocol version.

---

## §7 Content Hash

```
SHA-256( JSON.stringify(canonical_object) )  →  standard base64 (padded)
```

### JavaScript (Thunderbird, Haraka)

```javascript
const hash = crypto.createHash('sha256')
  .update(JSON.stringify(canonicalObject))
  .digest('base64');
```

`JSON.stringify` uses default separators (no spaces), which matches `(",", ":")` in Python.

### Python (Shield, Milter)

```python
json_str = json.dumps(canonical, separators=(",", ":"), ensure_ascii=False)
digest = hashlib.sha256(json_str.encode("utf-8")).digest()
hash_b64 = base64.b64encode(digest).decode("ascii")
```

**Critical:** Python `json.dumps` defaults to `(", ", ": ")` — the explicit `separators=(",", ":")` is REQUIRED to match JavaScript output.

---

## §8 Timestamp

### Format

ISO 8601 with milliseconds and UTC timezone: `2026-04-17T12:30:00.000Z`

Generated by `new Date().toISOString()` (JavaScript) or equivalent.

### Signing (Fresh Timestamp)

When signing, the timestamp MUST be within **±30 seconds** of the relay server's clock. The relay API rejects timestamps outside this window.

The same timestamp is used in both the canonical content object and the `X-ZEKNOP-Timestamp` header. Using different timestamps would cause hash mismatch.

### Verification (Signature Age)

Decided (2026-04-25): inbound verification has NO max-age expiry. Signatures remain
permanently verifiable — this is an intentional "forensic proof" design decision. The relay API
`/v1/verify` and all inbound verification components (proxy/Shield, milter, plugin) MUST NOT
reject signatures based on age. Age is not what is checked. Any alteration after signing of
the content the hash covers — the canonical content object of §1, after the normalisation of
§2 to §5 — is detected by the content hash; what that normalisation removes, and a body past
its first 1,048,576 characters, is not covered. Sender binding ties the signature to the
registered identity (UUID), keys can be revoked via the relay API, and the relay keeps a
Redis SETNX record of each verified tuple on its non-proxy path (see §8 Replay Model below).

When verifying, only the future-timestamp guard applies:

| Condition | Action | UX |
|-----------|--------|----|
| `timestamp > now + 30s` | REJECT | Red — "Signature from the future (clock skew exceeded)" |
| `timestamp ≤ now + 30s` | ACCEPT | Proceed to cryptographic verification |

**Validation order:** Timestamp validation MUST happen BEFORE cryptographic verification. This prevents wasting compute on future-dated signatures and provides faster UX feedback.

### Clock Skew Tolerance

A ±30 second tolerance is allowed for future timestamps to accommodate clock drift between the signing client and the verification server. This is intentionally conservative — larger skew indicates misconfigured systems.

### Age Windows

| Context | Max Age | Rationale |
|---------|---------|-----------|
| Inbound verification (all components) | **None** | Permanent verifiability. Integrity bound by content hash + revocation. |
| Outbound MTA (Haraka, Milter) | 24 hours | Outbound signing should be fresh; 24h catches MTA queue issues |
| Relay API `/v1/sign` | 30 seconds | Signing request must be real-time |
| Relay API `/v1/verify` | None | Permanent verifiability. Future-guard only. |

### Replay Model

Inbound verification security rests on five layers, not timestamp expiry:

1. **Content hash binding** — the SHA-256 hash covers from+to+subject+body+timestamp, as §1
   to §5 normalise them; any alteration of that content invalidates the hash and the
   signature check fails. What the normalisation removes, and a body past its first
   1,048,576 characters, is not covered.
2. **Sender binding** — the UUID maps to a registered identity (email address or domain); the
   proxy enforces that the inbound `From` matches the signed identity.
3. **Revocation** — a compromised signing key can be revoked via the relay API; all subsequent
   verification attempts return `valid=false`.
4. **Relay replay mark (non-proxy path)** — when an end-user plugin calls `/v1/verify`
   directly, Redis SETNX marks the triple `(uuid, sig_hash, content_hash)` as seen for 24h.
   The mark does **not spend the signature**: a repeat of the same triple is verified
   cryptographically again and the identity is read again, so the verdict never comes out of
   the mark, and when the signature holds and the identity is active the answer is
   `valid: true` with `message: "Previously verified"`. A FIRST question whose verdict comes
   out negative deletes the mark again, so a retry after a transient failure is not blocked; a
   repeat leaves the mark where it is, which blocks nothing, because the verdict is recomputed
   either way. What the mark
   buys is therefore the record that the triple has been asked about before — a caller can tell
   a repeat from a first question — and not a refusal; what refuses a replayed *message* is the
   proxy's own guard, point 5. The mark is **intentionally not set on the proxy path**
   (`source=proxy` with authenticated `proxy_secret`): a single signed message can legitimately
   reach multiple recipients behind the same proxy, and with no mark from the proxy the end
   recipient's own plugin asks a first question like any other. The proxy authenticates itself
   with a shared secret (HMAC comparison); an unauthenticated `source=proxy` claim is treated as
   a normal (marked) request.
5. **Proxy durable replay guard (hard, Redis)** — decided 2026-08-05. The
   verification proxy enforces a durable Redis-backed guard in `handle_DATA`: per-message
   key `(uuid, sha256(signature), content_hash)` holding a SET of already-served envelope
   recipients (24h TTL, matching the relay SETNX window). A verbatim re-injection for
   already-served recipients is HARD-REJECTED (550); the same message for new recipients
   (Bcc split, per-domain routing, partial retry) is forwarded to the remainder only.
   Redis outage = FAIL-CLOSED: verified mail is deferred (451), never delivered unchecked.
   The guard applies to `status=pass` mail only (an unverified replay carries no badge).

---

## §9 Parts Manifest (v1.3 — replaces the v1.2 `attachments`/`html`/`inline` fields)

`parts` is an ORDERED array binding every leaf of the MIME tree — content, order,
count, and structure — into the signature. It closes the three structural findings of
the 2026-08-07 re-audit: non-injective html concatenation, only-first-text/plain
coverage, and inconsistent `message/rfc822` handling.

### §9.1 Walk (document order)

Walk the MIME tree depth-first, pre-order, children in their order of appearance.
Every LEAF (per §9.2) contributes EXACTLY ONE entry to `parts`, in walk order.

**Order is normative. Entries MUST NOT be sorted.** The order of parts is part of the
displayed meaning (two text parts swapped is a different message); sorting would
discard it and re-admit reordering attacks within an equal multiset. With order,
count, and structure bound, the manifest is injective: `["A","B"]` ≠ `["AB"]`, and a
hidden, duplicated, or reordered part changes the hash.

`parts` is never empty in Shape B — every message has at least one leaf.

### §9.2 Container vs leaf (single rule for all implementations)

| Content-Type | Class | Behaviour |
|---|---|---|
| `multipart/*` with a usable boundary | **container** | descend into children; contributes NO entry |
| `multipart/*` with NO usable boundary (malformed) | **leaf (opaque)** | do NOT descend; one `{"k":"opaque","h":…}` entry over the container's raw body bytes |
| `message/rfc822` | **leaf (opaque)** | do NOT descend; hash the entire attached message's decoded bytes as one entry |
| anything else (`text/*`, `image/*`, `application/*`, …) | **leaf** | one entry per §9.3 |

**Malformed container = opaque leaf (fail-closed).** A `multipart/*` part whose
boundary parameter is absent or produces no children would otherwise contribute
nothing, leaving its body cryptographically UNBOUND — an attacker could swap the
whole body under a valid signature. Instead it becomes a single opaque leaf
`{"k":"opaque","h":"<base64 SHA-256 of the raw container body>"}`, so the
manifest is never empty (§9.1) and any change to the body breaks the hash. This
is deliberately fail-closed: a genuinely malformed message may not round-trip
byte-for-byte across parsers, but a tampered message does not verify.

`message/rfc822` as an opaque leaf is the v1.3 decision: one rule for Haraka
(which never descended) and Shield (which did) ends the forward-divergence, and the
whole attached `.eml` is bound byte-for-byte. We deliberately do not look inside: the
signature covers the delivered content, not the nested message.

### §9.2a A usable boundary (normative since v1.4)

RFC 2231 §3 lets a parameter be written in numbered segments. A reader that puts
`boundary*0` and `boundary*1` back together finds the parts the sender wrote; a reader
that does not finds ONE opaque leaf where the sender wrote two. Both readings are
defensible and they hash different messages, so until v1.4 the differential
harness only MEASURED the disagreement.

**One reading, and it is the signer's.** The signature covers the manifest the SIGNER
built. A verifier that reads a boundary the signer did not read verifies a different
message and fails; a verifier that reads one the signer ignored hashes leaves the
signature never covered. The reading below is therefore the Haraka signer's
(pinned, in this package, by `../vectors/parts-manifest-vectors.json` and by the
`manifest` cases of `../vectors/differential/cases.json`), and every implementation follows it — including the milter, which is a
signer of its own (§9.5) and has to hand Haraka's answer back.

For a `multipart/*` part, the boundary is read from the RAW `Content-Type` field,
unfolded (§2.2.3 of RFC 5322) and not otherwise decoded. **White space in this section
is the trim set of §2 step 4** — the set the signer's `trim()` removes and its `\s`
matches — and never the white space of the reading language:

1. A **segment** is `attribute*N=`, `attribute*=` or `attribute*N*=`, where `attribute`
   is a run of RFC 2045 token characters and `N` a run of ASCII digits. There is NO
   white space between the segment name and its `=`; white space there means the text is
   not a segment at all. White space AFTER the `=` is allowed, and a value may be
   quoted (`\` escapes the next character) or bare (up to the next white space, less a
   single trailing `;`).
2. Segments are joined in the order `*0`, `*1`, `*2`, … **by the literal spelling of the
   number**, and the join stops at the first spelling that is absent: `*01` is not `*1`,
   and a value written `*00` alone folds to nothing.
3. Segment names group by **exact case** (`boundary*0` and `BOUNDARY*1` are two groups);
   the parameter is then looked up **case-insensitively**.
4. A parameter written in segments — any group spelled `attribute*N=`, `attribute*N*=` or
   `attribute*=` — is percent-decoded after its segments are joined; when the first segment
   carried `charset'language'`, it is read in that charset. A parameter written without a
   `*` is never percent-decoded: `boundary="a%41b"` is the five characters `a%41b`, and
   `boundary*0="a%41b"` is `aAb`.
5. A **plain** `boundary=` parameter written in the same field **wins** over the
   segments, wherever in the field it stands.
6. The boundary is the value of the first `boundary=` this leaves, with leading and
   trailing characters of the **trim set of §2 step 4** removed — that set and no other.
   A reader that trims with its own language's white space reads a different container:
   Python's bare `str.strip()` also removes U+001C–U+001F and U+0085 and leaves U+FEFF,
   and Python's `\s` matches the same wider set, so a boundary written with one of those
   code points splits for such a reader and does not split for the signer, or the other
   way round (vectors `pm-021` to `pm-027`). When it leaves none — or leaves an empty one
   — the container has NO usable boundary and §9.2 applies: ONE opaque leaf over its raw
   body, fail-closed.

Implementations: one shared module for the Shield and the milter, and one for the
portal. Neither may fall back to its runtime's own parameter parser:
Python's `policy.default` folds `*01` as `*1` and the portal's `headerParams()` used to
fold across white space and across case — the two halves of the disagreement.

Test vectors: `../vectors/parts-manifest-vectors.json` (every spelling above,
with the boundary each reading yields and the leaves it produces), and the same
spellings as whole messages in the differential cases of `../vectors/` — where the
structure is now COMPARED across every implementation, not measured.

**A verifier that is handed a tree is outside this section.** §9.2a is addressed to a
reader that splits the message itself. A verifier that is handed a tree by its host — the
Thunderbird extension receives the parts from Thunderbird (`browser.messages.getFull`) and
never sees the raw `Content-Type` field — cannot read a boundary at all, so it cannot read
this one; it is OUTSIDE the scope of §9.2a. The false red such a verifier gives a container
whose boundary is written in segments is KNOWN, and it is not a disagreement about the
signature: neither signer signs that shape (§9.2 — a container that yields an opaque leaf
is refused, and an unsigned message carries no envelope and no code), so a message that
reaches a reader with a signature was never one of them.

**Scope.** §9.2a pins the BOUNDARY. The other parameters of a part header — `filename`
and `name` (§9.4), `charset` (§2 step 0) — are still read by each implementation's own
parameter rules, and a continued `filename*0`/`filename*1` is not measured anywhere
yet; that is the next canonicalisation window's question, not this one's.

### §9.3 Entry construction

Each entry is `{"k": ..., "n": ..., "h": ...}` — keys in this order, `n` present only
where §9.4 says so.

**`k` (kind)** — classify each leaf by the FIRST matching rule:

1. content type `message/rfc822` → `rfc822`
2. `Content-Disposition: attachment`, OR a filename with disposition ≠ `inline` → `attachment`
3. content type `text/plain` with no filename → `plain`
4. content type `text/html` with no filename → `html`
5. `Content-Disposition: inline`, OR no disposition but a `Content-ID` → `inline`
6. anything else → `attachment`

(`opaque` is not produced by this rule — it comes only from the malformed-container
path in §9.2.)

**Boundary matching (normative, RFC 2046 §5.1.1):** a line is a delimiter for
boundary `B` only when it is `--B` immediately followed by optional transport
padding (`[ \t]*`) and then a line break (CRLF/LF) or end of body — the part
delimiter — OR by `--` and then that same padding-and-line-break — the close
delimiter. Any other trailing character means `B` is only a strict PREFIX of a
longer boundary token and the line is NOT a delimiter for `B`:

- `--B1` — longer name; neither a part nor a close delimiter for `B`.
- `--B--1` — the close tail `1` is not padding/line-break, so this is NOT the
  close of `B` (it is a delimiter of the longer boundary `B--`).

Parsers MUST apply the trailing check to BOTH forms. Missing it on the part
delimiter mis-splits `--B1`; missing it on the close delimiter mis-terminates at
`--B--1`. Either way nested multiparts whose boundaries extend the outer one
split at the wrong level and the manifest diverges. A dangling `--B` at end of
body with no line break (a truncated final line) is accepted as an empty part
delimiter, so implementations agree on malformed-but-parseable input.

The first-match rule replaces the v1.2 §9∩§11 double-binding: a part with a filename
AND a Content-ID but no disposition is classified once, as `attachment` (rule 2).
Rule 6 is the catch-all that keeps the manifest total — every leaf is bound, even one
that fits no conventional category (e.g. `text/calendar` with no name and no cid).

**`h` (hash)** — standard base64 (padded) of SHA-256 over:
- `plain`, `html`: the part's decoded text, §2-normalized (BOM strip → CRLF→LF →
  trailing whitespace → trim), truncated to `MAX_BODY_SIZE` characters, encoded UTF-8.
  Normalization is per part; parts are never concatenated.
- `attachment`, `inline`, `rfc822`: the DECODED content bytes (transfer encoding
  removed), raw, untruncated. For `rfc822` that is the complete attached message —
  headers and body.

**Line endings of a raw-bytes leaf (normative):** `attachment`, `inline`, `rfc822` and
`opaque` entries hash the bytes AS DELIVERED — SMTP wire form, CRLF. An implementation
whose parser hands it an LF-normalised copy (Haraka strips the CR from every body line
while parsing and re-inserts it on delivery) MUST restore the wire form before hashing;
otherwise it signs a hash no verifier can reproduce and its own mail verifies red.
Text leaves (`plain`, `html`) are exempt by construction: §2 normalization makes CRLF
and LF the same input.

**Payload extent (normative, RFC 2046 §5.1.1):** the line break that precedes a
boundary delimiter belongs to the DELIMITER, not to the part — a part's payload
ends BEFORE the CRLF (or bare LF) that introduces the next `--boundary` line.
Line-oriented parsers that accumulate the payload including that final line
break MUST strip exactly one trailing CRLF (or LF) before hashing a binary
leaf. base64 payloads are exempt by construction (decoding discards all
whitespace). Without this rule, offset-based and line-based implementations
disagree by one CRLF on every non-base64 binary leaf and every `rfc822` leaf.

### §9.4 `n` (name)

- `attachment`: the filename — RFC 2047-decoded, `.trim()`, lowercased. **If the part
  has no filename, `n` is OMITTED** (no key in the entry).
- `inline`: the filename (decoded, trimmed, lowercased) when present; else `cid:` +
  the Content-ID stripped of surrounding `<>`, trimmed, lowercased; if neither
  exists, `n` is OMITTED.
- `rfc822`: `rfc822[i]` where `i` is the 0-based ordinal of this `rfc822` leaf among
  all `rfc822` leaves in document order (first attached message = `rfc822[0]`).
- `plain`, `html`: `n` is always omitted.

**Why omission, not a synthetic name (the v1.3 "fallback n" decision):** the entry's
position in `parts` already binds its place; inventing names like `"unnamed"` (the
retired v1.2 rule) adds a cross-implementation divergence surface — index-counting
bugs, casing, localisation — while binding nothing new. Omission is the one rule no
two implementations can compute differently. An unnamed and a named part with equal
content still produce different entries (the `n` key changes the JSON), so injectivity
is unaffected.

### §9.5 Milter scope (v1.4; superseded the v1.3 rule "plain only" on 2026-09-09)

The postfix-milter signs BOTH shapes: Shape A for a single text/plain message, Shape
B — the §9 manifest — for everything else. It selects the shape from the message
STRUCTURE (§1.1), like every other implementation.

**It does not carry a second implementation of this section.** The milter reassembles
the wire form from the header fields and body chunks libmilter hands it and then reads
it with the SAME modules the Shield verifies with — the MIME walk and the canonical
builders, imported as a shared library. One walk for the signer and
the verifier means the two cannot answer differently about the shape, the order of
the leaves or where a boundary is.

**Why the v1.3 rule is retired.** "Plain only" was written when the milter had no MIME
walk of its own; the consequence was that every HTML or multipart message — most mail —
went out UNSIGNED, and beta ships the Thunderbird extension plus the milter.
Refusing to sign is not a security property when the alternative is one walk, held to
the vectors.

**What leaves the milter (v1.4, `delivered-envelope.md` §2, §4, §5).** Every message it
signs carries the positive envelope in every displayed `text/plain` part it can write
into. Where it cannot write one — no displayed text at all, a transfer encoding it
cannot read back exactly, a charset outside §4 — the message is **signed and delivered
without the envelope**; it is never delivered unsigned and bare, and never deferred
for the envelope's sake. A message it cannot sign follows `FAIL_POLICY`: `defer` (451)
or `notice` (delivered inside the not-verified envelope; anything the envelope cannot be
written into is 451). There is no third delivery and no setting that makes one: a
configuration asking for the old degraded mode stops the milter at start (§5 of
`delivered-envelope.md`).

**The envelope is outside the hash.** The exact bytes of both envelopes, where they go,
and how a verifier takes the outer one off again live in `delivered-envelope.md` §3, §4
and §6.1 — one document for all three signers, because the block is what a human reads
and three wordings would be three products. Signer and verifier both take it off
(`strip_zeknop_envelope` / `stripDeliveredEnvelope` / `stripZeknopEnvelope`) before
hashing, so the delivered message hashes back to the value that was signed. The
identifier and the link inside the positive envelope are written after signing, which is
why they can be there at all: the link's token does not exist until the relay has
answered.

## §10 (retired in v1.3)

The v1.2 `html` field is replaced by `k:"html"` entries in the §9 manifest. Every
`text/html` alternative is bound individually, in document order — the non-injective
`"\n"`-join of multiple parts is gone.

## §11 (retired in v1.3)

The v1.2 `inline` field is replaced by `k:"inline"` entries in the §9 manifest. The
part-classification predicates live on in §9.3.

## §12 Implementation Checklist

Every implementation MUST do all of the following. A box is ticked only where a test
of the implementation holds it to the rule. Rules that are implemented but pinned by
nothing are listed separately — an unticked box is a statement about the tests, not
about the code.

Canonical content (all four implementations, driven by `../vectors/vectors.json`):

- [x] Strip UTF-8 BOM from body start (`body-001`)
- [x] Strip UTF-16 BOM from body start (`body-012`, `body-013`)
- [x] Normalize CRLF → LF, then lone CR → LF (`body-004` ff.)
- [x] Trim trailing whitespace per line
- [x] NOT collapse blank lines
- [x] Trim entire body string
- [x] Truncate body to 1 MB (`e2e-003`)
- [x] Parse From using RFC 5322 parser → lowercase bare address
- [x] Parse To+Cc using RFC 5322 parser → lowercase bare addresses, original order, `", "` join (`rcpt-001`…`rcpt-009`)
- [x] Trim Subject
- [x] Select Shape A vs Shape B from message STRUCTURE only (§1.1)
- [x] Walk MIME tree depth-first pre-order; `parts` in document order, never sorted (`parts-*`)
- [x] Treat `message/rfc822` as an opaque leaf (never descend)
- [x] Classify every leaf by the §9.3 first-match rules (manifest is total)
- [x] Omit `n` exactly per §9.4 (no synthetic names)
- [x] Hash raw-bytes leaves (`attachment`, `inline`, `rfc822`, `opaque`) as DELIVERED —
      CRLF wire form, transfer encoding removed (§9.3 line endings)
- [x] Strip the delivered ZEKNOP envelope before hashing a `plain` leaf and the Shape A
      body — on the signing side and the verifying side (§9.5)
- [x] Produce identical JSON for identical inputs across implementations
- [x] Pass all test vectors in `../vectors/vectors.json`

Timing and delivery:

- [x] Reject timestamps more than 30s in the future, accept within ±30s skew
      (pinned on the verify path)
- [x] Do NOT reject signatures based on age for inbound verification (permanent
      verifiability)
- [ ] Exclude BCC from canonical content — implemented everywhere (the milter builds
      recipients from the To/Cc HEADERS, not from SMTP RCPT TO), no test pins it
- [ ] Validate the timestamp before cryptographic verification, in every verifier
- [ ] Reject signatures older than 24 hours (outbound MTA only)
- [ ] `../vectors/timestamp-vectors.json` — the §8 boundary fixture exists but
      NO test reads it

**Where each implementation is held to the ticked rows.** Each of the four — the
Thunderbird plugin, the Haraka plugin, the Shield and the postfix-milter — is held to
them by its own tests over the vectors of `../vectors/`, and by cross-implementation
tests that compare the canonical objects, and the verdicts, of two implementations
over one message.

The milter carries no separate canonical implementation: it runs the Shield's walker
and builders (§9.5). One less implementation is one less way to diverge.

---

## §13 Test Vectors

See `../vectors/vectors.json` for normative test vectors covering:

- BOM stripping (UTF-8, UTF-16 LE, UTF-16 BE)
- Line ending normalization (CRLF, lone CR, mixed)
- Trailing whitespace removal
- Blank line preservation
- Unicode content (emoji, CJK, RTL, diacritics)
- Recipient parsing (angle brackets, display names, comments, quoted local parts)
- Punycode and internationalized domain names
- Empty body, single character body
- Body truncation at 1 MB
- v1.3 parts manifest (vectors v2.4): two text/plain parts (injectivity), re-split
  html `["A","B"]` vs `["AB"]`, `message/rfc822` opaque, mixed manifest in
  document order, unnamed attachment (`n` omitted), and the backward-compat anchor
  (single text/plain leaf = byte-identical v1.1 Shape A hash)

Each vector specifies input, expected canonical form, and expected SHA-256 hash.

Four more vector files pin what v1.4 added, each with its own generator and a
`--check` gate that fails when a file and its generator disagree:

- `../vectors/charset-vectors.json` — what a declared charset and an RFC 2047 encoded word read
  to (§2 step 0 and §5), input and expected text typed from the standard's own index
  data, never from an implementation;
- `../vectors/free-form-vectors.json` — the free text form of §2b, the second hash under the
  signature;
- `../vectors/signature-input-vectors.json` — the bytes the signature is made over, in both forms
  (`signature-input.md` §2 and §4);
- `../vectors/delivered-envelope-vectors.json` — the two delivered blocks and their removal
  (`delivered-envelope.md` §3.3 and §6.1); they are outside the hash, which is why
  nothing else would catch a drift in them.

Timestamp boundary cases live in `../vectors/timestamp-vectors.json` as a
separate regression fixture — they validate accept/reject decisions against §8: the
future guard (+30s), no maximum age for inbound verification, and the 24h age window of an
outbound MTA, with a fixed `reference_now` anchor so implementations can replay them
deterministically.

---

## References

- `../vectors/vectors.json` — Normative canonical-content test vectors
- `../vectors/timestamp-vectors.json` — Timestamp boundary regression fixture (§8)
- `CHANGELOG.md` — The normative changes, version by version
