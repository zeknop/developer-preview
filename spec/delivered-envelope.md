<!-- Developer Preview copy of the ZEKNOP Signed Email specification. -->
**`delivered-envelope.md`** — what is delivered. Version 1.4 (2026-09-17).
Publisher: Zeknod OÜ. Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
Source digest (SHA-256 of the file this copy was made from): `af23406d22a7ee288d474083d531a296aceccf6d09758f11dd53091d991ed013`.
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

---

# ZEKNOP Delivered Envelope Specification

**Version:** 1.4 (2026-09-17, first issued with `v1.4.0-beta.1`). Where a rule added later
names the release or the relay contract version it holds from, it does so in its heading or its
text (§3.4).
**Status:** Normative
**Scope:** The visible block a ZEKNOP signer writes into the delivered message, the signer
invariant it serves, the signer policies for a message that cannot be signed, what a
verifier does with the block, and how the positive block's marker lines change between
releases. All signers (Haraka plugin, postfix-milter, Thunderbird plugin on send) and all
verifiers (the Shield, the Thunderbird plugin, the verification portal) MUST
conform to this specification.

The envelope is **outside** the canonical content. Nothing in this document changes
`canonical-content.md`: the hash covers the sender's content, a verifier removes the
envelope before it recomputes, and a message signed under v1.3 verifies unchanged.

---

## §1 Principle

The sender's content is not touched. An envelope is added **around** the content of the
displayed plain-text part, without reading, normalising or re-encoding that content. The
same holds for a message that is not signed.

The envelope is text for a reader who has no tool. It never carries a verdict: anyone can
type any text into a message, so no text inside a message is evidence of anything (§8).

## §2 Signer invariant

**No UNSIGNED message ever leaves a signer bare. Every message that leaves a signer (the
Haraka relay, the milter, the Thunderbird plugin on send) carries exactly one of two things:
a valid signature, or the not-verified envelope (§3.2). There is no third way.**

A signed message carries the positive envelope (§3.1) in every displayed `text/plain` part
the signer writes. When a message has no such part the signer can write into, it is signed
and delivered WITHOUT the envelope — §4 lists exactly when. A missing envelope is never a
reason to stop a message the signer could sign: that deferral is permanent (every retry ends
the same way), and it made whole classes of mail undeliverable.

An UNSIGNED message for which the not-verified envelope cannot be delivered is deferred by a
server signer — SMTP `451 4.7.1 ZEKNOP: message could not be signed, please retry later`, the
same reply from the Haraka signer and the milter (an unexpected error inside a signer:
`451 4.7.1 ZEKNOP: message could not be processed`) — and is not sent by the Thunderbird
plugin, which tells the person at the keyboard why. An unsigned message never leaves a signer
bare: not when the source is allowed by an ACL the plugin does not trust, not when the domain
or identity is missing, and not when the relay cannot be reached.

Consequence for readers: the absence of an envelope never means "signed". A message that
passed through a ZEKNOP signer always shows which of the two it is.

The same rule on the reading side. A verifier says `fail` about a message only when
the relay gave a VERDICT about it — `POST /v1/verify` answering 200 with a body that names
`valid`, which is how every verdict arrives, the negative ones included. Every other outcome
means the relay was not asked or did not answer: no connection, no answer in time, 5xx, 429,
401/403 (our own credential is wrong — the relay is refusing us, not judging the message),
any other non-200 (the question itself was refused, 409 among them), and a 200 whose body
cannot be read as a verdict. None of those may become `fail`, because `fail` marks the
message red in front of the recipient and a customer policy of `reject`/`quarantine` acts on
it — so an outage of ours would bounce or quarantine mail nothing is wrong with, and the
text of our own exception would travel to the recipient in
`X-ZEKNOP-Content-Verified-Details`. The Shield instead defers the whole message —
`451 4.7.1 Verification service temporarily unavailable`, the same reply as when its replay
store is unreachable — marks nothing, forwards nothing, and the sending server's retry
verifies normally once the relay answers again. A verifier that does not hold a queue (the
checking mailbox) records that it has not been able to ask yet and asks again.

## §3 The two envelope shapes

Both shapes are US-ASCII text. Their marker lines use ASCII characters only (`=` and `-`),
never box-drawing characters. They are English only and are not localised: the same text
for every recipient is itself something a reader can recognise.

### §3.1 Positive envelope (signed message)

```
======= ZEKNOP =======
Message ID: <id>
Verify: https://verify.zeknop.org/v1/<token>

<sender content, unchanged>

======= END ZEKNOP =======
Text outside these markers is not covered by the signature. ZEKNOP never confirms authenticity by text inside a message.
```

- `<id>` is the envelope identifier the relay returns for the signature
  (`X-ZEKNOP-Envelope-ID`, 8 letters or digits). `<token>` is the verification token
  (`X-ZEKNOP-Verify` carries the same link): from v1.4 the base64url of
  `{"v":2,"uuid":<uuid>,"hash":<content hash>}` without padding, which says which message
  the link was made for and carries no signature — the portal reads the signature and the
  algorithm from the message source. Links made before the cutover carry the v1 token
  (`{signature, hash, uuid}`) and keep working. Both are written after signing, into every
  positive envelope the message carries and in every transfer encoding of the part (a base64
  part included); neither is covered by the hash. A relay answer without a signature or without
  such an identifier is not a signature: the signer treats the message as one it could not sign
  (§5). A positive envelope never names a placeholder or an invented identifier.
- The block does not claim that the message is verified. It names the message and points
  to where it can be checked.
- The closing sentence says that text outside the markers is not covered. It does not say
  that everything inside them is: the `Message ID` and `Verify` lines are not covered (above),
  and the content between the markers is covered as `canonical-content.md` normalises it, up
  to the length limit of its §2.

### §3.2 Not-verified envelope (message the signer could not sign)

```
------- ZEKNOP NOTICE: SENDER NOT VERIFIED -------
This message passed through a ZEKNOP signing service but could not be signed.
Treat it as ordinary, unverified e-mail. To check any ZEKNOP message, open verify.zeknop.org yourself and paste the message.

<sender content, unchanged>

------- END ZEKNOP NOTICE -------
```

- The block carries **no link**: a reader is never led through a link from a message nobody
  could verify. It names the portal as a host name to be typed.
- It differs from the positive envelope in its marker character (`-------` against
  `=======`), in its words, and in having no link. The two MUST NOT be confusable.

### §3.3 Exact bytes

The two blocks above are normative byte for byte. Written out, with `EOL` the line ending
of the part the block is written into:

- positive: `======= ZEKNOP =======` EOL `Message ID: ` id EOL `Verify: ` link EOL EOL
  content EOL EOL `======= END ZEKNOP =======` EOL
  `Text outside these markers is not covered by the signature. ZEKNOP never confirms authenticity by text inside a message.`
  EOL
- not verified: `------- ZEKNOP NOTICE: SENDER NOT VERIFIED -------` EOL
  `This message passed through a ZEKNOP signing service but could not be signed.` EOL
  `Treat it as ordinary, unverified e-mail. To check any ZEKNOP message, open verify.zeknop.org yourself and paste the message.`
  EOL EOL content EOL EOL `------- END ZEKNOP NOTICE -------` EOL

Every line of the block, the last one included, ends with `EOL`. `EOL` is CRLF on the wire;
a part whose payload demonstrably uses bare LF keeps LF. There is no trailing white space
on any line of the block.

Vectors: `../vectors/delivered-envelope-vectors.json` (`build` for both shapes in
both line endings, `strip` for the removal of §6.1). Each of the three signers — the
Haraka plugin, the postfix-milter and the Thunderbird plugin — defines each block once.

#### §3.3.1 The same envelope in an HTML part

Most recipients display the HTML alternative, so a block written only into the plain part
is a block most readers never see. An HTML display part therefore carries the **same two
envelopes, in the same words**, as two blocks: a **head** block before the sender's
document and a **tail** block after it. The sender's markup between them is not read, not
re-serialised and not changed — exactly as in a plain part.

Both blocks are US-ASCII. Each is written twice over: once as an **HTML comment** carrying
the marker words, which is the byte marker a verifier removes by (§6.1), and once as a
`<div>` whose text is the same lines a plain-text reader sees. The comment stands on both
sides of the `<div>`, so each block is delimited by the same words at both of its ends. The
`<div>` carries **no class and no id** and is styled only by its `style` attribute (§3.3.2).

With `EOL` the line ending of the part (the rule above) and `STYLE` the style attribute
value of §3.3.2, the four blocks are, byte for byte:

- positive head:
  `<!-- ======= ZEKNOP ======= -->` EOL
  `<div style="` STYLE `">======= ZEKNOP =======` EOL
  `Message ID: ` id EOL
  `Verify: ` link `</div>` EOL
  `<!-- ======= ZEKNOP ======= -->` EOL
- positive tail:
  `<!-- ======= END ZEKNOP ======= -->` EOL
  `<div style="` STYLE `">======= END ZEKNOP =======` EOL
  `Text outside these markers is not covered by the signature. ZEKNOP never confirms authenticity by text inside a message.</div>`
  EOL
  `<!-- ======= END ZEKNOP ======= -->` EOL
- not-verified head:
  `<!-- ------- ZEKNOP NOTICE: SENDER NOT VERIFIED ------- -->` EOL
  `<div style="` STYLE `">------- ZEKNOP NOTICE: SENDER NOT VERIFIED -------` EOL
  `This message passed through a ZEKNOP signing service but could not be signed.` EOL
  `Treat it as ordinary, unverified e-mail. To check any ZEKNOP message, open verify.zeknop.org yourself and paste the message.</div>`
  EOL
  `<!-- ------- ZEKNOP NOTICE: SENDER NOT VERIFIED ------- -->` EOL
- not-verified tail:
  `<!-- ------- END ZEKNOP NOTICE ------- -->` EOL
  `<div style="` STYLE `">------- END ZEKNOP NOTICE -------</div>` EOL
  `<!-- ------- END ZEKNOP NOTICE ------- -->` EOL

The marker words inside the comments are the words of §3.1 and §3.2 with one space on each
side of them, so that the seven `-` of the not-verified marker never touch the `<!--` and
`-->` of the comment. Nothing is escaped, and nothing in the blocks needs escaping: the
identifier is eight letters or digits and the link is the portal host of the given
deployment (§3.4) followed by `/` and base64url characters only (`A`–`Z`, `a`–`z`, `0`–`9`, `-`, `_`). A signer that
would have to write any other character into a block does not write the block at all.

**Where the head goes.** The rule, in one sentence (decided 25 September 2026): *the head
block is the first content after a leading DOCTYPE declaration when the part has one, and
the first content of the document when it has none; a verifier removes the WHOLE block — the
marker comment, the styled `<div>`, the marker comment again — and the bytes that remain are
the sender's bytes, unchanged.* The head block is therefore written at the start of the part,
after a leading DOCTYPE when there is one, and before everything else. The sender's markup is
never entered. The tail block is appended at the end of the part, after `</html>`, and
nothing is inserted between the head block and the sender's first byte or between the
sender's last byte and the tail block — so the sender's bytes between the two inner markers
are the bytes that came in. Both shapes are pinned by the vectors of
`../vectors/delivered-envelope-vectors.json`, **with a DOCTYPE and without one**
(`build-html-*-001-lf-doctype` and `-002-crlf-no-doctype` for what a signer writes,
`strip-html-001-positive-with-a-doctype` and `strip-html-002-positive-crlf` for what a
verifier takes off).

The DOCTYPE is stepped over because of what a browser does otherwise, which was measured in
Chromium and not assumed: a
document whose first token is our `<div>` is parsed with the DOCTYPE **dropped** and the
whole document in quirks mode (`document.compatMode` `BackCompat`), which changes the box
model and the line box rules of the sender's own document. With the head block written after
the DOCTYPE, `document.compatMode` stays `CSS1Compat`, `document.doctype` is the sender's,
and the block is still `document.body.firstElementChild`. A part with no DOCTYPE was already
in quirks mode and is unaffected either way. The leading DOCTYPE is recognised as
`<!DOCTYPE` … `>` at the very start of the part (leading white space allowed, the name read
case-insensitively, and only when the quotation marks inside it are balanced); anything else
counts as the sender's first byte.

**Which parts get one.** An HTML envelope goes only into a **non-empty** displayed
`text/html` part whose charset reads ASCII as ASCII (UTF-8, or one byte per character). An
empty such part has no document the blocks could stand around and no payload to pin them
to in place, so it is delivered as it came and the message leaves signed without them (the
exception of §4, the same rule as for an empty plain part). A part in a charset that
does not — UTF-16, UTF-32, ISO-2022 — carries **no** HTML envelope; a signed message like
that is delivered without one (the exception of §4), an unsigned one follows §5. A PLAIN
part in UTF-16 does carry the envelope, in its own charset and under the two conditions §4
names; an HTML one does not, because the blocks would then have to be written into markup a
browser parses, and what a browser makes of a UTF-16 document with our bytes in front of its
byte order mark has not been measured. The
transfer encoding is the part's own, exactly as for a plain part: the blocks go in under the
same encoding and the sender's decoded bytes are unchanged (7bit, 8bit, binary,
quoted-printable and base64 exactly).

#### §3.3.2 The style attribute of the blocks

A sender's own stylesheet can hide anything in the document it is displayed with, so the
blocks are made **hard to cover, which is not the same as impossible** (§8: the verdict is
the end point's, never the block's). Every block carries the same `style` attribute value,
with `!important` on each declaration:

```
display:block !important;visibility:visible !important;opacity:1 !important;position:static !important;transform:none !important;filter:none !important;clip:auto !important;clip-path:none !important;content-visibility:visible !important;font-size:13px !important;line-height:1.4 !important;color:#000000 !important;background:#ffffff !important;width:auto !important;height:auto !important;max-height:none !important;overflow:visible !important;margin:8px 0 !important;padding:8px !important;text-indent:0 !important;z-index:auto !important;white-space:pre-wrap !important;font-family:monospace !important
```

The first twenty-one declarations are the properties a covering stylesheet reaches for; the
last two are what makes the block read like the plain-text one. An important declaration in
a `style` attribute wins over an important declaration in a stylesheet of the same origin,
which is why the head block survives `body > * { display:none !important }`,
`:first-child`, `[class]` (the block has none) and `html { visibility:hidden }` — measured
in Chromium, not assumed. The **tail** block can still be swallowed by markup the sender
left open (an unclosed `<style>` or `<!--` runs to the end of the part and takes the tail
with it); the **head** block cannot, because it precedes the sender's first byte. That
asymmetry is known and recorded, and it is why the head block, not the tail, carries the
identifier and the link.

What was measured, rule by rule, in Chromium:

| the sender writes | the head block | the sender's own text |
|---|---|---|
| `body > * { display:none !important }` | shown, full size | gone |
| `[class] { display:none !important }` | shown, full size | gone |
| `html { visibility:hidden }` | shown, full size | shown |
| `:first-child { display:none !important }` | no box | no box |
| an unclosed `<style>` | shown | — (tail swallowed) |
| an unclosed `<!--` | shown | — (tail survives: its own comment ends the sender's) |

The one rule that does take the block off the page, `:first-child`, also matches the **root
element**, so it renders the whole document blank — the sender's own message included. It
hides the block only at the price of sending nothing anybody can read, which is not the
thing the styling is there to make hard. Nothing here is a guarantee: a sender who controls
the markup can always render a document that shows nothing, and §8 is why that does not
matter to the verdict.

All three signers build these two blocks, each of them once. Vectors: the `build_html`
set of `../vectors/delivered-envelope-vectors.json`.

### §3.4 The portal host is the given deployment's (normative from relay contract 1.8)

The link line of the positive envelope reads `Verify: <portal>/<token>`, where `<portal>`
is **the portal host of the given deployment** and not a fixed name. The production
deployment's is `https://verify.zeknop.org/v1`, and that is every signer's default, so a
deployment that configures nothing writes exactly what it wrote before this paragraph
existed. Decided 3 October 2026.

Where each signer reads it:

| signer | configuration |
| --- | --- |
| Haraka plugin | `verify_portal_url` in the signer's own configuration file; `VERIFY_PORTAL_URL` in the environment when the file does not say it |
| Postfix milter | `VERIFY_PORTAL_URL` in the environment |

**Both signers of one deployment must be given the same value.** Not as hygiene: the
delivered bytes depend on it. The Haraka signer writes a PLACEHOLDER of the link into the
body before signing and fills the real link in afterwards, so the soft line breaks of a
quoted-printable part are placed while the line is `<portal>/________` long; the milter has
the real link from the start and therefore wraps against a stand-in of that same length.
Two signers pointed at two portals wrap the same message at two different columns, and the
delivered bytes of the two differ — which is what a parity test of the two signers
measures.

Two things are deliberately NOT configurable with it. The not-verified envelope's sentence
`Treat it as ordinary, unverified e-mail. To check any ZEKNOP message, open
verify.zeknop.org yourself and paste the message.` is a fixed text (§3.2), compared byte for
byte by the content gate and by the three signers' parity vectors; it names the production
portal in every deployment. And the `X-ZEKNOP-Verify` header carries the same configured
link as the envelope line, because it is the same link.

## §4 Where the envelope goes

- The envelope is written into **every displayed part the signer can write into**: each
  displayed `text/plain` part — the Shape A body, or every `k:"plain"` leaf in document
  order (`canonical-content.md` §9) — around the content, and each displayed
  `text/html` part as the head and tail blocks of §3.3.1. It goes around the content, never
  inside it. The sender's bytes, charset and transfer encoding stay as they came.
- A signed message with an HTML alternative carries the positive envelope in the plain part
  **and** in the HTML part; an HTML-only message carries it in the HTML part. A part the
  signer cannot write into is left alone and does not stop the message (the exception
  below).
- **In an HTML part** (decided 25 September 2026; §3.3.1 writes it, §6.1 reads it back):
  the head block is the first content after a leading DOCTYPE declaration when the part has
  one, and the first content of the document when it has none; a verifier removes the WHOLE
  block — the marker comment, the styled `<div>`, the marker comment again — and the bytes
  that remain are the sender's bytes, unchanged. The head block is written after the DOCTYPE
  and not before it because a document whose first token is our `<div>` is parsed with the
  DOCTYPE dropped and the sender's whole document in quirks mode, which changes how the
  sender's own content is displayed (measured in Chromium, §3.3.1). Vectors exist for both
  shapes, with a DOCTYPE and without one.
- An unsigned message follows the signer's `notice` mode (§5): under `mild` it is delivered
  with the not-verified envelope in every displayed part the signer can write into, under
  `strict` only a message that is plain text and nothing else is delivered and everything
  else is deferred (451). **In an HTML part the sender's own document can hide the block**
  (§3.3.2 makes that harder for the head block, not impossible). The verdict of an end
  point — the Shield header, the portal, the plugin — is decided by §6.1 on the bytes and is
  not affected by what the document displays, and no text anywhere claims otherwise.
- **Exception (§2): a signed message is delivered WITHOUT the envelope** when it has no
  displayed part the signer can write into. That is the whole list:
  no displayed text part at all (attachments only, a digest); a part whose
  charset the signer cannot write ASCII bytes into; a part whose transfer encoding the
  signer does not decode exactly; a part whose payload cannot be pinned to one place in the
  body; and, for the Thunderbird plugin, a message written in the HTML editor whose
  text/plain part Thunderbird generates itself. The message is signed, it verifies, and it
  shows no markers. It is NEVER a 451 and never a permanent deferral. An UNSIGNED message
  in the same position is still deferred (§5).
- Where the signer CAN write, it writes: every displayed `text/plain` part of a multipart
  gets the envelope, not only the first, and every displayed `text/html` part gets the head
  and tail blocks of §3.3.1.
- Both envelopes are written around the sender's bytes: 7bit/8bit content and a
  quoted-printable payload stay as they came, a base64 payload keeps its decoded bytes. The
  signers write them into a part whose charset is UTF-8 (well-formed or not) or a charset
  with one byte per character.
- **A plain part in UTF-16** (from version 1.5) carries the envelope too, written in the
  part's own charset — two bytes per character — under exactly two conditions, and otherwise
  it stays the exception above:
  1. the charset label **names the byte order**: `utf-16le` or `utf-16be`. Every other UTF-16
     label (`utf-16`, `unicode`, `ucs-2`, …) is read here as UTF-16LE by its label alone
     (`canonical-content.md` §2), but a mail client sniffs the byte order mark instead — and a
     block written in front of a BOM takes the BOM off the front of the part, which would
     change how the **sender's own text** is displayed. That is the rule of §3.3.1 read a
     second time: the envelope never changes the sender's content, on the wire or on screen.
  2. the transfer encoding is **base64**. A UTF-16 line ending carries a bare CR, so such a
     part is refused by the line gate under 8bit before any signer sees it (measured: an
     SMTP 554 refusal); under quoted-printable the block would have to be
     written into the encoded text in a shape no corpus holds, and it is not written.
  The content must be a whole number of code units and end at a line break in its **text**
  (in UTF-16 the LF of a CRLF has no CR byte before it). `UTF-32` is not an encoding in this
  protocol at all: §2 reads a label it does not know as UTF-8, so a part that declares one is
  not a UTF-32 part here and carries no envelope. An HTML part in any of these charsets
  carries no blocks either (§3.3.1) — that rule is unchanged.
- A display text is decoded exactly or not at all: its transfer encoding is 7bit, 8bit, binary,
  quoted-printable or base64, and a base64 payload is base64 exactly (only its alphabet, white
  space and final padding, whole groups of four). Any other (x-uuencode, a misspelt name, a base64
  payload with other characters or cut short) cannot carry an envelope. A signed message like that
  is delivered without one (the exception above); an unsigned one is deferred.
- An empty display text is a display text. An empty message body carries the envelope around
  empty content (either envelope). An empty display part inside a multipart has no payload the
  envelope can be written into in place: a signed message is delivered without an envelope in
  that part, an unsigned one is deferred.
- The Thunderbird plugin writes the positive envelope into the parts it composes itself: a
  text/plain part written in the plain-text editor, and — since version 1.5 — the HTML
  document written in the HTML editor. It cannot write into a text/plain part Thunderbird
  makes from the HTML when it sends, so for a message written in the HTML editor it sets the
  delivery format to **HTML only**, where no such part exists, and writes the head and tail
  blocks of §3.3.1 around the document it composed. The person is told ONCE per profile what
  the message is delivered as, not on every message. §6.2 applies to that document like any
  other: an earlier positive block quoted in a reply is removed before the document is hashed,
  a quoted not-verified block stays. When the delivery format cannot be changed, the message is
  signed and sent WITHOUT a block (the exception above) and the plugin says so once — a message
  that used to go out is never refused for this. A real signing failure is still never sent (§5).

## §5 Signer policies for a message that cannot be signed

| policy | behaviour |
|---|---|
| `defer` (default) | 451, the message is not sent |
| `notice`, mode `mild` (default) | the not-verified envelope (§3.2, §3.3.1) goes into every displayed part the signer can write into — around the content of each `text/plain` part, head and tail of each `text/html` part — and the message is delivered. When there is no such part (attachments only, a digest, a transfer encoding that cannot be decoded exactly, a charset outside §4): 451 |
| `notice`, mode `strict` | what the signer did before the HTML blocks existed: only a message that is one display `text/plain` part and nothing else is delivered with the envelope; anything else (an HTML alternative, an HTML-only message, an attachment, nested or rich content) and a text the envelope cannot be written into: 451 |
| `reject` | not available: a configuration naming it is refused and the signer does not start (no silent translation to another policy) |
| `strip` | removed: a configuration naming it is refused and the signer does not start |

`notice` is chosen per source, where a customer asks for it: per signing domain in the Haraka
signer (`domains.<domain>.fail_policy`), per milter (`FAIL_POLICY`). Its **mode** is chosen
per signer, not per domain — `notice_mode` in the Haraka signer's own configuration file,
`NOTICE_MODE` in the milter's environment; `mild` when it is not set, `strict` the only
other value, and any other value keeps the signer from starting (no silent fallback).
A customer who wants no block inside a document they do not control asks for `strict` and
gets today's behaviour: their unsigned HTML mail is deferred rather than delivered with a
block their own markup could hide. Under `mild` a reader of an HTML part may not see the
block, and nothing promises that they will — the end point holds the verdict (§8). A message of a signing
domain — its From domain, or else the domain it is submitted as — follows that domain's
policy on every path: a source the signer does not trust for the domain, a missing identity,
a relay that is down or refuses, a structure the signer does not sign. The Thunderbird plugin
offers no `notice`: when signing fails it does not send and says why; the person sends later.

## §6 Verifier side

- The Shield, the Thunderbird plugin and the portal recognise the not-verified envelope. A
  message whose displayed text carries it as its outer envelope is **never** shown as
  verified, whatever `X-ZEKNOP-*` headers it carries. The Shield writes
  `X-ZEKNOP-Content-Verified: unsigned-notice`; the portal says the message carries a
  notice that it was not signed and that there is nothing to verify; the plugin shows its
  not-verified state.
- A not-verified envelope **quoted inside** the content of a signed message is only text in
  the signed content. It does not change the verification of the signed message.
- **Which text is looked at.** The displayed texts are the texts the outer envelope is taken
  off before hashing (§6.1): the body of a single `text/plain` message, or every `text/plain`
  leaf of the parts manifest that is not an attachment and not inside a `message/rfc822`
  part. When the outer envelope of one of them is the not-verified envelope, the verdict is
  decided before the `X-ZEKNOP-*` headers are read or the relay is asked: the Shield's
  `unsigned-notice` (a customer policy treats it as unsigned mail, `on_none`), the portal's
  notice, the plugin's grey "Not verified". A text file attached to a message is not a
  displayed text.

### §6.1 Removing the outer envelope before hashing

Every verifier (and a signer that recomputes, e.g. the milter on its own output) removes the
outer envelope of a delivered plain-text body the same way:

1. The text must **begin** with a start marker: the positive marker
   `======= ZEKNOP =======`, the legacy positive marker (§7: `ZEKNOP VERIFIED MESSAGE`
   between two runs of seven `=` or U+2550 characters) or the not-verified marker
   `------- ZEKNOP NOTICE: SENDER NOT VERIFIED -------`. That kind is the envelope.
   When the part does not begin with one, the text is returned unchanged — **the markers
   are never searched for inside the part** (v1.4). An envelope quoted in the content —
   indented, behind `>`, or at a line start with nothing in front of it — is the sender's
   text and stays in the hash, so a signed reply or forward that quotes one is green. A
   verifier that searched would let a sender move the boundary of what is hashed by writing
   a marker line, and would strip an envelope a gateway had pushed down by prefixing a
   banner line (that message now goes red instead of verifying with a stranger's text
   above the block).
2. The end marker of **that kind** is the **last** occurrence that **begins a line**
   (`======= END ZEKNOP =======`; legacy: `END ZEKNOP VERIFIED` between seven and seven or
   more `=`/U+2550; not verified: `------- END ZEKNOP NOTICE -------`). The last one, so
   that content carrying an end marker cannot truncate the envelope; beginning a line, so
   that a quoted or indented end marker is content. When there is none after the start
   marker, the text is returned unchanged. What follows the end marker is **not** pinned:
   the closing lines differ per kind (the legacy one carries a token in its URL), and text
   below them is outside the markers, which is what the closing sentence says.
3. The content begins after the first blank line following the start marker (the first
   `LF LF` after the marker; when there is none, the first `CRLF CRLF`). When there is no
   blank line, the text is returned unchanged.
4. The content ends where the end marker begins; trailing CR and LF characters are removed.
5. **When the outer envelope is the not-verified envelope, nothing is taken off**: the text
   is hashed as it is. The not-verified envelope is recognised (its kind is reported to the
   verdict, §6) but never removed before hashing, so a text whose outer envelope is the
   not-verified envelope does not recompute to a signature — whatever `X-ZEKNOP-*` headers
   it carries, the hash does not match. A not-verified envelope inside the content of a
   positive envelope (a quote) is content like any other text.

This is the removal every signature so far was made against (for the legacy marker it is
exactly the v1.3 rule). The Haraka plugin, the Shield (whose implementation the milter
shares), the Thunderbird plugin and the portal each implement the removal once, and each
also reports which kind is outermost (`deliveredEnvelopeKind` /
`delivered_envelope_kind`: `positive`, `legacy-positive`, `not-verified`, or none).

**An HTML part (§3.3.1) is taken off at its two ends and nowhere else.** The rule runs on
the part's source — its markup as it stands, before `canonical-content.md` §2b.3 resolves
anything — because the blocks are written into the source:

1. The part must **begin** with a head block: its opening comment at the very start, or
   right after a leading DOCTYPE declaration (§3.3.1). A leading DOCTYPE is optional white
   space — each reader's own `\s`, not the trim set of `canonical-content.md` §2 step 4; the
   Python and the JavaScript sets differ at U+FEFF and U+001C–U+001F, and no vector measures
   that difference — then `<!DOCTYPE` in any letter case and everything up to the first `>`, and it counts
   only when it holds an even number of `"` characters; one line break (CRLF or LF)
   directly after it belongs to it. The opening comment must follow directly. When the part
   does not begin this way, it is returned unchanged and no kind is reported: the comments
   are **never searched for inside the part**, for the same reason the plain markers are
   not. The opening comment that begins the part decides the kind.
2. The head block ends at the first occurrence of its own comment **after** the opening one.
   It is removed from the opening comment to the end of that second comment — the marker
   comment, the styled `<div>` and the marker comment again — and one line break (CRLF or
   LF) when one follows directly; anything else after the comment is content. The leading
   DOCTYPE, with its line break, stays where it was.
3. The part must **end** with the matching tail block: the last occurrence of its closing
   comment, followed by nothing but CR and LF characters. The block begins at the occurrence
   of that same comment before it, which must lie after the head block; text in front of it
   on the same line is content. When there is no such pair, or the head block of step 2 is
   not complete, the part is returned **unchanged** and no kind is reported: the head block
   is not removed on its own.
4. What is left — the DOCTYPE, if any, and the sender's markup between the two blocks — is
   the content, byte for byte as it arrived.
5. As in a plain part, a **not-verified** HTML envelope is recognised and **nothing is taken
   off**: the part is hashed as it is, so it does not recompute to a signature. The kind is
   decided by the opening comment alone; steps 2 and 3 are not asked of it.

A head or tail block quoted inside the content (a reply or a forward that carries an earlier
message, whether as `>` lines or inside a `<blockquote>`) is content: it is not at an end of
the part, so nothing removes it.

Every implementation applies this rule to the source and resolves the markup to text only
afterwards, for the free form (`canonical-content.md` §2b.3). A marker a sender typed into
the markup in another shape — split across elements, or with its characters written as
references — is not a block and stays content.

### §6.2 Removing every envelope when a message is signed again

A reply, a forward or a relayed message can carry envelopes of earlier messages, quoted or
not. A signer removes the **positive** ones before it signs, so one message carries one
positive envelope (`stripAllEnvelopes` in the Haraka and Thunderbird plugins,
`strip_all_envelopes` in the milter). The signature covers the text that is left, and the
signer delivers its own positive envelope around it. When nothing but white space would be
left, the server signers keep the text whole; the Thunderbird plugin does not send it.
Removed are whole lines — with any `>` quote prefix — that are:

- a start or end marker of the positive envelope, in either marker version
  (`======= ZEKNOP =======`, `======= END ZEKNOP =======`; legacy §7);
- an identifier line (`Message ID: <8 letters or digits>`; legacy `ID: <8 letters or digits>`);
- a link line, in the wordings the signers have delivered: `Verify: <link>`; legacy
  `To verify this email has not been altered, open <link>`, also when a client wrapped it
  before the link; and the two wordings from before the link named the portal —
  `To verify this email has not been altered, forward it to verify@zeknop.org` and
  `Forward to verify@zeknop.org to verify.`;
- a fixed sentence of the positive envelope (the closing sentence, the legacy
  `Content outside these markers is not verified.` and `Learn more:` lines), also when a
  quoting client wrapped it at a space.

In an **HTML** part the same removal takes out the **positive head and tail blocks of
§3.3.1 wherever they stand** — at the ends of the part and quoted inside it — because a
reply or an inline forward carries the earlier message's blocks in the middle of the new
document. A block is recognised **whole**: the marker comment, the styled `<div>` and the
same comment again, in that order, exactly as a signer writes them. The `<div>` is part of
what is recognised, so one marker comment a sender typed into their own markup pairs with
nothing and the markup after it is theirs; the price is that a block a client rewrote
(a `<div>` it reformatted or re-attributed) is no longer recognised and stays in the
content. The not-verified blocks are left in place for the reason above.

**Which portal a link line may name (1.8).** A link line
is recognised when the link names **this deployment's configured portal (§3.4) or the
production default**, and both server signers apply the same rule to both -- the Haraka plugin
and the milter. Two reasons, and they are both about the same message
being read twice:

* a deployment that moved its portal still receives replies that quote envelopes written
  before the move, and a signer that only knew the new name would sign a message carrying an
  old envelope -- two positive envelopes in one message, one of them pointing somewhere this
  deployment does not serve;
* a deployment runs BOTH signers (§3.4), and they must remove the same lines or the two sign
  different byte streams for one message, which is exactly the parity §7 is about.

A link line naming any OTHER portal is left in place. It is somebody else's statement about
somebody else's message and this signer has nothing to say about it; it becomes ordinary
content inside the signature, as the quoted not-verified envelope does below.

**Two things are deliberately left in place (v1.4).**

1. **The not-verified envelope.** It states that the message it arrived with passed a signing
   service and could not be signed. Forwarding or quoting that message does not make the
   statement untrue, and the signer puts its own positive envelope around the whole text, so
   the reader sees a signed message that visibly quotes an unsigned one. The notice is then
   ordinary content inside the signature (§6, §6.1 step 1). A signer that removed it would
   hand the reader a signed forward of unsigned mail with the only sentence saying so gone.
2. **A line of the sender's own that merely names our verification host or the address the
   old envelope used** — for example `Verify: see verify.zeknop.org/v1/ for the code`. Only a
   line that is exactly one of the shapes above is removed. Until v1.4 one pattern matched any
   line that began `Forward to`, `To verify` or `Verify:` and mentioned the host anywhere in
   it; a person who wrote such a sentence lost it from their own reply, and the signature then
   covered a text they had never seen.

## §7 Parity and marker transition

- **Parity.** The Haraka plugin, the milter and the Thunderbird plugin produce both
  envelopes byte-identically. A parity test builds each
  block in all three implementations and compares them with each other and with the vectors;
  the same test runs the §6.1 removal of all four verifiers over the `strip` vectors, and holds
  the §6.2 removal of **all three signers** to the same text. §6.2 removes whole lines and
  leaves their line breaks; no implementation collapses the runs of blank lines that removal
  leaves behind (§2 of `canonical-content.md` preserves blank lines), and all three know the
  same link-line wordings — and leave the same quoted notices and the same sentences of the
  sender's own. A line one signer removes and another keeps is a reply that hashes
  differently depending on which signer saw it.
- **Legacy positive envelope.** Signers before v1.4 delivered:

  ```
  ======= ZEKNOP VERIFIED MESSAGE =======
  ID: <id>

  <sender content>

  ======= END ZEKNOP VERIFIED =======
  Content outside these markers is not verified.
  To verify this email has not been altered, open https://verify.zeknop.org/v1/<token>
  Learn more: zeknop.org/verified
  ```

  Its link line says more than the signature covers: "has not been altered" is about the
  whole email, the signature about the signed content (`canonical-content.md` §1). Verifiers
  still accept the block because mail signed with it exists; no signer writes it.

- **Transition.** Verifiers accept the legacy and the new positive markers (§6.1), with no
  end date set.
  Signers deliver only the new markers from the release that introduces them (one cutover).
  Deployment order: verifiers first (Shield, portal, Thunderbird extension 1.2.0), signers
  after. `stripAllEnvelopes` removes both positive marker versions and leaves the
  not-verified envelope where it is (§6.2).

## §8 The verdict is shown by the end point, not by the envelope

The envelope never carries the verdict; the end point does, without a click, wherever a tool
exists:

- the Thunderbird extension's button in the message display: its label, tooltip and popup;
- the Shield: `X-ZEKNOP-Content-Verified`, on which the customer's own mail server can put a
  visible banner or label (sample rules for an Exchange transport rule and a Google
  Workspace rule are in the Shield runbook);
- the verification portal.

A verdict always says in words **what** was verified — the identity the signature belongs
to, and that the signed content (`canonical-content.md` §1) is unchanged — and **never**
claims that the sender was entitled to send it, that the content is legitimate, or anything
about the parts of the message outside the signed content. A genuine domain can send a
fraudulent request; the verdict says only that the signature holds for the signed content
and names the identity.

X and Y come from the verification itself: the relay's answer names the identity the
signature belongs to. When it names a mailbox, the verdict is "from mailbox Y" and Y must be
the message's From address; otherwise, when it names a domain, the verdict is "from domain X"
and X must be the domain of the From address. A valid signature for another mailbox or
domain, or an answer that names neither, is not a green verdict in any end point. At this
release the three end points write the words as follows: the Shield into
`X-ZEKNOP-Content-Verified-Details` (`Sent from domain X, unchanged` / `Sent from mailbox Y,
unchanged`), the portal as the title of its green verdict (`Sent from domain X, signed content
unchanged` / `Sent from mailbox Y, signed content unchanged`), the Thunderbird extension (1.3.0)
as the label and tooltip of its button (`From domain X, unchanged` / `From mailbox Y,
unchanged`). The Shield's and the extension's words say "unchanged" without the qualifier the
portal's title carries. In all three the word means the signed content (`canonical-content.md`
§1), and nothing outside it is claimed.

The envelope in the body is for a reader without any tool. For that reader a text saying
"verified" was never evidence either, because anyone can type it.
