<!-- Developer Preview: the README of the pinned tables. New text, not a copy. -->
**ZEKNOP Signed Email — the pinned tables.** Publisher: Zeknod OÜ.

---

# The pinned tables

`../canonical-content.md` reads a text part's bytes, and normalises the free text form, through
tables that runtimes ship in different versions. These three files are those tables as data:
every value as it stands in the publisher's copy at the revision this package was cut from. The
publisher's implementations, and the copies of them under `../../examples/`, are generated from
them. Only the key naming the publisher's generator command is left out.

| File | What it holds | Read by |
|---|---|---|
| `whatwg-indexes.json` | the index data of the WHATWG Encoding Standard for the legacy multi-byte encodings — Big5, EUC-KR, gb18030 and its ranges, JIS X 0208, JIS X 0212 — with the labels and, per index file, its identifier, date (2024-09-18) and SHA-256 | §2 step 0 point 3 |
| `whatwg-single-byte.json` | the labels and the index of every legacy single-byte encoding of that standard; its `source` says how the table was read out | §2 step 0 point 2 |
| `free-form-tables.json` | the canonical decompositions, combining classes and composition pairs of Unicode 15.1.0, the HTML5 named character references, and the small lists §2b names | §2b.4 |

`whatwg-indexes.json` leaves `fetched` empty: the publisher's copy does not record when the
files were fetched, and what pins each of them is its `date` and `sha256`. Its entry
`encodings.json` is the standard's label table, not an index file, and has no identifier or
date. `whatwg-single-byte.json` was read out of a browser's decoder and then compared, pointer
by pointer, with the standard's index files of 2024-09-18: all 28 encodings are equal (its
`source` says so).

An implementation that takes these tables from its own runtime instead reads a different text
wherever the runtime's version differs, and computes a different hash for that message.

**Licences.** The data comes from the WHATWG Encoding Standard and the WHATWG HTML Standard
(© WHATWG (Apple, Google, Mozilla, Microsoft), [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/))
and from the Unicode Character Database (© Unicode, Inc., Unicode License v3, whose notice is
[`LICENSE-UNICODE.txt`](LICENSE-UNICODE.txt) in this directory). The selection and the form of
these files are the publisher's, under CC BY 4.0 like the rest of `../`.
