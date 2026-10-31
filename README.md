# ZEKNOP Signed Email — Developer Preview

**Developer Preview — the protocol and the API may change; nothing in this repository is a security guarantee.**

This repository is the public package of the ZEKNOP Signed Email protocol as published by Zeknod OÜ: the specification extract, the test vectors with the differential cases, the public HTTP contract of a relay, two example clients, and the text of the sandbox. It is read at <https://docs.zeknop.org/> and kept here as the same files.

| Directory | What it is | Licence |
|---|---|---|
| `spec/` | the specification extract (canonical content, signature input, delivered envelope, changelog) with a quick start, and the tables it pins | CC BY 4.0; the data of `spec/tables/` also under its sources' terms, see `spec/tables/README.md` |
| `vectors/` | test vectors, the differential cases with reference answers, and how to report agreement | CC BY 4.0 |
| `api/` | the public HTTP contract of a relay (`openapi-public.json`), its semantics as the code behaves, and the API changelog | CC BY 4.0 |
| `examples/js/`, `examples/python/` | example clients: verify, sign, conformance — no dependencies beyond Node ≥ 20 or Python ≥ 3.11 | Apache-2.0 |
| `sandbox/` | what a sandbox relay is and how one is run | CC BY 4.0 |
| `site/` | the source of the documentation page | CC BY 4.0 |
| `CHANGELOG.md` | what changed between published states of this repository | CC BY 4.0 |
| `README.md` | this page | CC BY 4.0 |

Each directory's licence is the row above; where a file carries a licence header of its own, that header is what names its licence (the JSON vector files cannot carry one — `vectors/README.md` is their notice). The example clients carry `LICENSE` and `NOTICE`. There is no single licence for the whole repository, which is why there is no `LICENSE` file at its root.

**Where to start.** `spec/README.md` (the quick start), then `vectors/CONFORMANCE.md` (how to check an implementation against the vectors), then `api/README.md` (what a relay answers). **Sandbox:** none is published with this preview — `sandbox/README.md` says what one is, how to recognise one and what it does. What changed between published states of this repository: `CHANGELOG.md`.

What is said to be *measured* in these files was measured by the publisher on the publisher's own implementations; the evidence is not part of this package, and the vectors and differential cases are what you can run yourself.

© 2026 Zeknod OÜ. Zeknod® is a registered trade mark of Zeknod OÜ (EUTM 019305293).
