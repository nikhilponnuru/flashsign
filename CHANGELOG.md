# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Rewritten objects now keep their own generation number. The increment builder
  hard-coded generation 0 in object headers, xref entries and the trailer's
  `/Root` and `/Info` references, so signing a PDF whose catalog, signature page
  or `/Info` dictionary sat at a non-zero generation produced a document with
  dangling references.
- A cyclic `/Prev` chain in the cross-reference table no longer hangs the parser.
  Visited sections are tracked and a loop (or a chain longer than 64 sections) is
  reported as an error.
- Stream bodies are delimited by the dictionary's `/Length` when it is a direct
  integer that lands on an `endstream` keyword. Scanning for the keyword alone
  truncated compressed streams whose data happened to contain those bytes; the
  scan remains as the fallback for indirect or missing `/Length`.
- `Sign` and `SignAndEncrypt` stage output in a temporary file and rename it over
  the destination, so a failure part-way through no longer leaves a truncated or
  unsigned file where the signed one should be. Previously only the in-place path
  did this.
- Xref-stream detection reads the `startxref` target instead of scanning the last
  megabyte for `/Type/XRef`. The scan missed linearised files whose xref stream is
  not near the end, and needlessly rewrote hybrid-reference files that already
  carry a classic table.

### Changed

- `SignStream` reads the source once into a pooled buffer instead of reading it
  whole for parsing and then streaming over it twice more to hash and to copy.
  Memory per operation drops 83–99.96% (5MB PDF, 14 cores: 5.0MB → 2.0KB) and
  settles at a constant 5 allocations regardless of document size. Parallel
  latency falls 22–32% for PDFs of 500KB and up.
- PDF parsing no longer rebuilds the search key on every dictionary lookup, and
  the dictionary scanner is shared with the increment builder rather than
  duplicated. `ParsePDF` is ~22% faster and `BuildIncrement` ~5% faster, both
  still allocation-free.
- `SignBatch` workers pull from an atomic cursor rather than a buffered channel
  sized to the batch.
- `Sign` no longer fsyncs before renaming. The replacement is still atomic for
  readers; contents are not guaranteed durable across a power loss.

### Removed

- Dead code: the write-only `sigMaxLen` field, the unused `appendDEROctetString`
  helper, `parsePDFReader`, the test-only `encryptPDF` wrapper, and the CLI's
  `normalizeRect`, which duplicated normalisation the library already does.

## [0.2.1] - 2026-08-26

### Fixed

- The test suite now runs on a clean checkout. `testdata/` is gitignored, so CI
  had no fixtures and every test that needed one failed; missing certificates and
  PDFs are now generated as self-signed stand-ins at test time. Existing local
  fixtures are never overwritten.
- `TestSignXRefStreamSourceCompat` uses the generated test certificate instead of
  a production PFX, so it runs in CI.

### Changed

- `TestAdaptiveContentsPlaceholderLargePFX` reads its password from
  `FLASHSIGN_TEST_PFX_PASSWORD` and skips when it is unset, so no certificate
  password lives in the repository.
- CI uses `actions/checkout@v7` and `actions/setup-go@v7` (Node.js 20 deprecation).

No library code changed in this release; `v0.2.0` and `v0.2.1` are identical for
importers.

## [0.2.0] - 2026-08-26

### Added

- Accessibility preservation for tagged (PDF/UA-style) documents (#1, thanks @iamd3vil):
  - `/StructTreeRoot`, `/MarkInfo`, `/Lang`, `/Metadata` (XMP), `/Outlines`, `/Info`,
    `/ID`, per-page `/StructParents`, and existing `/ViewerPreferences` entries are
    preserved when signing.
  - `/ViewerPreferences << /DisplayDocTitle true >>` is added (or merged into existing
    preferences) so assistive technology announces the document title (PDF/UA-1 7.1).
  - `/Tabs /S` is added to the page receiving the signature widget (PDF/UA-1 7.18.3).
  - The signature widget gets a `/TU (Digital signature)` alternate description
    (PDF/UA-1 7.18.6.2).
  - Encryption permissions now include "extract text for accessibility"
    (PDF 32000-1 Table 22 bit 10) so screen readers can read encrypted documents.
- MIT license, Makefile, CI workflow, and this changelog.

### Changed

- Module path is now `github.com/nikhilponnuru/flashsign`, making the library
  installable with `go get` / `go install`.

### Fixed

- An indirect `/ViewerPreferences` reference with a non-zero generation number is
  merged inline instead of being rewritten as generation 0, which would have broken
  the catalog reference and dropped existing preferences.
- An unresolvable `/ViewerPreferences` reference is left untouched instead of being
  replaced with a bare dict, which would have silently discarded existing preferences.
- A catalog containing `/StructTreeRoot null` (a stripped structure tree) is no
  longer treated as tagged.

## [0.1.0] - 2026-03-18

### Added

- Initial release: high-performance PDF digital signing library and CLI, a drop-in
  replacement for Java-based PDF signing services.
- PKCS#7 detached signatures (SHA-256 + RSA / ECDSA P-256/P-384), visible and
  invisible signatures, sign + AES-128/256 encryption, PFX and PEM certificate
  loading, `config.ini` support, HTTP signing server, and a custom near-zero-alloc
  PDF parser and incremental-update writer.

[0.2.1]: https://github.com/nikhilponnuru/flashsign/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/nikhilponnuru/flashsign/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/nikhilponnuru/flashsign/releases/tag/v0.1.0
