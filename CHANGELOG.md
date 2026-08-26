# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
  replacement for [jpdfsigner](https://github.com/zerodha/jpdfsigner).
- PKCS#7 detached signatures (SHA-256 + RSA / ECDSA P-256/P-384), visible and
  invisible signatures, sign + AES-128/256 encryption, PFX and PEM certificate
  loading, `config.ini` support, HTTP signing server, and a custom near-zero-alloc
  PDF parser and incremental-update writer.

[0.2.0]: https://github.com/nikhilponnuru/flashsign/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/nikhilponnuru/flashsign/releases/tag/v0.1.0
