# flashsign

[![CI](https://github.com/nikhilponnuru/flashsign/actions/workflows/ci.yml/badge.svg)](https://github.com/nikhilponnuru/flashsign/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/nikhilponnuru/flashsign.svg)](https://pkg.go.dev/github.com/nikhilponnuru/flashsign)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

High-performance PDF digital signing library and CLI in Go, built as a Go port
of the core jpdfsigner workflow with near-zero allocations on the signing path.

## Features

- PKCS#7 detached signatures (SHA-256 + RSA / ECDSA P-256/P-384)
- Visible and invisible signatures
- Sign + AES-128/256 encryption
- Accessibility-preserving: tagged (PDF/UA style) documents keep their structure and stay screen-reader readable ([details](#accessibility-tagged-pdfs))
- PFX (PKCS#12) and PEM certificate loading
- `config.ini` support for easy deployment
- Custom PDF parser — no pdfcpu in the signing hot path
- Near-zero-allocation signing (5 allocs/op RSA at any PDF size, 0 allocs for parser and increment builder)
- Pooled CMS scratch buffers and xref maps for minimal GC pressure
- Concurrent batch signing
- Streaming-I/O and in-memory signing APIs (`SignStream` reuses one source-sized buffer and avoids a combined source+output allocation)
- Atomic file output — a failed sign never leaves a truncated or unsigned file
- Production-hardened HTTP server (graceful shutdown, concurrency limiter, health endpoint)

## Install

```bash
go install github.com/nikhilponnuru/flashsign/cmd/flashsign@latest
```

Or build from a checkout:

```bash
go build -o flashsign ./cmd/flashsign/
```

## Usage

### Using config.ini

Create a `config.ini` with your signing settings:

```ini
# Certificate
keyfile=signing.pfx
password=yourpassword

# Signature metadata
reason=Regulatory
contact=Example Corp
location=Example Corp, Head Office

# Visible signature coordinates (PDF coordinate system: 0,0 at bottom-left)
page=1
x1=0
y1=609
x2=278
y2=550
```

Then sign with:

```bash
./flashsign sign -config config.ini -src input.pdf -dest output.pdf
```

Start HTTP signer server (`/sign` endpoint + `/health`):

```bash
./flashsign serve -config config.ini -pfx ./testdata/signing.pfx
```

The server provides:
- `POST /sign` — sign (and optionally encrypt) a PDF
- `GET /health` — returns `200 ok` (for load balancer health checks)
- Graceful shutdown on SIGINT/SIGTERM (10s drain)
- Concurrency limiter (default: `NumCPU*2`, configurable via `-max-concurrent` or `max_concurrent` in config.ini)
- Request body size limit (1MB)

`/sign` request contract:

```json
{
  "input_file": "/path/to/input.pdf",
  "output_file": "/path/to/output.pdf",
  "password": "optional-password-for-encryption",
  "reason": "optional override",
  "contact": "optional override",
  "location": "optional override",
  "page": 1,
  "coordinates": { "x1": 0, "y1": 609, "x2": 278, "y2": 550 }
}
```

Sign and encrypt:

```bash
./flashsign encrypt -config config.ini -src input.pdf -dest output.pdf -password "recipient-password"
```

Signing vs password locking:

- `sign`: adds a digital PKCS#7 signature to the PDF (tamper detection + signer identity).
- `encrypt` or HTTP `/sign` with `"password"`: signs first, then AES-encrypts the PDF (password-protected open).

Flags override config values, so you can use the config for defaults and override per-invocation:

```bash
./flashsign sign -config config.ini -src input.pdf -dest output.pdf -reason "Override reason"
```

### Using flags only

```bash
./flashsign sign \
  -pfx signing.pfx \
  -pfx-pass 'yourpassword' \
  -src input.pdf \
  -dest output.pdf \
  -visible \
  -page 1 \
  -x1 0 -y1 609 -x2 278 -y2 550 \
  -reason "Regulatory" \
  -contact "Example Corp" \
  -location "Example Corp, Head Office"
```

### Sign and encrypt (flags)

```bash
./flashsign encrypt \
  -pfx signing.pfx \
  -pfx-pass 'yourpassword' \
  -src input.pdf \
  -dest output.pdf \
  -visible \
  -page 1 \
  -x1 0 -y1 609 -x2 278 -y2 550 \
  -reason "Regulatory" \
  -contact "Example Corp" \
  -location "Example Corp, Head Office" \
  -password "recipient-password"
```

Encryption uses AES-128 by default. Add `-aes256` for AES-256.

### Using PEM certificates

```bash
./flashsign sign -cert cert.pem -key key.pem -src input.pdf -dest output.pdf
```

Or in config.ini:

```ini
cert=cert.pem
key=key.pem
```

### Visible signature appearance

The text in the signature box reproduces what jpdfsigner (OpenPDF) draws:
`Digitally signed by <certificate CN>`, `Date: yyyy.MM.dd HH:mm:ss z` (local
time zone), `Reason: …`, `Location: …`, laid out from the bottom of the box up
to 70% of its height with 2 pt margins and leading equal to the font size;
lines that do not fit are dropped, exactly as OpenPDF does. jpdfsigner
hard-codes the style (9 pt Helvetica, rgb(16,181,60)); flashsign uses the same
values as defaults but lets you change them:

| config.ini | CLI flag | Library | Default |
|---|---|---|---|
| `font_size` | `-font-size` | `Config.Appearance.FontSize` | `9` |
| `font_bold` | `-font-bold` | `Config.Appearance.FontBold` | `false` (Helvetica) |
| `font_color` | `-font-color` | `Config.Appearance.FontColor` | `#10B53C` (rgb 16,181,60) |

Fonts are the standard-14 Helvetica family (not embedded); jpdfsigner embeds a
metric-compatible Liberation Sans subset for the same text.

## config.ini reference

| Key | Description |
|-----|-------------|
| `keyfile` | Path to PKCS#12 (.pfx/.p12) certificate file |
| `password` | PKCS#12 password |
| `cert` | PEM certificate path (alternative to keyfile) |
| `key` | PEM private key path (alternative to keyfile) |
| `reason` | Signature reason |
| `contact` | Signer contact info |
| `location` | Signing location |
| `page` | Page number for visible signature (default: 1) |
| `visible` | Enable visible signature (`true`/`false`) |
| `x1` | Signature box left X coordinate |
| `y1` | Signature box bottom Y coordinate |
| `x2` | Signature box right X coordinate |
| `y2` | Signature box top Y coordinate |
| `font_size` | Visible signature text size in points (default: `9`) |
| `font_bold` | `true` to use Helvetica-Bold for the signature text (default: `false`) |
| `font_color` | Signature text colour, `#RRGGBB` or `r,g,b` (default: `#10B53C`, i.e. rgb(16,181,60)) |
| `server` | If `true`, running `flashsign` with no args starts HTTP server from `config.ini` |
| `server_host` | HTTP server host (default: `localhost`) |
| `server_port` | HTTP server port (default: `8090`) |
| `max_concurrent` | Maximum signing operations in flight at once; further requests wait (default: `NumCPU*2`) |

Setting any coordinate (`x1`/`x2`) automatically enables visible signature.

Relative paths in `keyfile`/`cert`/`key` are resolved in this order:
1) directory of the `-config` file
2) current working directory
3) directory of `-src` (for sign/encrypt CLI mode)

Coordinates use the PDF coordinate system: `(0,0)` is at the bottom-left of the page. `x1,y1` is the bottom-left corner and `x2,y2` is the top-right corner of the signature box.

## CLI reference

```
flashsign sign    [flags]   Sign a PDF
flashsign encrypt [flags]   Sign and encrypt a PDF
flashsign serve   [flags]   Start HTTP signer server (`/sign`)

Common flags:
  -config string     Path to config.ini (optional, flags override config values)
  -pfx string        PKCS#12 (.pfx/.p12) certificate path
  -pfx-pass string   PKCS#12 password
  -cert string       PEM certificate path (alternative to -pfx)
  -key string        PEM private key path (alternative to -pfx)
  -src string        Input PDF path (required)
  -dest string       Output PDF path (required)
  -reason string     Signature reason
  -contact string    Signer contact info
  -location string   Signing location

Sign flags:
  -page int          Page for visible signature (default: 1)
  -visible           Render a visible signature box
  -x1 float          Signature box left X
  -y1 float          Signature box bottom Y
  -x2 float          Signature box right X
  -y2 float          Signature box top Y

Encrypt flags:
  -password string   Encryption password (required for encrypt)
  -aes256            Use AES-256 instead of AES-128

Serve flags:
  -host string           Listen host (default: localhost; config key: server_host)
  -port int              Listen port (default: 8090; config key: server_port)
  -max-concurrent int    Max concurrent sign operations (default: NumCPU*2)
```

Compatibility mode (no-args startup):

```bash
# If ./config.ini has server=true, this starts the /sign server.
./flashsign
```

## Library usage

flashsign is also a Go library:

```go
import "github.com/nikhilponnuru/flashsign"
```

### Sign in memory (fastest)

```go
signer, err := flashsign.NewSignerFromPFX("signing.pfx", "password")
if err != nil {
    log.Fatal(err)
}

pdfData, _ := os.ReadFile("input.pdf")

visible := true
rect := flashsign.Rectangle{X1: 0, Y1: 550, X2: 278, Y2: 609}
signed, err := signer.SignBytes(pdfData, flashsign.SignParams{
    Reason:   "Regulatory",
    Contact:  "Example Corp",
    Location: "Example Corp, Head Office",
    Page:     1,
    Visible:  &visible,
    Rect:     &rect,
})
if err != nil {
    log.Fatal(err)
}
os.WriteFile("output.pdf", signed, 0644)
```

### Sign with streaming I/O

```go
src, _ := os.Open("input.pdf")
defer src.Close()
dst, _ := os.Create("output.pdf")
defer dst.Close()

err := signer.SignStream(src, dst, flashsign.SignParams{
    Reason: "Regulatory",
})
```

### Sign file to file

```go
err := signer.Sign(flashsign.SignParams{
    Src:  "input.pdf",
    Dest: "output.pdf",
})
```

### Sign and encrypt

```go
err := signer.SignAndEncrypt(
    flashsign.SignParams{Src: "input.pdf", Dest: "output.pdf"},
    flashsign.EncryptParams{Password: "recipient-password"},
)
```

### Batch sign (concurrent)

```go
items := []flashsign.BatchItem{
    {PDFData: pdf1, Params: flashsign.SignParams{Reason: "Regulatory"}},
    {PDFData: pdf2, Params: flashsign.SignParams{Reason: "Regulatory"}},
}
signer.SignBatch(items)
for _, item := range items {
    if item.Err != nil {
        log.Printf("failed: %v", item.Err)
        continue
    }
    // item.Result contains signed PDF bytes
}
```

## Accessibility (tagged PDFs)

Signing must not degrade an accessible document. When the source PDF is tagged
(it has `/StructTreeRoot`, or `/MarkInfo << /Marked true >>`), flashsign:

- **Preserves** `/StructTreeRoot`, `/MarkInfo`, `/Lang`, `/Metadata` (XMP), `/Outlines`,
  the `/Info` dictionary, `/ID`, existing `/ViewerPreferences` entries (eg `/Direction`),
  and per-page `/StructParents`, existing `/Tabs` and existing `/Annots`.
  The catalog and page dictionaries are copied byte-for-byte apart from the keys
  that must change.
- **Adds** `/ViewerPreferences << /DisplayDocTitle true >>` so assistive technology
  announces the document title instead of the file name (PDF/UA-1 7.1). Existing
  viewer preferences are merged. Matching the Java signer, an existing explicit
  `/DisplayDocTitle` value is preserved. When `/ViewerPreferences` is an indirect
  reference, that object is updated in the increment instead of the catalog.
- **Adds** `/Tabs /S` to the page that receives the signature widget, so annotation
  tab order follows the structure tree (PDF/UA-1 7.18.3). This applies to invisible
  signatures too, since they also add a widget annotation. Pages that already
  declare `/Tabs` are left untouched.
- **Adds** `/TU (Digital signature)` to the signature widget as its alternate
  description (PDF/UA-1 7.18.6.2).
- **Permits screen readers** when `password`/`SignAndEncrypt` encryption is used:
  the encryption permissions are printing *plus* "extract text and graphics for
  accessibility" (PDF 32000-1 Table 22 bit 10, `/P = -1337`). Copying for other
  purposes, modification and assembly remain disallowed.

Untagged PDFs are signed exactly as before — none of the entries above are added.

The signature widget deliberately gets **no** `/StructParent`: referencing the
structure tree would require also extending `/StructTreeRoot /K`, the `/ParentTree`
number tree and `/ParentTreeNextKey`, and a dangling `/StructParent` is worse than
none. Full structure-tree integration of the widget is intentionally out of scope.

## Testing

```bash
make test        # go test ./...
make race        # go test -race ./...
make cover       # coverage report in the browser
make help        # all targets
```

`testdata/` is gitignored because it holds real signing certificates. Any fixture
the suite needs and cannot find there is generated as a self-signed stand-in on
the first run, so `make test` works on a fresh clone. Fixtures that already exist
are never overwritten.

One test needs a production certificate and is skipped unless you supply both the
file and its password out-of-band:

```bash
FLASHSIGN_TEST_PFX_PASSWORD=... go test -run LargePFX ./...
```

## Performance

Benchmarked on Apple M4 Pro (14 cores), Go 1.25, RSA-2048 key. Median of 5 runs.

| Operation | ns/op | allocs/op | B/op |
|---|---|---|---|
| SignBytes (10KB PDF) | 729μs | 5 | 18KB |
| SignBytes (1MB PDF) | 1.07ms | 5 | 1.0MB |
| SignStream (10KB PDF) | 745μs | 5 | 2.0KB |
| SignStream (5MB PDF) | 2.60ms | 5 | 14KB |
| SignStream (5MB, 14 cores) | 226μs | 5 | 2.0KB |
| Parallel Visible Sign (10KB, 14 cores) | 72μs | 5 | 18KB |
| SignBytes ECDSA P-384 (10KB PDF) | 24μs | 63 | 23KB |
| ParsePDF | 1.2μs | 0 | 0 |
| BuildIncrement | 0.92μs | 0 | 0 |
| CMS/PKCS7 Signature | 724μs | 3 | 1.9KB |

After its buffer pool is warm, `SignStream` performs a roughly constant number
of allocations regardless of PDF size. Its live working memory is not constant:
the custom parser needs random access, so one source-sized buffer is retained
while signing (buffers larger than 8 MiB are not returned to the pool). It still
avoids allocating a second buffer containing the combined source and output.

## Test and benchmark guide

### 1) Quick correctness checks

Run unit tests:

```bash
go test ./...
```

Run race detector:

```bash
go test -race ./...
```

### 2) CLI smoke test

This example assumes `./testdata/signing.pfx` and `./testdata/xrefstream-sample.pdf` are available. The
test suite generates `xrefstream-sample.pdf` for you on its first run; supply your own
certificate as `signing.pfx`.

Build binary:

```bash
go build -o flashsign ./cmd/flashsign/
```

Sign a sample PDF using config defaults (override only what changes per run):

```bash
./flashsign sign \
  -config ./config.ini \
  -pfx ./testdata/signing.pfx \
  -src ./testdata/xrefstream-sample.pdf \
  -dest /tmp/xrefstream-sample.signed.pdf
```

Sanity-check signature markers:

```bash
rg -a -n "ByteRange|adbe\\.pkcs7\\.detached|/Reason|/Location" /tmp/xrefstream-sample.signed.pdf
```

Verify output size increased:

```bash
wc -c ./testdata/xrefstream-sample.pdf /tmp/xrefstream-sample.signed.pdf
```

Optional in-place write check (`-src == -dest`):

```bash
cp ./testdata/xrefstream-sample.pdf /tmp/xrefstream-sample.inplace.pdf
./flashsign sign \
  -config ./config.ini \
  -pfx ./testdata/signing.pfx \
  -src /tmp/xrefstream-sample.inplace.pdf \
  -dest /tmp/xrefstream-sample.inplace.pdf
```

### 3) HTTP server smoke test

Start server:

```bash
./flashsign serve -config ./config.ini -pfx ./testdata/signing.pfx -host 127.0.0.1 -port 18090
```

Send request:

```bash
curl -sS -X POST http://127.0.0.1:18090/sign \
  -H 'Content-Type: application/json' \
  -d '{
    "input_file":"./testdata/xrefstream-sample.pdf",
    "output_file":"/tmp/xrefstream-sample.http.signed.pdf",
    "password":"recipient-password"
  }'
```

Check signature markers:

```bash
rg -a -n "ByteRange|adbe\\.pkcs7\\.detached|/Rect|/BBox" /tmp/xrefstream-sample.http.signed.pdf
```

### 4) Benchmarking

Run full benchmark suite:

```bash
go test -run '^$' -bench . -benchmem -count=3
```

Run focused hot-path benchmarks:

```bash
go test -run '^$' \
  -bench 'Benchmark(SignBytes$|SignBytesVisible$|SignStreamVisible$|PKCS7Signature$|SignAndEncrypt$)' \
  -benchmem -count=3
```

Run parallel throughput benchmark:

```bash
go test -run '^$' -bench 'BenchmarkSignBytesVisibleParallel$' -benchmem -count=3
```

### 5) Saving and comparing benchmark runs

Save current run:

```bash
go test -run '^$' -bench . -benchmem -count=5 > /tmp/flashsign.bench.txt
```

Optional: compare two runs with `benchstat`:

```bash
go install golang.org/x/perf/cmd/benchstat@latest
benchstat /tmp/old.bench.txt /tmp/flashsign.bench.txt
```
