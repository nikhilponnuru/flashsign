# flashsign

High-performance PDF digital signing library and CLI in Go.

## Features

- PKCS#7 detached signatures (SHA-256 + RSA / ECDSA P-256/P-384)
- Visible and invisible signatures
- Sign + AES-128/256 encryption
- PFX (PKCS#12) and PEM certificate loading
- `config.ini` support for easy deployment
- Custom PDF parser — no pdfcpu in the signing hot path
- Pre-computed CMS/DER fragments for zero-alloc signing
- Concurrent batch signing
- Streaming and in-memory signing APIs

## Build

```bash
go build -o flashsign ./cmd/flashsign/
```

## Usage

### Using config.ini

Create a `config.ini` with your signing settings:

```ini
# Certificate
keyfile=Zerodha.pfx
password=yourpassword

# Signature metadata
reason=Regulatory
contact=Zerodha Broking Limited
location=Zerodha Broking Limited, Bangalore

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

Sign and encrypt:

```bash
./flashsign encrypt -config config.ini -src input.pdf -dest output.pdf -password "clientPAN123"
```

Flags override config values, so you can use the config for defaults and override per-invocation:

```bash
./flashsign sign -config config.ini -src input.pdf -dest output.pdf -reason "Override reason"
```

### Using flags only

```bash
./flashsign sign \
  -pfx Zerodha.pfx \
  -pfx-pass 'yourpassword' \
  -src input.pdf \
  -dest output.pdf \
  -visible \
  -page 1 \
  -x1 0 -y1 609 -x2 278 -y2 550 \
  -reason "Regulatory" \
  -contact "Zerodha Broking Limited" \
  -location "Zerodha Broking Limited, Bangalore"
```

### Sign and encrypt (flags)

```bash
./flashsign encrypt \
  -pfx Zerodha.pfx \
  -pfx-pass 'yourpassword' \
  -src input.pdf \
  -dest output.pdf \
  -visible \
  -page 1 \
  -x1 0 -y1 609 -x2 278 -y2 550 \
  -reason "Regulatory" \
  -contact "Zerodha Broking Limited" \
  -location "Zerodha Broking Limited, Bangalore" \
  -password "clientPAN123"
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

Setting any coordinate (`x1`/`x2`) automatically enables visible signature.

Coordinates use the PDF coordinate system: `(0,0)` is at the bottom-left of the page. `x1,y1` is the bottom-left corner and `x2,y2` is the top-right corner of the signature box.

## CLI reference

```
flashsign sign    [flags]   Sign a PDF
flashsign encrypt [flags]   Sign and encrypt a PDF

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
```

## Library usage

flashsign is also a Go library:

```go
import "flashsign"
```

### Sign in memory (fastest)

```go
signer, err := flashsign.NewSignerFromPFX("Zerodha.pfx", "password")
if err != nil {
    log.Fatal(err)
}

pdfData, _ := os.ReadFile("input.pdf")

visible := true
rect := flashsign.Rectangle{X1: 0, Y1: 550, X2: 278, Y2: 609}
signed, err := signer.SignBytes(pdfData, flashsign.SignParams{
    Reason:   "Regulatory",
    Contact:  "Zerodha Broking Limited",
    Location: "Zerodha Broking Limited, Bangalore",
    Page:     1,
    Visible:  &visible,
    Rect:     &rect,
})
if err != nil {
    log.Fatal(err)
}
os.WriteFile("output.pdf", signed, 0644)
```

### Sign streaming (low memory)

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
    flashsign.EncryptParams{Password: "clientPAN123"},
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

### 2) CLI smoke test (contract-note style PDF)

This example assumes `./testdata/Zerodha.pfx` and `./testdata/mcx-SUN844.pdf` are available.

Build binary:

```bash
go build -o flashsign ./cmd/flashsign/
```

Sign a sample PDF using config defaults (override only what changes per run):

```bash
./flashsign sign \
  -config ./config.ini \
  -pfx ./testdata/Zerodha.pfx \
  -src ./testdata/mcx-SUN844.pdf \
  -dest /tmp/mcx-SUN844.signed.pdf
```

Sanity-check signature markers:

```bash
rg -a -n "ByteRange|adbe\\.pkcs7\\.detached|/Reason|/Location" /tmp/mcx-SUN844.signed.pdf
```

Verify output size increased:

```bash
wc -c ./testdata/mcx-SUN844.pdf /tmp/mcx-SUN844.signed.pdf
```

Optional in-place write check (`-src == -dest`):

```bash
cp ./testdata/mcx-SUN844.pdf /tmp/mcx-SUN844.inplace.pdf
./flashsign sign \
  -config ./config.ini \
  -pfx ./testdata/Zerodha.pfx \
  -src /tmp/mcx-SUN844.inplace.pdf \
  -dest /tmp/mcx-SUN844.inplace.pdf
```

### 3) Benchmarking

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

### 4) Saving and comparing benchmark runs

Save current run:

```bash
go test -run '^$' -bench . -benchmem -count=5 > /tmp/flashsign.bench.txt
```

Optional: compare two runs with `benchstat`:

```bash
go install golang.org/x/perf/cmd/benchstat@latest
benchstat /tmp/old.bench.txt /tmp/flashsign.bench.txt
```
