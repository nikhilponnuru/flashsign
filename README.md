# flashsign

High-performance PDF digital signing library and CLI in Go. Drop-in replacement for jpdfsigner (Java/OpenPDF/BouncyCastle) for signing Zerodha contract note PDFs.

## Features

- PKCS#7 detached signatures (SHA-256 + RSA / ECDSA P-256/P-384)
- Visible and invisible signatures
- Sign + AES-128/256 encryption
- PFX (PKCS#12) and PEM certificate loading
- Custom PDF parser — no pdfcpu in the signing hot path
- Pre-computed CMS/DER fragments for zero-alloc signing
- Concurrent batch signing
- Streaming and in-memory signing APIs

## Build

```bash
go build -o flashsign ./cmd/flashsign/
```

## Usage

### Sign a PDF

```bash
./flashsign sign \
  -pfx Zerodha.pfx \
  -pfx-pass 'yourpassword' \
  -src input.pdf \
  -dest output.pdf \
  -reason "Regulatory" \
  -contact "Zerodha Broking Limited" \
  -location "Zerodha Broking Limited, Bangalore"
```

### Sign with visible signature

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

Coordinates use the PDF coordinate system: (0,0) is at the bottom-left of the page. `x1,y1` is the bottom-left corner and `x2,y2` is the top-right corner of the signature box.

### Sign and encrypt

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

Encryption uses AES-128 by default (same as jpdfsigner). Add `-aes256` for AES-256.

### Using PEM certificates instead of PFX

```bash
./flashsign sign \
  -cert cert.pem \
  -key key.pem \
  -src input.pdf \
  -dest output.pdf
```

## CLI Reference

```
flashsign sign    [flags]   Sign a PDF
flashsign encrypt [flags]   Sign and encrypt a PDF

Common flags:
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

## Library Usage

flashsign is also a Go library. Import it directly:

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
    // ...
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

## Run Tests

```bash
go test ./...
```

## Run Benchmarks

```bash
go test -bench=. -benchmem -count=3
```
