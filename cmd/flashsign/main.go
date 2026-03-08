// Command flashsign signs and optionally encrypts PDF files.
//
// Usage:
//
//	flashsign sign    [flags] -src input.pdf -dest output.pdf
//	flashsign encrypt [flags] -src input.pdf -dest output.pdf
package main

import (
	"flag"
	"fmt"
	"os"

	"flashsign"
)

const usage = `flashsign — high-performance PDF signing

Usage:
  flashsign sign    [flags]   Sign a PDF
  flashsign encrypt [flags]   Sign and encrypt a PDF

Common flags:
  -src string        Input PDF path (required)
  -dest string       Output PDF path (required)
  -pfx string        PKCS#12 (.pfx/.p12) certificate path
  -pfx-pass string   PKCS#12 password
  -cert string       PEM certificate path (alternative to -pfx)
  -key string        PEM private key path (alternative to -pfx)
  -reason string     Signature reason
  -contact string    Signer contact info
  -location string   Signing location

Sign flags:
  -page int          Page for visible signature (default: 1)
  -visible           Render a visible signature box
  -x1, -y1, -x2, -y2 float  Signature box coordinates

Encrypt flags:
  -password string   Encryption password (required for encrypt)
  -aes256            Use AES-256 instead of AES-128
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	cmd := os.Args[1]
	if cmd == "-h" || cmd == "--help" || cmd == "help" {
		fmt.Print(usage)
		return
	}

	if cmd != "sign" && cmd != "encrypt" {
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", cmd, usage)
		os.Exit(1)
	}

	fs := flag.NewFlagSet(cmd, flag.ExitOnError)

	pfxPath := fs.String("pfx", "", "PKCS#12 (.pfx/.p12) certificate path")
	pfxPass := fs.String("pfx-pass", "", "PKCS#12 password")
	certPath := fs.String("cert", "", "PEM certificate path")
	keyPath := fs.String("key", "", "PEM private key path")

	src := fs.String("src", "", "Input PDF path (required)")
	dest := fs.String("dest", "", "Output PDF path (required)")

	reason := fs.String("reason", "", "Signature reason")
	contact := fs.String("contact", "", "Signer contact info")
	location := fs.String("location", "", "Signing location")

	page := fs.Int("page", 1, "Page for visible signature")
	visible := fs.Bool("visible", false, "Render a visible signature box")
	x1 := fs.Float64("x1", 0, "Signature box X1")
	y1 := fs.Float64("y1", 0, "Signature box Y1")
	x2 := fs.Float64("x2", 0, "Signature box X2")
	y2 := fs.Float64("y2", 0, "Signature box Y2")

	password := fs.String("password", "", "Encryption password")
	aes256 := fs.Bool("aes256", false, "Use AES-256 instead of AES-128")

	fs.Parse(os.Args[2:])

	if *src == "" || *dest == "" {
		fatal("-src and -dest are required")
	}

	signer, err := buildSigner(*pfxPath, *pfxPass, *certPath, *keyPath)
	if err != nil {
		fatal("load certificate: %v", err)
	}

	params := flashsign.SignParams{
		Src:      *src,
		Dest:     *dest,
		Reason:   *reason,
		Contact:  *contact,
		Location: *location,
		Page:     *page,
	}
	if *visible {
		v := true
		params.Visible = &v
		rect := flashsign.Rectangle{X1: *x1, Y1: *y1, X2: *x2, Y2: *y2}
		params.Rect = &rect
	}

	switch cmd {
	case "sign":
		if err := signer.Sign(params); err != nil {
			fatal("sign: %v", err)
		}
		fmt.Printf("Signed %s → %s\n", *src, *dest)

	case "encrypt":
		if *password == "" {
			fatal("-password is required for encrypt")
		}
		enc := flashsign.EncryptParams{
			Password: *password,
			AES256:   *aes256,
		}
		if err := signer.SignAndEncrypt(params, enc); err != nil {
			fatal("sign and encrypt: %v", err)
		}
		fmt.Printf("Signed and encrypted %s → %s\n", *src, *dest)
	}
}

func buildSigner(pfxPath, pfxPass, certPath, keyPath string) (*flashsign.Signer, error) {
	if pfxPath != "" {
		return flashsign.NewSignerFromPFX(pfxPath, pfxPass)
	}
	if certPath != "" && keyPath != "" {
		return flashsign.NewSignerFromPEM(certPath, keyPath)
	}
	return nil, fmt.Errorf("provide either -pfx or both -cert and -key")
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
