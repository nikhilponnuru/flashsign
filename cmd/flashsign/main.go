// Command flashsign signs and optionally encrypts PDF files.
//
// Usage:
//
//	flashsign sign    [flags] -src input.pdf -dest output.pdf
//	flashsign encrypt [flags] -src input.pdf -dest output.pdf
//	flashsign sign    -config config.ini -src input.pdf -dest output.pdf
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"flashsign"
)

const usage = `flashsign — high-performance PDF signing

Usage:
  flashsign sign    [flags]   Sign a PDF
  flashsign encrypt [flags]   Sign and encrypt a PDF

Common flags:
  -config string     Path to config.ini (optional, flags override config values)
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

	configPath := fs.String("config", "", "Path to config.ini")

	pfxPath := fs.String("pfx", "", "PKCS#12 (.pfx/.p12) certificate path")
	pfxPass := fs.String("pfx-pass", "", "PKCS#12 password")
	certPath := fs.String("cert", "", "PEM certificate path")
	keyPath := fs.String("key", "", "PEM private key path")

	src := fs.String("src", "", "Input PDF path (required)")
	dest := fs.String("dest", "", "Output PDF path (required)")

	reason := fs.String("reason", "", "Signature reason")
	contact := fs.String("contact", "", "Signer contact info")
	location := fs.String("location", "", "Signing location")

	page := fs.Int("page", 0, "Page for visible signature")
	visible := fs.Bool("visible", false, "Render a visible signature box")
	x1 := fs.Float64("x1", 0, "Signature box X1")
	y1 := fs.Float64("y1", 0, "Signature box Y1")
	x2 := fs.Float64("x2", 0, "Signature box X2")
	y2 := fs.Float64("y2", 0, "Signature box Y2")

	password := fs.String("password", "", "Encryption password")
	aes256 := fs.Bool("aes256", false, "Use AES-256 instead of AES-128")

	fs.Parse(os.Args[2:])

	// Track which flags were explicitly set on the command line.
	flagSet := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { flagSet[f.Name] = true })

	// Load config.ini if provided, then overlay explicit flags.
	if *configPath != "" {
		cfg, err := loadConfig(*configPath)
		if err != nil {
			fatal("load config: %v", err)
		}
		// Config values are defaults; explicit flags override them.
		if !flagSet["pfx"] && cfg["keyfile"] != "" {
			*pfxPath = cfg["keyfile"]
		}
		if !flagSet["pfx-pass"] && cfg["password"] != "" {
			*pfxPass = cfg["password"]
		}
		if !flagSet["cert"] && cfg["cert"] != "" {
			*certPath = cfg["cert"]
		}
		if !flagSet["key"] && cfg["key"] != "" {
			*keyPath = cfg["key"]
		}
		if !flagSet["reason"] && cfg["reason"] != "" {
			*reason = cfg["reason"]
		}
		if !flagSet["contact"] && cfg["contact"] != "" {
			*contact = cfg["contact"]
		}
		if !flagSet["location"] && cfg["location"] != "" {
			*location = cfg["location"]
		}
		if !flagSet["page"] && cfg["page"] != "" {
			if v, err := strconv.Atoi(cfg["page"]); err == nil {
				*page = v
			}
		}
		if !flagSet["visible"] && cfg["visible"] != "" {
			if v, err := strconv.ParseBool(cfg["visible"]); err == nil {
				*visible = v
			}
		}
		if !flagSet["x1"] && cfg["x1"] != "" {
			if v, err := strconv.ParseFloat(cfg["x1"], 64); err == nil {
				*x1 = v
			}
		}
		if !flagSet["y1"] && cfg["y1"] != "" {
			if v, err := strconv.ParseFloat(cfg["y1"], 64); err == nil {
				*y1 = v
			}
		}
		if !flagSet["x2"] && cfg["x2"] != "" {
			if v, err := strconv.ParseFloat(cfg["x2"], 64); err == nil {
				*x2 = v
			}
		}
		if !flagSet["y2"] && cfg["y2"] != "" {
			if v, err := strconv.ParseFloat(cfg["y2"], 64); err == nil {
				*y2 = v
			}
		}
		// Auto-enable visible if coordinates are set in config.
		if !*visible && (cfg["x1"] != "" || cfg["x2"] != "") {
			*visible = true
		}
	}

	if *page == 0 {
		*page = 1
	}

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

// loadConfig reads a simple key=value INI file. Lines starting with # or ;
// are comments. Quotes around values are stripped.
func loadConfig(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	cfg := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key := strings.TrimSpace(k)
		val := strings.TrimSpace(v)
		// Strip surrounding quotes.
		if len(val) >= 2 && (val[0] == '"' || val[0] == '\'') && val[len(val)-1] == val[0] {
			val = val[1 : len(val)-1]
		}
		cfg[key] = val
	}
	return cfg, scanner.Err()
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
