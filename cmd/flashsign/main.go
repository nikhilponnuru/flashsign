// Command flashsign signs and optionally encrypts PDF files.
//
// Usage:
//
//	flashsign sign    [flags] -src input.pdf -dest output.pdf
//	flashsign encrypt [flags] -src input.pdf -dest output.pdf
//	flashsign serve   [flags]
//	flashsign sign    -config config.ini -src input.pdf -dest output.pdf
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"flashsign"
)

const usage = `flashsign — high-performance PDF signing

Usage:
  flashsign sign    [flags]   Sign a PDF
  flashsign encrypt [flags]   Sign and encrypt a PDF
  flashsign serve   [flags]   Start HTTP signer server compatible with jpdfsigner

Common flags:
  -config string     Path to config.ini (optional, flags override config values)
  -src string        Input PDF path (required for sign/encrypt)
  -dest string       Output PDF path (required for sign/encrypt)
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

Serve flags:
  -host string       Listen host (default: localhost; config key: server_host)
  -port int          Listen port (default: 8090; config key: server_port)
  -max-concurrent int  Max concurrent sign operations (default: NumCPU*2)
`

type requestCoordinates struct {
	X1 *float64 `json:"x1"`
	Y1 *float64 `json:"y1"`
	X2 *float64 `json:"x2"`
	Y2 *float64 `json:"y2"`
}

func (c *requestCoordinates) valid() bool {
	return c != nil && c.X1 != nil && c.Y1 != nil && c.X2 != nil && c.Y2 != nil
}

type signRequest struct {
	InputFile   string              `json:"input_file"`
	OutputFile  string              `json:"output_file"`
	Password    string              `json:"password"`
	Reason      string              `json:"reason"`
	Contact     string              `json:"contact"`
	Location    string              `json:"location"`
	Page        *int                `json:"page"`
	Coordinates *requestCoordinates `json:"coordinates"`
}

type serverDefaults struct {
	reason   string
	contact  string
	location string
	page     int
	visible  bool
	rect     flashsign.Rectangle
}

func main() {
	if len(os.Args) < 2 {
		started, err := maybeRunCompatServerFromDefaultConfig()
		if err != nil {
			fatal("compat server: %v", err)
		}
		if started {
			return
		}
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	cmd := os.Args[1]
	if cmd == "-h" || cmd == "--help" || cmd == "help" {
		fmt.Print(usage)
		return
	}

	if cmd != "sign" && cmd != "encrypt" && cmd != "serve" && cmd != "server" {
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", cmd, usage)
		os.Exit(1)
	}

	fs := flag.NewFlagSet(cmd, flag.ExitOnError)

	configPath := fs.String("config", "", "Path to config.ini")

	pfxPath := fs.String("pfx", "", "PKCS#12 (.pfx/.p12) certificate path")
	pfxPass := fs.String("pfx-pass", "", "PKCS#12 password")
	certPath := fs.String("cert", "", "PEM certificate path")
	keyPath := fs.String("key", "", "PEM private key path")

	src := fs.String("src", "", "Input PDF path (required for sign/encrypt)")
	dest := fs.String("dest", "", "Output PDF path (required for sign/encrypt)")

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
	host := fs.String("host", "", "Listen host for serve mode")
	port := fs.Int("port", 0, "Listen port for serve mode")
	maxConcurrent := fs.Int("max-concurrent", 0, "Max concurrent sign operations")

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
			*pfxPath = resolvePathFromConfig(*configPath, cfg["keyfile"], *src)
		}
		if !flagSet["pfx-pass"] && cfg["password"] != "" {
			*pfxPass = cfg["password"]
		}
		if !flagSet["cert"] && cfg["cert"] != "" {
			*certPath = resolvePathFromConfig(*configPath, cfg["cert"], *src)
		}
		if !flagSet["key"] && cfg["key"] != "" {
			*keyPath = resolvePathFromConfig(*configPath, cfg["key"], *src)
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
		if !flagSet["host"] && cfg["server_host"] != "" {
			*host = cfg["server_host"]
		}
		if !flagSet["port"] && cfg["server_port"] != "" {
			if v, err := strconv.Atoi(cfg["server_port"]); err == nil {
				*port = v
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
	if *host == "" {
		*host = "localhost"
	}
	if *port == 0 {
		*port = 8090
	}
	if *maxConcurrent <= 0 {
		*maxConcurrent = runtime.NumCPU() * 2
	}

	if (cmd == "sign" || cmd == "encrypt") && (*src == "" || *dest == "") {
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
		rect := normalizeRect(flashsign.Rectangle{X1: *x1, Y1: *y1, X2: *x2, Y2: *y2})
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

	case "serve", "server":
		d := serverDefaults{
			reason:   *reason,
			contact:  *contact,
			location: *location,
			page:     *page,
			visible:  *visible,
			rect:     normalizeRect(flashsign.Rectangle{X1: *x1, Y1: *y1, X2: *x2, Y2: *y2}),
		}
		if err := runServer(fmt.Sprintf("%s:%d", *host, *port), signer, d, *maxConcurrent); err != nil {
			fatal("serve: %v", err)
		}
	}
}

// maxRequestBodySize limits request body to 1MB to prevent DoS.
const maxRequestBodySize = 1 << 20

func runServer(addr string, signer *flashsign.Signer, defaults serverDefaults, maxConcurrent int) error {
	sem := make(chan struct{}, maxConcurrent)

	mux := http.NewServeMux()

	// Health endpoint for load balancer checks.
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		io.WriteString(w, "ok")
	})

	mux.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		send := func(code int, body string) {
			w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
			w.WriteHeader(code)
			if body != "" {
				io.WriteString(w, body)
			}
		}

		if r.Method != http.MethodPost {
			send(http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		// Acquire concurrency semaphore.
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		default:
			send(http.StatusServiceUnavailable, "server busy, try again later")
			return
		}

		// Read body with size limit.
		body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodySize+1))
		if err != nil {
			send(http.StatusInternalServerError, "read body: "+err.Error())
			return
		}
		if int64(len(body)) > maxRequestBodySize {
			send(http.StatusRequestEntityTooLarge, "request body too large")
			return
		}

		var req signRequest
		if err := json.Unmarshal(body, &req); err != nil {
			send(http.StatusInternalServerError, err.Error())
			return
		}
		if req.InputFile == "" || req.OutputFile == "" {
			send(http.StatusInternalServerError, "input_file and output_file are required")
			return
		}

		reason := strings.TrimSpace(req.Reason)
		if reason == "" {
			reason = defaults.reason
		}
		contact := strings.TrimSpace(req.Contact)
		if contact == "" {
			contact = defaults.contact
		}
		location := strings.TrimSpace(req.Location)
		if location == "" {
			location = defaults.location
		}

		page := defaults.page
		if req.Page != nil && *req.Page > 0 {
			page = *req.Page
		}

		visible := defaults.visible
		rect := defaults.rect
		if req.Coordinates.valid() {
			rect = flashsign.Rectangle{
				X1: *req.Coordinates.X1,
				Y1: *req.Coordinates.Y1,
				X2: *req.Coordinates.X2,
				Y2: *req.Coordinates.Y2,
			}
			visible = true
		}
		rect = normalizeRect(rect)

		params := flashsign.SignParams{
			Src:      req.InputFile,
			Dest:     req.OutputFile,
			Reason:   reason,
			Contact:  contact,
			Location: location,
			Page:     page,
		}
		if visible {
			v := true
			params.Visible = &v
			params.Rect = &rect
		}

		if strings.TrimSpace(req.Password) != "" {
			err = signer.SignAndEncrypt(params, flashsign.EncryptParams{Password: req.Password})
		} else {
			err = signer.Sign(params)
		}
		if err != nil {
			send(http.StatusInternalServerError, err.Error())
			return
		}

		send(http.StatusOK, "")
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	errCh := make(chan error, 1)
	go func() {
		fmt.Printf("flashsign server listening on %s (max-concurrent: %d)\n", addr, maxConcurrent)
		errCh <- srv.ListenAndServe()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		fmt.Printf("\nreceived %s, shutting down...\n", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	case err := <-errCh:
		return err
	}
}

func normalizeRect(rect flashsign.Rectangle) flashsign.Rectangle {
	if rect.X1 > rect.X2 {
		rect.X1, rect.X2 = rect.X2, rect.X1
	}
	if rect.Y1 > rect.Y2 {
		rect.Y1, rect.Y2 = rect.Y2, rect.Y1
	}
	return rect
}

// maybeRunCompatServerFromDefaultConfig preserves jpdfsigner's startup behavior:
// if config.ini exists and has server=true, start the HTTP server with no args.
func maybeRunCompatServerFromDefaultConfig() (bool, error) {
	const cfgPath = "config.ini"
	if _, err := os.Stat(cfgPath); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return false, err
	}

	serverEnabled, err := strconv.ParseBool(strings.TrimSpace(cfg["server"]))
	if err != nil || !serverEnabled {
		return false, nil
	}

	pfxPath := resolvePathFromConfig(cfgPath, cfg["keyfile"], "")
	certPath := resolvePathFromConfig(cfgPath, cfg["cert"], "")
	keyPath := resolvePathFromConfig(cfgPath, cfg["key"], "")

	signer, err := buildSigner(pfxPath, cfg["password"], certPath, keyPath)
	if err != nil {
		return false, err
	}

	page := 1
	if v, err := strconv.Atoi(cfg["page"]); err == nil && v > 0 {
		page = v
	}

	visible := false
	if v, err := strconv.ParseBool(cfg["visible"]); err == nil {
		visible = v
	}

	rect := flashsign.Rectangle{}
	coordSet := false
	if v, err := strconv.ParseFloat(cfg["x1"], 64); err == nil {
		rect.X1 = v
		coordSet = true
	}
	if v, err := strconv.ParseFloat(cfg["y1"], 64); err == nil {
		rect.Y1 = v
		coordSet = true
	}
	if v, err := strconv.ParseFloat(cfg["x2"], 64); err == nil {
		rect.X2 = v
		coordSet = true
	}
	if v, err := strconv.ParseFloat(cfg["y2"], 64); err == nil {
		rect.Y2 = v
		coordSet = true
	}
	if coordSet {
		visible = true
	}

	host := strings.TrimSpace(cfg["server_host"])
	if host == "" {
		host = "localhost"
	}
	port := 8090
	if v, err := strconv.Atoi(cfg["server_port"]); err == nil && v > 0 {
		port = v
	}

	maxConcurrent := runtime.NumCPU() * 2

	defaults := serverDefaults{
		reason:   cfg["reason"],
		contact:  cfg["contact"],
		location: cfg["location"],
		page:     page,
		visible:  visible,
		rect:     normalizeRect(rect),
	}
	return true, runServer(fmt.Sprintf("%s:%d", host, port), signer, defaults, maxConcurrent)
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

func resolvePathFromConfig(configPath, pathVal, srcPath string) string {
	pathVal = strings.TrimSpace(pathVal)
	if pathVal == "" || filepath.IsAbs(pathVal) {
		return pathVal
	}

	candidates := make([]string, 0, 4)

	cfgDir := strings.TrimSpace(filepath.Dir(configPath))
	if cfgDir != "" {
		candidates = append(candidates, filepath.Join(cfgDir, pathVal))
	}

	if wd, err := os.Getwd(); err == nil && wd != "" {
		candidates = append(candidates, filepath.Join(wd, pathVal))
	}

	srcDir := strings.TrimSpace(filepath.Dir(srcPath))
	if srcPath != "" && srcDir != "" && srcDir != "." {
		candidates = append(candidates, filepath.Join(srcDir, pathVal))
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}

	// Keep stable default behavior if none of the candidates exist.
	if cfgDir != "" {
		return filepath.Join(cfgDir, pathVal)
	}
	return pathVal
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
