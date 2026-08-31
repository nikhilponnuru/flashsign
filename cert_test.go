package flashsign

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestNewSignerFromPFX(t *testing.T) {
	signer, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), "test123")
	if err != nil {
		t.Fatalf("NewSignerFromPFX returned error: %v", err)
	}
	if signer == nil {
		t.Fatal("NewSignerFromPFX returned nil signer")
	}
	if signer.keyType != keyTypeRSA {
		t.Fatalf("expected RSA key type, got %d", signer.keyType)
	}
}

func TestNewSignerFromPFXKeepsCertificateChain(t *testing.T) {
	pfxData, err := os.ReadFile(filepath.Join("testdata", "test.pfx"))
	if err != nil {
		t.Fatalf("read PFX: %v", err)
	}
	key, cert, _, err := pkcs12.DecodeChain(pfxData, testPFXPassword)
	if err != nil {
		t.Fatalf("decode fixture PFX: %v", err)
	}
	withChain, err := pkcs12.LegacyRC2.Encode(key, cert, []*x509.Certificate{cert}, testPFXPassword)
	if err != nil {
		t.Fatalf("encode chained PFX: %v", err)
	}
	path := filepath.Join(t.TempDir(), "chain.pfx")
	if err := os.WriteFile(path, withChain, 0o600); err != nil {
		t.Fatalf("write chained PFX: %v", err)
	}

	signer, err := NewSignerFromPFX(path, testPFXPassword)
	if err != nil {
		t.Fatalf("NewSignerFromPFX: %v", err)
	}
	if got := len(signer.cfg.Chain); got != 2 {
		t.Fatalf("certificate chain length = %d, want 2", got)
	}
}

func TestNewSignerRejectsNilAndMismatchedCertificate(t *testing.T) {
	certPEM, err := os.ReadFile(filepath.Join("testdata", "test-cert.pem"))
	if err != nil {
		t.Fatalf("read certificate: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	if _, err := NewSigner(Config{Key: &rsa.PrivateKey{}, Chain: []*x509.Certificate{nil}}); err == nil {
		t.Fatal("NewSigner accepted a nil signer certificate")
	}

	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate mismatched key: %v", err)
	}
	if _, err := NewSigner(Config{Key: other, Chain: []*x509.Certificate{cert}}); err == nil {
		t.Fatal("NewSigner accepted a private key that does not match the signer certificate")
	}
}

func TestNewSignerFromPEM(t *testing.T) {
	signer, err := NewSignerFromPEM(
		filepath.Join("testdata", "test-cert.pem"),
		filepath.Join("testdata", "test-key.pem"),
	)
	if err != nil {
		t.Fatalf("NewSignerFromPEM returned error: %v", err)
	}
	if signer == nil {
		t.Fatal("NewSignerFromPEM returned nil signer")
	}
}

func TestNewSignerFromPEMECDSA(t *testing.T) {
	signer, err := NewSignerFromPEM(
		filepath.Join("testdata", "test-ec-cert.pem"),
		filepath.Join("testdata", "test-ec-key.pem"),
	)
	if err != nil {
		t.Fatalf("NewSignerFromPEM (ECDSA) returned error: %v", err)
	}
	if signer == nil {
		t.Fatal("NewSignerFromPEM returned nil signer")
	}
	if signer.keyType != keyTypeECDSAP256 {
		t.Fatalf("expected ECDSA-P256 key type, got %d", signer.keyType)
	}
}

func TestNewSignerFromPFXBadPassword(t *testing.T) {
	if _, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), "wrong-password"); err == nil {
		t.Fatal("expected error for bad password, got nil")
	}
}

func TestNewSignerFromPFXMissingFile(t *testing.T) {
	if _, err := NewSignerFromPFX(filepath.Join("testdata", "does-not-exist.pfx"), "test123"); err == nil {
		t.Fatal("expected error for missing PFX file, got nil")
	}
}

func TestNewSignerFromPEMMissingFile(t *testing.T) {
	if _, err := NewSignerFromPEM(filepath.Join("testdata", "missing-cert.pem"), filepath.Join("testdata", "missing-key.pem")); err == nil {
		t.Fatal("expected error for missing PEM files, got nil")
	}
}

func TestAdaptiveContentsPlaceholder(t *testing.T) {
	signer, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), "test123")
	if err != nil {
		t.Fatalf("NewSignerFromPFX returned error: %v", err)
	}

	if signer.contentsPlaceholderLen < minContentsPlaceholderLen {
		t.Fatalf("placeholder too small: got=%d min=%d", signer.contentsPlaceholderLen, minContentsPlaceholderLen)
	}
	if signer.contentsPlaceholderLen > defaultContentsPlaceholderLen {
		t.Fatalf("placeholder unexpectedly larger than default: got=%d default=%d", signer.contentsPlaceholderLen, defaultContentsPlaceholderLen)
	}
	if signer.contentsPlaceholderLen%placeholderRoundUpHex != 0 {
		t.Fatalf("placeholder should be rounded to %d, got=%d", placeholderRoundUpHex, signer.contentsPlaceholderLen)
	}

	digest := make([]byte, 32)
	sig, err := signer.buildCMSSignature(digest, time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("buildCMSSignature returned error: %v", err)
	}
	if len(sig)*2 > signer.contentsPlaceholderLen {
		t.Fatalf("signature does not fit placeholder: sigHex=%d placeholder=%d", len(sig)*2, signer.contentsPlaceholderLen)
	}
}

// TestAdaptiveContentsPlaceholderLargePFX checks that a real, large certificate
// chain still fits the signature placeholder. It needs a production PFX, whose
// password must never live in the repository, so both the file and the
// FLASHSIGN_TEST_PFX_PASSWORD environment variable are required:
//
//	FLASHSIGN_TEST_PFX_PASSWORD=... go test -run LargePFX ./...
func TestAdaptiveContentsPlaceholderLargePFX(t *testing.T) {
	pfxPath := filepath.Join("testdata", "signing.pfx")
	if _, err := os.Stat(pfxPath); err != nil {
		t.Skip("signing.pfx not available")
	}
	password := os.Getenv("FLASHSIGN_TEST_PFX_PASSWORD")
	if password == "" {
		t.Skip("FLASHSIGN_TEST_PFX_PASSWORD not set")
	}

	signer, err := NewSignerFromPFX(pfxPath, password)
	if err != nil {
		t.Fatalf("NewSignerFromPFX returned error: %v", err)
	}

	digest := make([]byte, 32)
	sig, err := signer.buildCMSSignature(digest, time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("buildCMSSignature returned error: %v", err)
	}
	if len(sig)*2 > signer.contentsPlaceholderLen {
		t.Fatalf("large PFX signature does not fit placeholder: sigHex=%d placeholder=%d", len(sig)*2, signer.contentsPlaceholderLen)
	}
}
