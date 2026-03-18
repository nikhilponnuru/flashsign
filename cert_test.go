package flashsign

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestAdaptiveContentsPlaceholderLargePFX(t *testing.T) {
	pfxPath := filepath.Join("testdata", "Zerodha.pfx")
	if _, err := os.Stat(pfxPath); err != nil {
		t.Skip("Zerodha.pfx not available")
	}

	signer, err := NewSignerFromPFX(pfxPath, "Newton_90356%")
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
