package flashsign

import (
	"path/filepath"
	"testing"
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
