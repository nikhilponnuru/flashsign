package flashsign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBuildCMSSignatureRSA(t *testing.T) {
	certPEM, err := os.ReadFile(filepath.Join("testdata", "test-cert.pem"))
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join("testdata", "test-key.pem"))
	if err != nil {
		t.Fatalf("read key: %v", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	pk, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	rsaKey, ok := pk.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected RSA key, got %T", pk)
	}

	signer, err := NewSigner(Config{
		Key:   rsaKey,
		Chain: []*x509.Certificate{cert},
	})
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	hash := sha256.Sum256([]byte("test"))
	sig, err := signer.buildCMSSignature(hash[:], time.Now().UTC())
	if err != nil {
		t.Fatalf("buildCMSSignature: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("signature is empty")
	}
	if sig[0] != 0x30 {
		t.Fatalf("expected ASN.1 SEQUENCE (0x30), got 0x%X", sig[0])
	}
}

func TestBuildCMSSignatureECDSA(t *testing.T) {
	// Generate ephemeral ECDSA key pair for testing.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}

	// Create a self-signed cert.
	template := &x509.Certificate{
		SerialNumber: mustBigInt("123456"),
	}
	template.Subject.CommonName = "ECDSA Test"
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &ecKey.PublicKey, ecKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	signer, err := NewSigner(Config{
		Key:   ecKey,
		Chain: []*x509.Certificate{cert},
	})
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	hash := sha256.Sum256([]byte("test"))
	sig, err := signer.buildCMSSignature(hash[:], time.Now().UTC())
	if err != nil {
		t.Fatalf("buildCMSSignature (ECDSA): %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("signature is empty")
	}
	if sig[0] != 0x30 {
		t.Fatalf("expected ASN.1 SEQUENCE (0x30), got 0x%X", sig[0])
	}
}

func mustBigInt(s string) *big.Int {
	n := new(big.Int)
	n.SetString(s, 10)
	return n
}
