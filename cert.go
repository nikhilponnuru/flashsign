package flashsign

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	pkcs12modern "software.sslmate.com/src/go-pkcs12"
)

// NewSignerFromPFX loads a signer from a PKCS#12 (PFX) file.
func NewSignerFromPFX(pfxPath string, password string) (*Signer, error) {
	pfxData, err := os.ReadFile(pfxPath)
	if err != nil {
		return nil, fmt.Errorf("read pfx file: %w", err)
	}

	key, cert, caCerts, err := pkcs12modern.DecodeChain(pfxData, password)
	if err != nil {
		return nil, fmt.Errorf("decode pfx: %w", err)
	}

	chain := make([]*x509.Certificate, 0, 1+len(caCerts))
	chain = append(chain, cert)
	chain = append(chain, caCerts...)

	return NewSigner(Config{
		Key:   key,
		Chain: chain,
	})
}

// NewSignerFromPEM loads a signer from PEM-encoded certificate and key files.
func NewSignerFromPEM(certPath string, keyPath string) (*Signer, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read certificate file: %w", err)
	}

	var chain []*x509.Certificate
	for len(certPEM) > 0 {
		var block *pem.Block
		block, certPEM = pem.Decode(certPEM)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("parse certificate: %w", parseErr)
		}
		chain = append(chain, cert)
	}

	if len(chain) == 0 {
		return nil, fmt.Errorf("no certificates found in PEM file")
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode key PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		rsaKey, pkcs1Err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if pkcs1Err != nil {
			ecKey, ecErr := x509.ParseECPrivateKey(keyBlock.Bytes)
			if ecErr != nil {
				return nil, fmt.Errorf("parse private key (PKCS#8, PKCS#1, EC all failed): %v; %v; %v", err, pkcs1Err, ecErr)
			}
			key = ecKey
		} else {
			key = rsaKey
		}
	}

	return NewSigner(Config{
		Key:   key,
		Chain: chain,
	})
}

// NewSigner creates a signer from an already-parsed configuration.
// Supports RSA and ECDSA (P-256, P-384) private keys.
func NewSigner(cfg Config) (*Signer, error) {
	if cfg.Key == nil {
		return nil, fmt.Errorf("private key is required")
	}
	if len(cfg.Chain) == 0 {
		return nil, fmt.Errorf("certificate chain must contain at least one certificate")
	}
	if cfg.Chain[0] == nil {
		return nil, fmt.Errorf("signer certificate must not be nil")
	}

	s := &Signer{cfg: cfg}
	if err := s.SetAppearance(cfg.Appearance); err != nil {
		return nil, err
	}

	// Detect key type and set parameters.
	switch k := cfg.Key.(type) {
	case *rsa.PrivateKey:
		if err := k.Validate(); err != nil {
			return nil, fmt.Errorf("invalid RSA private key: %w", err)
		}
		certKey, ok := cfg.Chain[0].PublicKey.(*rsa.PublicKey)
		if !ok || !certKey.Equal(&k.PublicKey) {
			return nil, fmt.Errorf("private key does not match signer certificate")
		}
		k.Precompute()
		s.keyType = keyTypeRSA
	case *ecdsa.PrivateKey:
		// ECDH() validates the key constant-time, rejecting an out-of-range
		// scalar; its derived public key comes from the scalar itself, so
		// comparing it against the certificate also catches stale X/Y fields.
		ek, err := k.ECDH()
		if err != nil {
			return nil, fmt.Errorf("invalid ECDSA private key: %w", err)
		}
		certKey, ok := cfg.Chain[0].PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("private key does not match signer certificate")
		}
		certEK, err := certKey.ECDH()
		if err != nil || !ek.PublicKey().Equal(certEK) {
			return nil, fmt.Errorf("private key does not match signer certificate")
		}
		switch k.Curve {
		case elliptic.P256():
			s.keyType = keyTypeECDSAP256
		case elliptic.P384():
			s.keyType = keyTypeECDSAP384
		default:
			return nil, fmt.Errorf("unsupported ECDSA curve: %v", k.Curve.Params().Name)
		}
	default:
		return nil, fmt.Errorf("unsupported key type: %T (need *rsa.PrivateKey or *ecdsa.PrivateKey)", cfg.Key)
	}

	// Pre-compute signer name.
	if len(cfg.Chain) > 0 && cfg.Chain[0] != nil {
		cert := cfg.Chain[0]
		if cert.Subject.CommonName != "" {
			s.signerNameStr = cert.Subject.CommonName
		} else if len(cert.Subject.Organization) > 0 {
			s.signerNameStr = cert.Subject.Organization[0]
		} else {
			s.signerNameStr = cert.SerialNumber.String()
		}
	}

	// Pre-compute DER-encoded certificate chain.
	var totalLen int
	for _, cert := range cfg.Chain {
		if cert != nil {
			totalLen += len(cert.Raw)
		}
	}
	s.certBytesDER = make([]byte, 0, totalLen)
	for _, cert := range cfg.Chain {
		if cert != nil {
			s.certBytesDER = append(s.certBytesDER, cert.Raw...)
		}
	}

	// Pre-compute all CMS DER fragments.
	if err := s.precomputeCMS(); err != nil {
		return nil, fmt.Errorf("precompute CMS: %w", err)
	}

	// Size /Contents placeholder adaptively per certificate/key while keeping
	// a conservative safety margin.
	s.initContentsPlaceholder()

	return s, nil
}

func (s *Signer) initContentsPlaceholder() {
	s.contentsPlaceholderLen = defaultContentsPlaceholderLen

	hashLen := 32
	if s.keyType == keyTypeECDSAP384 {
		hashLen = 48
	}
	digest := make([]byte, hashLen)

	// Best-effort sizing; fallback to default on any failure.
	if sig, err := s.buildCMSSignature(digest, time.Unix(0, 0).UTC()); err == nil {
		need := len(sig)*2 + placeholderSafetyMarginHex
		if need < minContentsPlaceholderLen {
			need = minContentsPlaceholderLen
		}
		// Round up so future variation (eg, ECDSA DER length) still fits.
		if rem := need % placeholderRoundUpHex; rem != 0 {
			need += placeholderRoundUpHex - rem
		}
		s.contentsPlaceholderLen = need
	}

	s.contentsZeros = bytes.Repeat([]byte("0"), s.contentsPlaceholderLen)
}

// SetAppearance changes the visible signature text style. Call it before the
// signer is shared between goroutines; NewSignerFromPFX and NewSignerFromPEM
// use the default (Java signer) style.
func (s *Signer) SetAppearance(a Appearance) error {
	st, err := resolveAppearance(a)
	if err != nil {
		return err
	}
	s.appearance = st
	return nil
}
