package flashsign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/pkcs12"
	pkcs12modern "software.sslmate.com/src/go-pkcs12"
)

// NewSignerFromPFX loads a signer from a PKCS#12 (PFX) file.
func NewSignerFromPFX(pfxPath string, password string) (*Signer, error) {
	pfxData, err := os.ReadFile(pfxPath)
	if err != nil {
		return nil, fmt.Errorf("read pfx file: %w", err)
	}

	key, cert, err := pkcs12.Decode(pfxData, password)
	if err != nil {
		fallbackKey, fallbackCert, caCerts, fallbackErr := pkcs12modern.DecodeChain(pfxData, password)
		if fallbackErr != nil {
			return nil, fmt.Errorf("decode pfx: %w", err)
		}

		chain := make([]*x509.Certificate, 0, 1+len(caCerts))
		chain = append(chain, fallbackCert)
		chain = append(chain, caCerts...)

		return NewSigner(Config{
			Key:   fallbackKey,
			Chain: chain,
		})
	}

	return NewSigner(Config{
		Key:   key,
		Chain: []*x509.Certificate{cert},
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

	s := &Signer{cfg: cfg}

	// Detect key type and set parameters.
	switch k := cfg.Key.(type) {
	case *rsa.PrivateKey:
		k.Precompute()
		s.keyType = keyTypeRSA
		s.sigMaxLen = k.Size() // key size in bytes = max signature size
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			s.keyType = keyTypeECDSAP256
			s.sigMaxLen = 72 // max DER-encoded ECDSA-P256 signature
		case elliptic.P384():
			s.keyType = keyTypeECDSAP384
			s.sigMaxLen = 104 // max DER-encoded ECDSA-P384 signature
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

	return s, nil
}
