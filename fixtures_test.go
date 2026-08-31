package flashsign

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// testdata/ holds production signing certificates and is therefore gitignored,
// so a fresh checkout — CI in particular — starts without any fixtures. Every
// fixture the suite needs is synthesisable, so TestMain generates the missing
// ones as self-signed stand-ins. Files that already exist are never
// overwritten, which keeps a working copy holding the real fixtures on those.
//
// testdata/signing.pfx is the one exception: it is a real certificate and
// cannot be synthesised, so the tests that need it skip when it is absent.
const (
	testDataDir     = "testdata"
	testPFXPassword = "test123"
)

func TestMain(m *testing.M) {
	if err := ensureTestFixtures(); err != nil {
		fmt.Fprintf(os.Stderr, "flashsign: generate test fixtures: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func ensureTestFixtures() error {
	if err := os.MkdirAll(testDataDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", testDataDir, err)
	}
	if err := ensureRSAFixtures(); err != nil {
		return err
	}
	if err := ensureECDSAFixtures(); err != nil {
		return err
	}
	return ensurePDFFixtures()
}

// writeIfMissing writes the bytes produced by gen to testDataDir/name unless
// the file already exists. gen runs only when the file is missing.
func writeIfMissing(name string, gen func() ([]byte, error)) error {
	if !fixtureMissing(name) {
		return nil
	}
	data, err := gen()
	if err != nil {
		return fmt.Errorf("generate %s: %w", name, err)
	}
	path := filepath.Join(testDataDir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func fixtureMissing(name string) bool {
	_, err := os.Stat(filepath.Join(testDataDir, name))
	return err != nil
}

// selfSignedCert issues a self-signed certificate usable for document signing.
func selfSignedCert(key crypto.Signer, commonName string) (*x509.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"FlashSign Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func encodePEM(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

// encodeKeyPEM marshals a private key as PKCS#8, which NewSignerFromPEM tries
// first.
func encodeKeyPEM(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return encodePEM("PRIVATE KEY", der), nil
}

func ensureRSAFixtures() error {
	const (
		certName = "test-cert.pem"
		keyName  = "test-key.pem"
		pfxName  = "test.pfx"
	)
	if !fixtureMissing(certName) && !fixtureMissing(keyName) && !fixtureMissing(pfxName) {
		return nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate RSA key: %w", err)
	}
	cert, err := selfSignedCert(key, "FlashSign RSA Test")
	if err != nil {
		return fmt.Errorf("issue RSA certificate: %w", err)
	}

	if err := writeIfMissing(certName, func() ([]byte, error) {
		return encodePEM("CERTIFICATE", cert.Raw), nil
	}); err != nil {
		return err
	}
	if err := writeIfMissing(keyName, func() ([]byte, error) {
		return encodeKeyPEM(key)
	}); err != nil {
		return err
	}
	// LegacyRC2 keeps the file readable by golang.org/x/crypto/pkcs12, the
	// decoder NewSignerFromPFX reaches for first, so the generated fixture
	// exercises the same path a real-world PFX does.
	return writeIfMissing(pfxName, func() ([]byte, error) {
		return pkcs12.LegacyRC2.Encode(key, cert, nil, testPFXPassword)
	})
}

func ensureECDSAFixtures() error {
	const (
		certName = "test-ec-cert.pem"
		keyName  = "test-ec-key.pem"
	)
	if !fixtureMissing(certName) && !fixtureMissing(keyName) {
		return nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ECDSA key: %w", err)
	}
	cert, err := selfSignedCert(key, "FlashSign ECDSA Test")
	if err != nil {
		return fmt.Errorf("issue ECDSA certificate: %w", err)
	}

	if err := writeIfMissing(certName, func() ([]byte, error) {
		return encodePEM("CERTIFICATE", cert.Raw), nil
	}); err != nil {
		return err
	}
	return writeIfMissing(keyName, func() ([]byte, error) {
		return encodeKeyPEM(key)
	})
}

func ensurePDFFixtures() error {
	// A plain single-page PDF with a classic xref table.
	if err := writeIfMissing("test.pdf", func() ([]byte, error) {
		return buildSinglePagePDF(10 * 1024), nil
	}); err != nil {
		return err
	}

	// A PDF whose catalog and pages live in object streams behind an xref
	// stream, exercising the parser's compressed-object resolution.
	return writeIfMissing("xrefstream-sample.pdf", func() ([]byte, error) {
		conf := model.NewDefaultConfiguration()
		conf.ValidationMode = model.ValidationRelaxed
		conf.ValidateLinks = false
		conf.WriteXRefStream = true
		conf.WriteObjectStream = true

		var out bytes.Buffer
		if err := api.Optimize(bytes.NewReader(buildSinglePagePDF(10*1024)), &out, conf); err != nil {
			return nil, err
		}
		return out.Bytes(), nil
	})
}
