// Package flashsign provides high-performance PDF digital signing using PKCS#7
// detached signatures. It is a drop-in replacement for that eliminates
// the pdfcpu dependency from the hot path, supports ECDSA keys, and uses zero-alloc
// incremental update building.
//
// Three signing paths are provided:
//
//   - Sign: file-to-file convenience method
//   - SignStream: streaming I/O with seekable input
//   - SignBytes: in-memory operation on byte slices (fastest)
//
// All methods are safe for concurrent use.
package flashsign

import (
	"crypto"
	"crypto/x509"
)

// Rectangle defines the position of the visible signature box on a page.
// Coordinates use PDF coordinate system: (0,0) at bottom-left of page.
type Rectangle struct {
	X1, Y1, X2, Y2 float64
}

// Config holds the signer's certificate and default signature metadata.
type Config struct {
	// Certificate and key (required). Key can be *rsa.PrivateKey or *ecdsa.PrivateKey.
	Key   crypto.PrivateKey
	Chain []*x509.Certificate // Chain[0] = signer cert, rest = intermediates

	// Default signature metadata (can be overridden per-document in SignParams)
	Reason   string
	Contact  string
	Location string

	// Default visible signature settings
	Page    int       // 1-indexed page number (default: 1)
	Rect    Rectangle // Signature box coordinates
	Visible bool      // Whether to render a visible signature box
}

// SignParams holds per-document signing parameters.
// Zero values mean "use Config defaults".
type SignParams struct {
	Src  string // Input PDF file path (used by Sign and SignAndEncrypt)
	Dest string // Output PDF file path (used by Sign and SignAndEncrypt)

	// Optional per-document overrides
	Reason   string     // Override Config.Reason
	Contact  string     // Override Config.Contact
	Location string     // Override Config.Location
	Page     int        // Override Config.Page
	Rect     *Rectangle // Override Config.Rect (nil = use default)
	Visible  *bool      // Override Config.Visible (nil = use default)
}

// EncryptParams holds encryption parameters for SignAndEncrypt.
type EncryptParams struct {
	Password string // User and owner password for AES encryption (required)
	AES256   bool   // Use AES-256 instead of AES-128 (default: false)
}

// BatchItem represents a single PDF to sign in a batch operation.
type BatchItem struct {
	PDFData []byte     // Input PDF bytes
	Params  SignParams // Signing parameters
	Result  []byte     // Populated on success
	Err     error      // Populated on failure
}

const (
	keyTypeRSA       = 0
	keyTypeECDSAP256 = 1
	keyTypeECDSAP384 = 2
)

// Signer signs PDF documents with PKCS#7 digital signatures.
type Signer struct {
	cfg Config

	// Pre-computed values set at creation time.
	certBytesDER  []byte // DER-encoded certificate chain bytes
	signerNameStr string // human-readable signer name
	keyType       int    // keyTypeRSA, keyTypeECDSAP256, keyTypeECDSAP384
	sigMaxLen     int    // max raw signature bytes

	// Pre-computed CMS/DER fragments for zero-marshal signing.
	issuerSerialDER []byte // pre-encoded issuerAndSerialNumber
	digestAlgDER    []byte // SEQUENCE { SHA-256 OID, NULL }
	digestEncAlgDER []byte // SEQUENCE { RSA/ECDSA OID, params }
	digestAlgSetDER []byte // SET { digestAlgDER }
	contentInfoDER  []byte // SEQUENCE { id-data OID }
	certTagDER      []byte // [0] IMPLICIT { cert chain DER }
	contentTypeAttr []byte // pre-encoded contentType attribute DER
	oidSignedData   []byte // OID encoding of id-signedData

	// Per-signer reserved hex placeholder for /Contents.
	contentsPlaceholderLen int
	contentsZeros          []byte
}
