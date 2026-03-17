package flashsign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"
)

// ASN.1 Object Identifiers used in the CMS/PKCS#7 SignedData structure.
var (
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidECDSASHA256   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSASHA384   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
)

// Pre-computed DER encodings for constant structures, computed at init.
var (
	derVersion1       []byte // INTEGER 1
	derNullParams     []byte // NULL
	derOIDData        []byte // OID encoding of id-data
	derOIDSignedData  []byte // OID encoding of id-signedData
	derOIDSHA256      []byte // OID encoding of SHA-256
	derOIDSHA384      []byte // OID encoding of SHA-384
	derOIDRSA         []byte // OID encoding of RSA
	derOIDECDSASHA256 []byte // OID encoding of ecdsa-with-SHA256
	derOIDECDSASHA384 []byte // OID encoding of ecdsa-with-SHA384
	derOIDContentType []byte // OID encoding of contentType
	derOIDMsgDigest   []byte // OID encoding of messageDigest
	derOIDSigningTime []byte // OID encoding of signingTime
)

func init() {
	var err error
	derVersion1, err = asn1.Marshal(1)
	if err != nil {
		panic("flashsign: marshal version: " + err.Error())
	}
	derNullParams, err = asn1.Marshal(asn1.RawValue{Tag: asn1.TagNull})
	if err != nil {
		panic("flashsign: marshal null: " + err.Error())
	}
	derOIDData, _ = asn1.Marshal(oidData)
	derOIDSignedData, _ = asn1.Marshal(oidSignedData)
	derOIDSHA256, _ = asn1.Marshal(oidSHA256)
	derOIDSHA384, _ = asn1.Marshal(oidSHA384)
	derOIDRSA, _ = asn1.Marshal(oidRSAEncryption)
	derOIDECDSASHA256, _ = asn1.Marshal(oidECDSASHA256)
	derOIDECDSASHA384, _ = asn1.Marshal(oidECDSASHA384)
	derOIDContentType, _ = asn1.Marshal(oidContentType)
	derOIDMsgDigest, _ = asn1.Marshal(oidMessageDigest)
	derOIDSigningTime, _ = asn1.Marshal(oidSigningTime)
}

// DER encoding helpers that work with append semantics.

func appendDERLength(buf []byte, length int) []byte {
	if length < 128 {
		return append(buf, byte(length))
	}
	if length < 256 {
		return append(buf, 0x81, byte(length))
	}
	if length < 65536 {
		return append(buf, 0x82, byte(length>>8), byte(length))
	}
	return append(buf, 0x83, byte(length>>16), byte(length>>8), byte(length))
}

func appendDERSequence(buf []byte, content []byte) []byte {
	buf = append(buf, 0x30) // SEQUENCE tag
	buf = appendDERLength(buf, len(content))
	return append(buf, content...)
}

func appendDERSet(buf []byte, content []byte) []byte {
	buf = append(buf, 0x31) // SET tag
	buf = appendDERLength(buf, len(content))
	return append(buf, content...)
}

func appendDEROctetString(buf []byte, data []byte) []byte {
	buf = append(buf, 0x04) // OCTET STRING tag
	buf = appendDERLength(buf, len(data))
	return append(buf, data...)
}

func appendDERContextTag(buf []byte, tag int, content []byte, constructed bool) []byte {
	tagByte := byte(0x80 | tag) // context-specific
	if constructed {
		tagByte |= 0x20
	}
	buf = append(buf, tagByte)
	buf = appendDERLength(buf, len(content))
	return append(buf, content...)
}

func derLength(length int) int {
	if length < 128 {
		return 1
	}
	if length < 256 {
		return 2
	}
	if length < 65536 {
		return 3
	}
	return 4
}

// precomputeCMS builds all constant CMS DER fragments at Signer creation time.
func (s *Signer) precomputeCMS() error {
	cert := s.cfg.Chain[0]

	// issuerAndSerialNumber: SEQUENCE { issuer RDN, serial INTEGER }
	serialDER, err := asn1.Marshal(cert.SerialNumber)
	if err != nil {
		return err
	}
	issContent := make([]byte, 0, len(cert.RawIssuer)+len(serialDER))
	issContent = append(issContent, cert.RawIssuer...)
	issContent = append(issContent, serialDER...)
	s.issuerSerialDER = appendDERSequence(nil, issContent)

	// digestAlgorithm: SEQUENCE { digest OID, NULL }
	digestOID := derOIDSHA256
	if s.keyType == keyTypeECDSAP384 {
		digestOID = derOIDSHA384
	}
	algContent := make([]byte, 0, len(digestOID)+len(derNullParams))
	algContent = append(algContent, digestOID...)
	algContent = append(algContent, derNullParams...)
	s.digestAlgDER = appendDERSequence(nil, algContent)

	// digestEncryptionAlgorithm: depends on key type
	switch s.keyType {
	case keyTypeRSA:
		encContent := make([]byte, 0, len(derOIDRSA)+len(derNullParams))
		encContent = append(encContent, derOIDRSA...)
		encContent = append(encContent, derNullParams...)
		s.digestEncAlgDER = appendDERSequence(nil, encContent)
	case keyTypeECDSAP256:
		// ECDSA algorithms have no parameters (absent, not NULL)
		s.digestEncAlgDER = appendDERSequence(nil, derOIDECDSASHA256)
	case keyTypeECDSAP384:
		s.digestEncAlgDER = appendDERSequence(nil, derOIDECDSASHA384)
	}

	// digestAlgorithms SET: SET { digestAlgDER }
	s.digestAlgSetDER = appendDERSet(nil, s.digestAlgDER)

	// contentInfo: SEQUENCE { id-data OID }
	s.contentInfoDER = appendDERSequence(nil, derOIDData)

	// certificates: [0] IMPLICIT CONSTRUCTED { cert chain DER }
	s.certTagDER = appendDERContextTag(nil, 0, s.certBytesDER, true)

	// Pre-computed contentType attribute:
	// SEQUENCE { OID(contentType), SET { OID(data) } }
	ctAttrContent := make([]byte, 0, len(derOIDContentType)+2+len(derOIDData))
	ctAttrContent = append(ctAttrContent, derOIDContentType...)
	ctAttrContent = appendDERSet(ctAttrContent, derOIDData)
	s.contentTypeAttr = appendDERSequence(nil, ctAttrContent)

	// OID for outer wrapper
	s.oidSignedData = derOIDSignedData

	return nil
}

// buildCMSSignature creates a DER-encoded CMS SignedData structure.
func (s *Signer) buildCMSSignature(contentHash []byte, signingTime time.Time) ([]byte, error) {
	// Build messageDigest attribute:
	// SEQUENCE { OID(messageDigest), SET { OCTET STRING(hash) } }
	mdValue := appendDEROctetString(nil, contentHash)
	mdAttrContent := make([]byte, 0, len(derOIDMsgDigest)+2+len(mdValue))
	mdAttrContent = append(mdAttrContent, derOIDMsgDigest...)
	mdAttrContent = appendDERSet(mdAttrContent, mdValue)
	mdAttr := appendDERSequence(nil, mdAttrContent)

	// Build signingTime attribute:
	// SEQUENCE { OID(signingTime), SET { UTCTime(time) } }
	timeDER, err := asn1.Marshal(signingTime.UTC())
	if err != nil {
		return nil, err
	}
	stAttrContent := make([]byte, 0, len(derOIDSigningTime)+2+len(timeDER))
	stAttrContent = append(stAttrContent, derOIDSigningTime...)
	stAttrContent = appendDERSet(stAttrContent, timeDER)
	stAttr := appendDERSequence(nil, stAttrContent)

	// Concatenate attributes in DER-sorted order.
	// The OIDs sort as: contentType (.9.3) < messageDigest (.9.4) < signingTime (.9.5),
	// so the order is always: contentTypeAttr, mdAttr, stAttr.
	attrSetContent := make([]byte, 0, len(s.contentTypeAttr)+len(mdAttr)+len(stAttr))
	attrSetContent = append(attrSetContent, s.contentTypeAttr...)
	attrSetContent = append(attrSetContent, mdAttr...)
	attrSetContent = append(attrSetContent, stAttr...)

	// Build the SET wrapper for hashing (uses SET tag 0x31).
	attrSetDER := appendDERSet(nil, attrSetContent)

	// Hash the attribute SET for signing with the same digest as SignerInfo.digestAlgorithm.
	var attrHash []byte
	if s.keyType == keyTypeECDSAP384 {
		sum := sha512.Sum384(attrSetDER)
		attrHash = sum[:]
	} else {
		sum := sha256.Sum256(attrSetDER)
		attrHash = sum[:]
	}

	// Sign the hash.
	sig, err := s.signHash(attrHash)
	if err != nil {
		return nil, err
	}

	// Build signerInfo SEQUENCE content.
	siContent := make([]byte, 0, 512)
	siContent = append(siContent, derVersion1...)
	siContent = append(siContent, s.issuerSerialDER...)
	siContent = append(siContent, s.digestAlgDER...)
	// [0] IMPLICIT CONSTRUCTED: authenticated attributes
	siContent = appendDERContextTag(siContent, 0, attrSetContent, true)
	siContent = append(siContent, s.digestEncAlgDER...)
	siContent = appendDEROctetString(siContent, sig)

	// Wrap in SEQUENCE.
	siDER := appendDERSequence(nil, siContent)

	// Build signerInfos SET.
	siSetDER := appendDERSet(nil, siDER)

	// Build signedData SEQUENCE content.
	sdContent := make([]byte, 0, len(s.digestAlgSetDER)+len(s.contentInfoDER)+len(s.certTagDER)+len(siSetDER)+16)
	sdContent = append(sdContent, derVersion1...)
	sdContent = append(sdContent, s.digestAlgSetDER...)
	sdContent = append(sdContent, s.contentInfoDER...)
	sdContent = append(sdContent, s.certTagDER...)
	sdContent = append(sdContent, siSetDER...)

	// Wrap in SEQUENCE.
	sdDER := appendDERSequence(nil, sdContent)

	// Build [0] EXPLICIT wrapper for signedData.
	explicitContent := appendDERContextTag(nil, 0, sdDER, true)

	// Build outer ContentInfo SEQUENCE.
	ciContent := make([]byte, 0, len(s.oidSignedData)+len(explicitContent))
	ciContent = append(ciContent, s.oidSignedData...)
	ciContent = append(ciContent, explicitContent...)

	return appendDERSequence(nil, ciContent), nil
}

// signHash signs a SHA-256 hash using the signer's private key.
func (s *Signer) signHash(hash []byte) ([]byte, error) {
	switch s.keyType {
	case keyTypeRSA:
		key, ok := s.cfg.Key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("key type mismatch: expected RSA")
		}
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash)
	case keyTypeECDSAP256, keyTypeECDSAP384:
		key, ok := s.cfg.Key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("key type mismatch: expected ECDSA")
		}
		return ecdsa.SignASN1(rand.Reader, key, hash)
	default:
		return nil, errors.New("unsupported key type")
	}
}

// compareDER compares two DER-encoded byte slices lexicographically.
func compareDER(a, b []byte) int {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	for i := 0; i < minLen; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}

// ASN.1 types used only for issuerAndSerialNumber pre-computation.
type issuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}
