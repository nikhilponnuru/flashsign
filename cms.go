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
	"sync"
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

// cmsPool provides reusable scratch buffers for buildCMSSignature.
var cmsPool = sync.Pool{New: func() any {
	b := make([]byte, 0, 8192)
	return &b
}}

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

// derTLVLen returns the total DER-encoded size of a tag-length-value element.
func derTLVLen(contentLen int) int {
	return 1 + derLength(contentLen) + contentLen
}

// appendUTCTime appends a DER-encoded UTCTime (tag 0x17) for the given time.
// Format: YYMMDDHHMMSSZ (13 content bytes, 15 total). Zero allocations.
func appendUTCTime(buf []byte, t time.Time) []byte {
	t = t.UTC()
	y, mo, d := t.Date()
	hh, mm, ss := t.Clock()
	yy := y % 100
	return append(buf,
		0x17, 0x0D, // tag + length(13)
		byte('0'+yy/10), byte('0'+yy%10),
		byte('0'+int(mo)/10), byte('0'+int(mo)%10),
		byte('0'+d/10), byte('0'+d%10),
		byte('0'+hh/10), byte('0'+hh%10),
		byte('0'+mm/10), byte('0'+mm%10),
		byte('0'+ss/10), byte('0'+ss%10),
		'Z',
	)
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
// Uses a pooled scratch buffer for near-zero allocations.
// Only allocations: signHash return (crypto library) + final result copy.
func (s *Signer) buildCMSSignature(contentHash []byte, signingTime time.Time) ([]byte, error) {
	hashLen := len(contentHash)

	// Pre-compute all DER sizes bottom-up.

	// messageDigest attribute: SEQUENCE { OID, SET { OCTET STRING(hash) } }
	mdValueLen := derTLVLen(hashLen)             // OCTET STRING
	mdSetLen := derTLVLen(mdValueLen)            // SET { ... }
	mdAttrContentLen := len(derOIDMsgDigest) + mdSetLen
	mdAttrLen := derTLVLen(mdAttrContentLen) // SEQUENCE

	// signingTime attribute: SEQUENCE { OID, SET { UTCTime } }
	const utcTimeLen = 15                           // tag(1) + len(1) + 13 chars
	stSetLen := derTLVLen(utcTimeLen)               // SET { UTCTime }
	stAttrContentLen := len(derOIDSigningTime) + stSetLen
	stAttrLen := derTLVLen(stAttrContentLen) // SEQUENCE

	// Attribute set content (sorted by OID: contentType < messageDigest < signingTime)
	attrSetContentLen := len(s.contentTypeAttr) + mdAttrLen + stAttrLen

	// Get scratch buffer from pool.
	bp := cmsPool.Get().(*[]byte)
	scratch := (*bp)[:0]

	// Phase A: Write attrSetContent into scratch[0:attrSetContentLen].

	// contentType attribute (pre-computed)
	scratch = append(scratch, s.contentTypeAttr...)

	// messageDigest attribute
	scratch = append(scratch, 0x30) // SEQUENCE
	scratch = appendDERLength(scratch, mdAttrContentLen)
	scratch = append(scratch, derOIDMsgDigest...)
	scratch = append(scratch, 0x31) // SET
	scratch = appendDERLength(scratch, mdValueLen)
	scratch = append(scratch, 0x04) // OCTET STRING
	scratch = appendDERLength(scratch, hashLen)
	scratch = append(scratch, contentHash...)

	// signingTime attribute
	scratch = append(scratch, 0x30) // SEQUENCE
	scratch = appendDERLength(scratch, stAttrContentLen)
	scratch = append(scratch, derOIDSigningTime...)
	scratch = append(scratch, 0x31) // SET
	scratch = appendDERLength(scratch, utcTimeLen)
	scratch = appendUTCTime(scratch, signingTime)

	// Phase B: Write attrSetDER (SET wrapper + copy) for hashing.
	attrSetDERStart := len(scratch)
	attrSetDERLen := derTLVLen(attrSetContentLen)
	scratch = append(scratch, 0x31) // SET tag
	scratch = appendDERLength(scratch, attrSetContentLen)
	scratch = append(scratch, scratch[:attrSetContentLen]...) // copy attrSetContent
	attrSetDER := scratch[attrSetDERStart : attrSetDERStart+attrSetDERLen]

	// Phase C: Hash and sign.
	var attrHash []byte
	if s.keyType == keyTypeECDSAP384 {
		sum := sha512.Sum384(attrSetDER)
		attrHash = sum[:]
	} else {
		sum := sha256.Sum256(attrSetDER)
		attrHash = sum[:]
	}

	sig, err := s.signHash(attrHash)
	if err != nil {
		*bp = scratch
		cmsPool.Put(bp)
		return nil, err
	}

	// Phase D: Compute remaining sizes with known signature length.
	sigLen := len(sig)
	authAttrsLen := derTLVLen(attrSetContentLen)
	sigOctetLen := derTLVLen(sigLen)

	siContentLen := len(derVersion1) + len(s.issuerSerialDER) + len(s.digestAlgDER) +
		authAttrsLen + len(s.digestEncAlgDER) + sigOctetLen
	siDERLen := derTLVLen(siContentLen)
	siSetLen := derTLVLen(siDERLen)

	sdContentLen := len(derVersion1) + len(s.digestAlgSetDER) + len(s.contentInfoDER) +
		len(s.certTagDER) + siSetLen
	sdDERLen := derTLVLen(sdContentLen)
	explicitLen := derTLVLen(sdDERLen)
	ciContentLen := len(s.oidSignedData) + explicitLen
	totalLen := derTLVLen(ciContentLen)

	// Phase E: Write final CMS structure.
	// Ensure capacity to avoid reallocation (preserves attrSetContent at scratch[0:]).
	resultStart := len(scratch)
	needed := resultStart + totalLen
	if cap(scratch) < needed {
		newScratch := make([]byte, len(scratch), needed)
		copy(newScratch, scratch)
		scratch = newScratch
	}

	// Outer ContentInfo SEQUENCE
	scratch = append(scratch, 0x30)
	scratch = appendDERLength(scratch, ciContentLen)
	scratch = append(scratch, s.oidSignedData...)

	// [0] EXPLICIT CONSTRUCTED
	scratch = append(scratch, 0xA0)
	scratch = appendDERLength(scratch, sdDERLen)

	// SignedData SEQUENCE
	scratch = append(scratch, 0x30)
	scratch = appendDERLength(scratch, sdContentLen)
	scratch = append(scratch, derVersion1...)
	scratch = append(scratch, s.digestAlgSetDER...)
	scratch = append(scratch, s.contentInfoDER...)
	scratch = append(scratch, s.certTagDER...)

	// SignerInfos SET
	scratch = append(scratch, 0x31)
	scratch = appendDERLength(scratch, siDERLen)

	// SignerInfo SEQUENCE
	scratch = append(scratch, 0x30)
	scratch = appendDERLength(scratch, siContentLen)
	scratch = append(scratch, derVersion1...)
	scratch = append(scratch, s.issuerSerialDER...)
	scratch = append(scratch, s.digestAlgDER...)

	// [0] IMPLICIT CONSTRUCTED (authenticated attributes)
	scratch = append(scratch, 0xA0)
	scratch = appendDERLength(scratch, attrSetContentLen)
	scratch = append(scratch, scratch[:attrSetContentLen]...) // copy attrSetContent

	scratch = append(scratch, s.digestEncAlgDER...)

	// OCTET STRING (signature)
	scratch = append(scratch, 0x04)
	scratch = appendDERLength(scratch, sigLen)
	scratch = append(scratch, sig...)

	// Copy result out.
	result := make([]byte, len(scratch)-resultStart)
	copy(result, scratch[resultStart:])

	// Return scratch to pool.
	*bp = scratch
	cmsPool.Put(bp)

	return result, nil
}

// signHash signs a hash using the signer's private key.
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
