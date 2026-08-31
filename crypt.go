package flashsign

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// This file implements the parts of the PDF standard security handler needed
// to append an incremental update to an already-encrypted document: deriving
// the file encryption key from the password, and AES-encrypting the strings
// and streams the increment adds. This mirrors what the Java signer's OpenPDF
// stamper does in its single encrypt-and-sign pass — the signature covers the
// final encrypted bytes, and only the signature /Contents value itself stays
// unencrypted (PDF 32000-1 7.6.2).
//
// Supported forms are exactly the ones encryptPDFStream produces:
// V4/R4 with AESV2 (AES-128) and V5/R5 with AESV3 (AES-256).

// stdPasswordPad is the 32-byte padding string from PDF 32000-1 Algorithm 2.
var stdPasswordPad = [32]byte{
	0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41,
	0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
	0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
	0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
}

// fileCrypt encrypts increment content for an encrypted document.
type fileCrypt struct {
	key []byte // file encryption key
	v5  bool   // V5 (AES-256): the file key is used directly for every object
}

// newFileCrypt derives and authenticates the file encryption key from the
// user password, the raw /Encrypt dict content, and the first /ID element.
func newFileCrypt(password string, encDict, idFirst []byte) (*fileCrypt, error) {
	if f := extractDictValue(encDict, "Filter"); !isNameEqual(f, []byte("Standard")) {
		return nil, fmt.Errorf("unsupported security handler %q", f)
	}
	v := extractDictInt(encDict, "V", 0)
	r := extractDictInt(encDict, "R", 0)

	switch {
	case v == 5 && r == 5:
		return newFileCryptV5(password, encDict)
	case v == 4 && r == 4:
		return newFileCryptV4(password, encDict, idFirst)
	case v == 5 && r == 6:
		// pdfcpu switches to R6 (PDF 2.0 / ISO 32000-2 hashing) when the
		// source header is %PDF-2.0. The Java signer only ever produced R4.
		return nil, fmt.Errorf("PDF 2.0 (R6) encryption is not supported; the source must be a PDF 1.x document")
	default:
		return nil, fmt.Errorf("unsupported encryption V %d R %d", v, r)
	}
}

// newFileCryptV4 implements Algorithm 2 (key derivation) and Algorithm 5
// (user-password verification) for R4 / AES-128.
func newFileCryptV4(password string, encDict, idFirst []byte) (*fileCrypt, error) {
	o := decodePDFString(extractDictValue(encDict, "O"))
	u := decodePDFString(extractDictValue(encDict, "U"))
	if len(o) < 32 || len(u) < 16 {
		return nil, fmt.Errorf("malformed /O or /U entry")
	}
	length := extractDictInt(encDict, "Length", 40) / 8
	if length < 5 || length > 16 {
		return nil, fmt.Errorf("unsupported key length %d bytes", length)
	}
	p := extractDictInt(encDict, "P", 0)
	encryptMetadata := true
	if em := extractDictValue(encDict, "EncryptMetadata"); em != nil && !isPDFTrue(em) {
		encryptMetadata = false
	}

	// Algorithm 2: file key from the padded password.
	h := md5.New()
	h.Write(padPassword(password))
	h.Write(o[:32])
	var pbuf [4]byte
	binary.LittleEndian.PutUint32(pbuf[:], uint32(int32(p)))
	h.Write(pbuf[:])
	h.Write(idFirst)
	if !encryptMetadata {
		h.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	}
	key := h.Sum(nil)
	for i := 0; i < 50; i++ {
		sum := md5.Sum(key[:length])
		key = sum[:]
	}
	key = key[:length]

	// Algorithm 5: verify against /U so a wrong password fails here rather
	// than producing an undecryptable increment.
	vh := md5.New()
	vh.Write(stdPasswordPad[:])
	vh.Write(idFirst)
	check := vh.Sum(nil)
	rc, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	rc.XORKeyStream(check, check)
	tmpKey := make([]byte, len(key))
	for i := 1; i <= 19; i++ {
		for j := range key {
			tmpKey[j] = key[j] ^ byte(i)
		}
		rc, err = rc4.NewCipher(tmpKey)
		if err != nil {
			return nil, err
		}
		rc.XORKeyStream(check, check)
	}
	if !bytes.Equal(check, u[:16]) {
		return nil, fmt.Errorf("wrong password for encrypted PDF")
	}

	return &fileCrypt{key: key}, nil
}

// newFileCryptV5 implements the R5 (AES-256) user-password path: SHA-256 with
// the validation and key salts from /U, then unwrapping the file key from /UE.
func newFileCryptV5(password string, encDict []byte) (*fileCrypt, error) {
	u := decodePDFString(extractDictValue(encDict, "U"))
	ue := decodePDFString(extractDictValue(encDict, "UE"))
	if len(u) < 48 || len(ue) < 32 {
		return nil, fmt.Errorf("malformed /U or /UE entry")
	}
	pwd := []byte(password)
	if len(pwd) > 127 {
		pwd = pwd[:127]
	}

	valHash := sha256.Sum256(append(append([]byte{}, pwd...), u[32:40]...))
	if !bytes.Equal(valHash[:], u[:32]) {
		return nil, fmt.Errorf("wrong password for encrypted PDF")
	}

	interKey := sha256.Sum256(append(append([]byte{}, pwd...), u[40:48]...))
	block, err := aes.NewCipher(interKey[:])
	if err != nil {
		return nil, err
	}
	fileKey := make([]byte, 32)
	cipher.NewCBCDecrypter(block, make([]byte, 16)).CryptBlocks(fileKey, ue[:32])

	return &fileCrypt{key: fileKey, v5: true}, nil
}

// padPassword truncates/pads a password to 32 bytes per Algorithm 2 step a.
func padPassword(password string) []byte {
	out := make([]byte, 32)
	n := copy(out, password)
	copy(out[n:], stdPasswordPad[:])
	return out
}

// objectKey returns the AES key for content belonging to object (objNr, gen).
func (fc *fileCrypt) objectKey(objNr, gen int) []byte {
	if fc.v5 {
		return fc.key
	}
	h := md5.New()
	h.Write(fc.key)
	h.Write([]byte{
		byte(objNr), byte(objNr >> 8), byte(objNr >> 16),
		byte(gen), byte(gen >> 8),
		0x73, 0x41, 0x6C, 0x54, // "sAlT", the AES marker
	})
	key := h.Sum(nil)
	if n := len(fc.key) + 5; n < 16 {
		return key[:n]
	}
	return key
}

// encryptBytes AES-CBC encrypts plaintext for object (objNr, gen): a random
// 16-byte IV followed by the PKCS#7-padded ciphertext.
func (fc *fileCrypt) encryptBytes(objNr, gen int, plaintext []byte) []byte {
	block, err := aes.NewCipher(fc.objectKey(objNr, gen))
	if err != nil {
		// Key sizes are validated at construction; this cannot happen.
		panic("flashsign: " + err.Error())
	}

	padLen := aes.BlockSize - len(plaintext)%aes.BlockSize
	out := make([]byte, aes.BlockSize+len(plaintext)+padLen)
	rand.Read(out[:aes.BlockSize])
	body := out[aes.BlockSize:]
	copy(body, plaintext)
	for i := len(plaintext); i < len(body); i++ {
		body[i] = byte(padLen)
	}
	cipher.NewCBCEncrypter(block, out[:aes.BlockSize]).CryptBlocks(body, body)
	return out
}
