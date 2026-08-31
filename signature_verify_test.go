package flashsign

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/hhrutter/pkcs7"
	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// verifyPDFSignature cryptographically verifies the last signature in a PDF:
// it parses /ByteRange, concatenates the two covered ranges, and verifies the
// CMS in /Contents over them (signature, digest, and signed attributes).
func verifyPDFSignature(pdf []byte) error {
	i := bytes.LastIndex(pdf, []byte("/ByteRange"))
	if i < 0 {
		return fmt.Errorf("no /ByteRange found")
	}
	open := bytes.IndexByte(pdf[i:], '[')
	if open < 0 {
		return fmt.Errorf("malformed ByteRange")
	}
	pos := i + open + 1
	var r [4]int
	for k := 0; k < 4; k++ {
		pos = skipWhitespaceInSlice(pdf, pos)
		v, n := parseInt(pdf, pos)
		if n == 0 {
			return fmt.Errorf("ByteRange int %d unparsable at %d", k, pos)
		}
		r[k] = v
		pos += n
	}
	if r[0]+r[1] > len(pdf) || r[2]+r[3] > len(pdf) || r[2] < r[0]+r[1] {
		return fmt.Errorf("ByteRange %v out of bounds for %d-byte file", r, len(pdf))
	}

	// The gap between the ranges must be exactly the <hex> /Contents value.
	gap := bytes.TrimSpace(pdf[r[0]+r[1] : r[2]])
	if len(gap) < 2 || gap[0] != '<' || gap[len(gap)-1] != '>' {
		return fmt.Errorf("ByteRange gap is not a hex string (len %d)", len(gap))
	}
	hexSig := bytes.TrimRight(gap[1:len(gap)-1], "0")
	if len(hexSig)%2 == 1 {
		hexSig = append(hexSig, '0')
	}
	der, err := hex.DecodeString(string(hexSig))
	if err != nil {
		return fmt.Errorf("decode /Contents hex: %w", err)
	}

	signed := make([]byte, 0, r[1]+r[3])
	signed = append(signed, pdf[r[0]:r[0]+r[1]]...)
	signed = append(signed, pdf[r[2]:r[2]+r[3]]...)

	p7, err := pkcs7.Parse(der)
	if err != nil {
		return fmt.Errorf("parse CMS: %w", err)
	}
	p7.Content = signed
	if err := p7.Verify(); err != nil {
		return fmt.Errorf("CMS verify: %w", err)
	}
	return nil
}

// The signatures flashsign emits must actually verify, for both classic-xref
// and xref-stream sources.
func TestSignedOutputVerifiesCryptographically(t *testing.T) {
	signer, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), testPFXPassword)
	if err != nil {
		t.Fatal(err)
	}

	for _, fixture := range []string{"test.pdf", "xrefstream-sample.pdf"} {
		t.Run(fixture, func(t *testing.T) {
			in, err := os.ReadFile(filepath.Join("testdata", fixture))
			if err != nil {
				t.Fatal(err)
			}
			out, err := signer.SignBytes(in, SignParams{Reason: "Regulatory"})
			if err != nil {
				t.Fatalf("SignBytes: %v", err)
			}
			if err := verifyPDFSignature(out); err != nil {
				t.Errorf("signed output does not verify: %v", err)
			}
		})
	}
}

// SignAndEncrypt must produce a document whose signature verifies over the
// final encrypted bytes (as the Java signer's single encrypt-and-sign pass
// does) and whose increment decrypts with the password: the new strings and
// the appearance stream must be encrypted with the correct file key.
func TestSignAndEncryptOutputVerifiesAndDecrypts(t *testing.T) {
	signer, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), testPFXPassword)
	if err != nil {
		t.Fatal(err)
	}
	in, err := os.ReadFile(filepath.Join("testdata", "test.pdf"))
	if err != nil {
		t.Fatal(err)
	}

	visible := true
	rect := Rectangle{X1: 0, Y1: 609, X2: 278, Y2: 550}
	for _, tc := range []struct {
		name   string
		aes256 bool
		params SignParams
	}{
		{"AES-128 invisible", false, SignParams{Reason: "Regulatory", Location: "Head Office"}},
		{"AES-128 visible", false, SignParams{Reason: "Regulatory", Visible: &visible, Rect: &rect}},
		{"AES-256 visible", true, SignParams{Reason: "Regulatory", Visible: &visible, Rect: &rect}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			src := filepath.Join(dir, "in.pdf")
			dst := filepath.Join(dir, "out.pdf")
			if err := os.WriteFile(src, in, 0o600); err != nil {
				t.Fatal(err)
			}
			params := tc.params
			params.Src, params.Dest = src, dst
			if err := signer.SignAndEncrypt(params, EncryptParams{Password: "secret", AES256: tc.aes256}); err != nil {
				t.Fatalf("SignAndEncrypt: %v", err)
			}
			out, err := os.ReadFile(dst)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Contains(out, []byte("/Encrypt")) {
				t.Fatal("output is not encrypted")
			}
			if bytes.Contains(out, []byte("(Regulatory)")) {
				t.Error("signature /Reason was written in the clear inside an encrypted document")
			}
			if err := verifyPDFSignature(out); err != nil {
				t.Errorf("signature over encrypted output does not verify: %v", err)
			}

			// Decrypt with the password; the increment's strings and stream must
			// come back as plaintext, proving they were encrypted correctly.
			var dec bytes.Buffer
			conf := model.NewAESConfiguration("secret", "secret", 128)
			conf.ValidationMode = model.ValidationRelaxed
			// Plain objects, so the decrypted dictionaries are visible to the
			// byte checks below rather than repacked into object streams.
			conf.WriteObjectStream = false
			conf.WriteXRefStream = false
			if err := api.Decrypt(bytes.NewReader(out), &dec, conf); err != nil {
				t.Fatalf("decrypt signed output: %v", err)
			}
			// pdfcpu re-serialises decrypted strings as hex, so accept either form.
			plain := dec.Bytes()
			containsString := func(s string) bool {
				return bytes.Contains(plain, []byte(s)) ||
					bytes.Contains(bytes.ToLower(plain), []byte(hex.EncodeToString([]byte(s))))
			}
			if !containsString("Regulatory") {
				t.Error("decrypted output lacks the /Reason plaintext: string encryption is wrong")
			}
			if !containsString("Signature1") {
				t.Error("decrypted output lacks the /T field name plaintext")
			}
			if tc.params.Visible != nil && !bytes.Contains(plain, []byte("Digitally signed by")) {
				t.Error("decrypted output lacks the appearance stream plaintext: stream encryption is wrong")
			}
		})
	}
}

// A wrong password must be rejected before any output is produced.
func TestSignEncryptedWrongPasswordRejected(t *testing.T) {
	signer, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), testPFXPassword)
	if err != nil {
		t.Fatal(err)
	}
	in, err := os.ReadFile(filepath.Join("testdata", "test.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	var enc bytes.Buffer
	if err := encryptPDFStream(bytes.NewReader(in), &enc, "secret", 128); err != nil {
		t.Fatal(err)
	}
	if _, err := signer.signBytes(enc.Bytes(), SignParams{}, "wrong"); err == nil {
		t.Fatal("signing with the wrong password succeeded")
	}
}
