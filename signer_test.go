package flashsign

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestSignInvisible(t *testing.T) {
	signer, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), "test123")
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	inPath := filepath.Join("testdata", "test.pdf")
	inData, err := os.ReadFile(inPath)
	if err != nil {
		t.Fatalf("read input file: %v", err)
	}

	outPath := filepath.Join(t.TempDir(), "signed-invisible.pdf")
	if err := signer.Sign(SignParams{Src: inPath, Dest: outPath}); err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	outData, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if len(outData) <= len(inData) {
		t.Fatalf("expected output larger than input: out=%d in=%d", len(outData), len(inData))
	}
	if !bytes.Contains(outData, []byte("adbe.pkcs7.detached")) {
		t.Fatal("output missing adbe.pkcs7.detached marker")
	}
	if !bytes.Contains(outData, []byte("ByteRange")) {
		t.Fatal("output missing ByteRange")
	}
}

func TestSignVisible(t *testing.T) {
	signer, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), "test123")
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	visible := true
	rect := Rectangle{X1: 50, Y1: 50, X2: 250, Y2: 120}
	outPath := filepath.Join(t.TempDir(), "signed-visible.pdf")

	err = signer.Sign(SignParams{
		Src:     filepath.Join("testdata", "test.pdf"),
		Dest:    outPath,
		Visible: &visible,
		Rect:    &rect,
	})
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	outData, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if len(outData) == 0 {
		t.Fatal("output file is empty")
	}
}

func TestSignBytes(t *testing.T) {
	signer, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), "test123")
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	inData, err := os.ReadFile(filepath.Join("testdata", "test.pdf"))
	if err != nil {
		t.Fatalf("read input file: %v", err)
	}

	outData, err := signer.SignBytes(inData, SignParams{})
	if err != nil {
		t.Fatalf("SignBytes returned error: %v", err)
	}
	if len(outData) <= len(inData) {
		t.Fatalf("expected output larger than input: out=%d in=%d", len(outData), len(inData))
	}
	if !bytes.Contains(outData, []byte("ByteRange")) {
		t.Fatal("output missing ByteRange")
	}
}

func TestSignBytesECDSA(t *testing.T) {
	signer, err := NewSignerFromPEM(
		filepath.Join("testdata", "test-ec-cert.pem"),
		filepath.Join("testdata", "test-ec-key.pem"),
	)
	if err != nil {
		t.Fatalf("create ECDSA signer: %v", err)
	}

	inData, err := os.ReadFile(filepath.Join("testdata", "test.pdf"))
	if err != nil {
		t.Fatalf("read input file: %v", err)
	}

	outData, err := signer.SignBytes(inData, SignParams{})
	if err != nil {
		t.Fatalf("SignBytes (ECDSA) returned error: %v", err)
	}
	if len(outData) <= len(inData) {
		t.Fatalf("expected output larger than input: out=%d in=%d", len(outData), len(inData))
	}
	if !bytes.Contains(outData, []byte("adbe.pkcs7.detached")) {
		t.Fatal("output missing adbe.pkcs7.detached marker")
	}
}

func TestSignStream(t *testing.T) {
	signer, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), "test123")
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	inData, err := os.ReadFile(filepath.Join("testdata", "test.pdf"))
	if err != nil {
		t.Fatalf("read input file: %v", err)
	}

	src := bytes.NewReader(inData)
	var dst bytes.Buffer

	visible := true
	rect := Rectangle{X1: 50, Y1: 50, X2: 250, Y2: 120}
	err = signer.SignStream(src, &dst, SignParams{
		Visible: &visible,
		Rect:    &rect,
		Reason:  "Testing",
	})
	if err != nil {
		t.Fatalf("SignStream returned error: %v", err)
	}

	outData := dst.Bytes()
	if len(outData) <= len(inData) {
		t.Fatalf("expected output larger than input: out=%d in=%d", len(outData), len(inData))
	}
	if !bytes.Contains(outData, []byte("adbe.pkcs7.detached")) {
		t.Fatal("output missing adbe.pkcs7.detached marker")
	}
	if !bytes.Contains(outData, []byte("ByteRange")) {
		t.Fatal("output missing ByteRange")
	}
	if !bytes.Contains(outData, []byte("Digitally signed by")) {
		t.Fatal("output missing visible signature text")
	}
}

func TestSignStreamToDiscard(t *testing.T) {
	signer, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), "test123")
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	inData, err := os.ReadFile(filepath.Join("testdata", "test.pdf"))
	if err != nil {
		t.Fatalf("read input file: %v", err)
	}

	src := bytes.NewReader(inData)
	err = signer.SignStream(src, io.Discard, SignParams{})
	if err != nil {
		t.Fatalf("SignStream to Discard returned error: %v", err)
	}
}

func TestSignAndEncrypt(t *testing.T) {
	signer, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), "test123")
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	tests := []struct {
		name   string
		aes256 bool
	}{
		{"AES-128", false},
		{"AES-256", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outPath := filepath.Join(t.TempDir(), "signed-encrypted.pdf")
			err = signer.SignAndEncrypt(
				SignParams{
					Src:  filepath.Join("testdata", "test.pdf"),
					Dest: outPath,
				},
				EncryptParams{
					Password: "secret",
					AES256:   tt.aes256,
				},
			)
			if err != nil {
				t.Fatalf("SignAndEncrypt with %s returned error: %v", tt.name, err)
			}

			outData, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatalf("read encrypted output file: %v", err)
			}
			if len(outData) == 0 {
				t.Fatalf("encrypted output file (%s) is empty", tt.name)
			}
		})
	}
}

func TestSignAndEncryptEmptyPassword(t *testing.T) {
	signer, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), "test123")
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	outPath := filepath.Join(t.TempDir(), "signed-encrypted.pdf")
	err = signer.SignAndEncrypt(
		SignParams{
			Src:  filepath.Join("testdata", "test.pdf"),
			Dest: outPath,
		},
		EncryptParams{},
	)
	if err == nil {
		t.Fatal("expected error for empty password, got nil")
	}
}

func TestSignBatch(t *testing.T) {
	signer, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), "test123")
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	inData, err := os.ReadFile(filepath.Join("testdata", "test.pdf"))
	if err != nil {
		t.Fatalf("read input file: %v", err)
	}

	items := make([]BatchItem, 10)
	for i := range items {
		items[i] = BatchItem{
			PDFData: inData,
			Params:  SignParams{},
		}
	}

	signer.SignBatch(items)

	for i, item := range items {
		if item.Err != nil {
			t.Fatalf("batch item %d failed: %v", i, item.Err)
		}
		if len(item.Result) <= len(inData) {
			t.Fatalf("batch item %d: expected output larger than input", i)
		}
	}
}
