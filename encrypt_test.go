package flashsign

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptPDF(t *testing.T) {
	inData, err := os.ReadFile(filepath.Join("testdata", "test.pdf"))
	if err != nil {
		t.Fatalf("read input PDF: %v", err)
	}

	tests := []struct {
		name      string
		keyLength int
	}{
		{"AES-128", 128},
		{"AES-256", 256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			inPath := filepath.Join(dir, "input.pdf")
			outPath := filepath.Join(dir, "encrypted.pdf")

			if err := os.WriteFile(inPath, inData, 0o644); err != nil {
				t.Fatalf("write temp input PDF: %v", err)
			}

			if err := encryptPDF(inPath, outPath, "secret", tt.keyLength); err != nil {
				t.Fatalf("encryptPDF(%s) returned error: %v", tt.name, err)
			}

			outData, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatalf("read encrypted output PDF: %v", err)
			}
			if len(outData) == 0 {
				t.Fatalf("encrypted output file (%s) is empty", tt.name)
			}
		})
	}
}
