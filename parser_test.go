package flashsign

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParsePDF(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "test.pdf"))
	if err != nil {
		t.Fatalf("read test PDF: %v", err)
	}

	pi, err := parsePDF(data, 1)
	if err != nil {
		t.Fatalf("parsePDF: %v", err)
	}

	if pi.catalogObjNr == 0 {
		t.Fatal("catalog object number is 0")
	}
	if pi.pageObjNr == 0 {
		t.Fatal("page object number is 0")
	}
	if pi.nextObjNr == 0 {
		t.Fatal("next object number is 0")
	}
	if pi.prevXrefOffset == 0 {
		t.Fatal("prevXrefOffset is 0")
	}
	if len(pi.catalogRaw) == 0 {
		t.Fatal("catalog raw bytes are empty")
	}
	if len(pi.pageRaw) == 0 {
		t.Fatal("page raw bytes are empty")
	}
}

func TestParsePDFGenerated(t *testing.T) {
	// Test with a generated PDF to exercise the parser more.
	pdfData := buildSinglePagePDF(10 * 1024)

	pi, err := parsePDF(pdfData, 1)
	if err != nil {
		t.Fatalf("parsePDF (generated): %v", err)
	}

	if pi.catalogObjNr == 0 {
		t.Fatal("catalog object number is 0")
	}
	if pi.pageObjNr == 0 {
		t.Fatal("page object number is 0")
	}
}

func TestFindStartxref(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "test.pdf"))
	if err != nil {
		t.Fatalf("read test PDF: %v", err)
	}

	offset, err := findStartxref(data)
	if err != nil {
		t.Fatalf("findStartxref: %v", err)
	}
	if offset == 0 {
		t.Fatal("startxref offset is 0")
	}
}

func TestExtractDictValue(t *testing.T) {
	dict := []byte(` /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [1 0 R] /SigFlags 1 >>`)

	tests := []struct {
		key      string
		expected string
	}{
		{"Type", "/Catalog"},
		{"Pages", "2 0 R"},
		{"AcroForm", "<< /Fields [1 0 R] /SigFlags 1 >>"},
		{"Missing", ""},
	}

	for _, tc := range tests {
		val := extractDictValue(dict, tc.key)
		got := ""
		if val != nil {
			got = string(val)
		}
		if got != tc.expected {
			t.Errorf("extractDictValue(%q) = %q, want %q", tc.key, got, tc.expected)
		}
	}
}

func TestExtractIndirectRef(t *testing.T) {
	val := []byte("5 0 R")
	objNr, gen, err := extractIndirectRef(val)
	if err != nil {
		t.Fatalf("extractIndirectRef: %v", err)
	}
	if objNr != 5 || gen != 0 {
		t.Fatalf("expected 5 0, got %d %d", objNr, gen)
	}
}

func TestParsePDFXrefStream(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "mcx-SUN844.pdf"))
	if err != nil {
		t.Fatalf("read xref stream PDF: %v", err)
	}

	pi, err := parsePDF(data, 1)
	if err != nil {
		t.Fatalf("parsePDF (xref stream): %v", err)
	}

	if pi.catalogObjNr == 0 {
		t.Fatal("catalog object number is 0")
	}
	if pi.pageObjNr == 0 {
		t.Fatal("page object number is 0")
	}
	if pi.nextObjNr == 0 {
		t.Fatal("next object number is 0")
	}
}

func TestParseSignedPDF(t *testing.T) {
	// Test parsing a previously signed PDF (which has incremental updates).
	signer, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), "test123")
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	inData, err := os.ReadFile(filepath.Join("testdata", "test.pdf"))
	if err != nil {
		t.Fatalf("read input file: %v", err)
	}

	// Sign once.
	signed1, err := signer.SignBytes(inData, SignParams{})
	if err != nil {
		t.Fatalf("first sign: %v", err)
	}

	// Sign again (incremental update on top of signed PDF).
	signed2, err := signer.SignBytes(signed1, SignParams{})
	if err != nil {
		t.Fatalf("second sign: %v", err)
	}

	if len(signed2) <= len(signed1) {
		t.Fatalf("double-signed should be larger: %d <= %d", len(signed2), len(signed1))
	}
}
