package flashsign

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var benchmarkSizes = []struct {
	name string
	size int
}{
	{name: "10KB", size: 10 * 1024},
	{name: "100KB", size: 100 * 1024},
	{name: "500KB", size: 500 * 1024},
	{name: "1MB", size: 1024 * 1024},
	{name: "5MB", size: 5 * 1024 * 1024},
}

func BenchmarkSignBytes(b *testing.B) {
	signer := newBenchmarkSigner(b)
	basePDF := loadBenchmarkBasePDF(b)
	pdfs := makeBenchmarkPDFs(basePDF)

	for _, tc := range benchmarkSizes {
		pdfData := pdfs[tc.name]
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(pdfData)))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, err := signer.SignBytes(pdfData, SignParams{})
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSignBytesVisible(b *testing.B) {
	signer := newBenchmarkSigner(b)
	basePDF := loadBenchmarkBasePDF(b)
	pdfs := makeBenchmarkPDFs(basePDF)

	visible := true
	rect := Rectangle{X1: 50, Y1: 50, X2: 250, Y2: 120}
	params := SignParams{Visible: &visible, Rect: &rect}

	for _, tc := range benchmarkSizes {
		pdfData := pdfs[tc.name]
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(pdfData)))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, err := signer.SignBytes(pdfData, params)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSignBytesVisibleParallel(b *testing.B) {
	signer := newBenchmarkSigner(b)
	basePDF := loadBenchmarkBasePDF(b)
	pdfs := makeBenchmarkPDFs(basePDF)

	visible := true
	rect := Rectangle{X1: 50, Y1: 50, X2: 250, Y2: 120}
	params := SignParams{Visible: &visible, Rect: &rect}

	for _, tc := range benchmarkSizes {
		pdfData := pdfs[tc.name]
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(pdfData)))
			b.ResetTimer()

			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					_, err := signer.SignBytes(pdfData, params)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

func BenchmarkSignStreamVisible(b *testing.B) {
	signer := newBenchmarkSigner(b)
	basePDF := loadBenchmarkBasePDF(b)
	pdfs := makeBenchmarkPDFs(basePDF)

	visible := true
	rect := Rectangle{X1: 50, Y1: 50, X2: 250, Y2: 120}
	params := SignParams{Visible: &visible, Rect: &rect}

	for _, tc := range benchmarkSizes {
		pdfData := pdfs[tc.name]
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(pdfData)))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				src := bytes.NewReader(pdfData)
				if err := signer.SignStream(src, io.Discard, params); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSignStreamVisibleParallel(b *testing.B) {
	signer := newBenchmarkSigner(b)
	basePDF := loadBenchmarkBasePDF(b)
	pdfs := makeBenchmarkPDFs(basePDF)

	visible := true
	rect := Rectangle{X1: 50, Y1: 50, X2: 250, Y2: 120}
	params := SignParams{Visible: &visible, Rect: &rect}

	for _, tc := range benchmarkSizes {
		pdfData := pdfs[tc.name]
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(pdfData)))
			b.ResetTimer()

			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					src := bytes.NewReader(pdfData)
					if err := signer.SignStream(src, io.Discard, params); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

func BenchmarkSignBytesECDSA(b *testing.B) {
	signer := newBenchmarkSignerECDSA(b)
	basePDF := loadBenchmarkBasePDF(b)
	pdfs := makeBenchmarkPDFs(basePDF)

	for _, tc := range benchmarkSizes {
		pdfData := pdfs[tc.name]
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(pdfData)))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, err := signer.SignBytes(pdfData, SignParams{})
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSignBytesECDSAParallel(b *testing.B) {
	signer := newBenchmarkSignerECDSA(b)
	basePDF := loadBenchmarkBasePDF(b)
	pdfs := makeBenchmarkPDFs(basePDF)

	for _, tc := range benchmarkSizes {
		pdfData := pdfs[tc.name]
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(pdfData)))
			b.ResetTimer()

			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					_, err := signer.SignBytes(pdfData, SignParams{})
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

func BenchmarkPKCS7Signature(b *testing.B) {
	signer := newBenchmarkSigner(b)

	payload := bytes.Repeat([]byte("pdf-signature-payload"), 1024)
	contentHash := sha256.Sum256(payload)
	signingTime := time.Now().UTC()

	b.ReportAllocs()
	b.SetBytes(int64(len(contentHash)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := signer.buildCMSSignature(contentHash[:], signingTime)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParsePDF(b *testing.B) {
	basePDF := loadBenchmarkBasePDF(b)
	pdfs := makeBenchmarkPDFs(basePDF)

	for _, tc := range benchmarkSizes {
		pdfData := pdfs[tc.name]
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(pdfData)))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, err := parsePDF(pdfData, 1)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkBuildIncrement(b *testing.B) {
	signer := newBenchmarkSigner(b)
	basePDF := loadBenchmarkBasePDF(b)

	pi, err := parsePDF(basePDF, 1)
	if err != nil {
		b.Fatalf("parsePDF: %v", err)
	}

	signingTime := time.Now().UTC()
	rect := Rectangle{X1: 50, Y1: 50, X2: 250, Y2: 120}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		incr, _, err := signer.buildIncrement(pi, int64(len(basePDF)), "Test", "", "", rect, true, signingTime)
		if err != nil {
			b.Fatal(err)
		}
		slicePool.Put(incr[:0])
	}
}

func BenchmarkSignAndEncrypt(b *testing.B) {
	signer := newBenchmarkSigner(b)
	basePDF := loadBenchmarkBasePDF(b)
	pdfs := makeBenchmarkPDFs(basePDF)

	for _, tc := range benchmarkSizes {
		pdfData := pdfs[tc.name]
		b.Run(tc.name, func(b *testing.B) {
			dir := b.TempDir()
			inPath := filepath.Join(dir, "input.pdf")
			if err := os.WriteFile(inPath, pdfData, 0o644); err != nil {
				b.Fatal(err)
			}

			b.ReportAllocs()
			b.SetBytes(int64(len(pdfData)))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				outPath := filepath.Join(dir, fmt.Sprintf("output-%d.pdf", i))
				err := signer.SignAndEncrypt(
					SignParams{Src: inPath, Dest: outPath},
					EncryptParams{Password: "secret"},
				)
				if err != nil {
					b.Fatal(err)
				}
				os.Remove(outPath)
			}
		})
	}
}

// Test helpers.

func newBenchmarkSigner(b *testing.B) *Signer {
	b.Helper()
	signer, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), "test123")
	if err != nil {
		b.Fatalf("create signer: %v", err)
	}
	return signer
}

func newBenchmarkSignerECDSA(b *testing.B) *Signer {
	b.Helper()
	signer, err := NewSignerFromPEM(
		filepath.Join("testdata", "test-ec-cert.pem"),
		filepath.Join("testdata", "test-ec-key.pem"),
	)
	if err != nil {
		b.Fatalf("create ECDSA signer: %v", err)
	}
	return signer
}

func loadBenchmarkBasePDF(b *testing.B) []byte {
	b.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "test.pdf"))
	if err != nil {
		b.Fatalf("read base PDF: %v", err)
	}
	return data
}

func makeBenchmarkPDFs(basePDF []byte) map[string][]byte {
	pdfs := make(map[string][]byte, len(benchmarkSizes))
	for _, tc := range benchmarkSizes {
		pdfs[tc.name] = generateTestPDF(basePDF, tc.size)
	}
	return pdfs
}

func generateTestPDF(basePDF []byte, approxSizeBytes int) []byte {
	if len(basePDF) >= approxSizeBytes {
		return append([]byte(nil), basePDF...)
	}

	paddingTarget := approxSizeBytes
	for {
		pdfData := buildSinglePagePDF(paddingTarget)
		if len(pdfData) >= approxSizeBytes {
			return pdfData
		}
		paddingTarget += approxSizeBytes - len(pdfData) + 256
	}
}

func buildSinglePagePDF(contentTarget int) []byte {
	if contentTarget < 1024 {
		contentTarget = 1024
	}

	streamData := buildContentStream(contentTarget)

	var buf bytes.Buffer
	offsets := make([]int64, 6)

	write := func(s string) {
		_, _ = buf.WriteString(s)
	}

	write("%PDF-1.4\n")

	offsets[1] = int64(buf.Len())
	write("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

	offsets[2] = int64(buf.Len())
	write("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")

	offsets[3] = int64(buf.Len())
	write("3 0 obj\n")
	write("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>\n")
	write("endobj\n")

	offsets[4] = int64(buf.Len())
	write(fmt.Sprintf("4 0 obj\n<< /Length %d >>\nstream\n", len(streamData)))
	write(streamData)
	write("\nendstream\nendobj\n")

	offsets[5] = int64(buf.Len())
	write("5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")

	xrefOffset := int64(buf.Len())
	write("xref\n0 6\n")
	write("0000000000 65535 f \r\n")
	for i := 1; i <= 5; i++ {
		write(fmt.Sprintf("%010d 00000 n \r\n", offsets[i]))
	}

	write("trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n")
	write(fmt.Sprintf("%d\n", xrefOffset))
	write("%%EOF\n")

	return buf.Bytes()
}

func buildContentStream(targetLen int) string {
	base := "BT\n/F1 12 Tf\n72 720 Td\n(Benchmark PDF) Tj\nET\n"
	if targetLen <= len(base) {
		return base
	}

	var sb strings.Builder
	sb.Grow(targetLen)
	sb.WriteString(base)

	commentChunk := "% " + strings.Repeat("X", 76) + "\n"
	for sb.Len() < targetLen {
		sb.WriteString(commentChunk)
	}

	return sb.String()
}
