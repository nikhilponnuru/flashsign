package flashsign

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hhrutter/pkcs7"
)

func verifyDetachedSignature(t *testing.T, signed []byte) {
	t.Helper()

	byteRangePos := bytes.LastIndex(signed, []byte("/ByteRange [0 "))
	if byteRangePos < 0 {
		t.Fatal("signed PDF has no /ByteRange")
	}
	var firstLen, secondStart, secondLen int
	if _, err := fmt.Sscanf(string(signed[byteRangePos:]),
		"/ByteRange [0 %d %d %d]", &firstLen, &secondStart, &secondLen); err != nil {
		t.Fatalf("parse /ByteRange: %v", err)
	}
	if firstLen <= 0 || secondStart <= firstLen || secondLen < 0 || secondStart+secondLen != len(signed) {
		t.Fatalf("invalid /ByteRange [0 %d %d %d] for %d-byte PDF",
			firstLen, secondStart, secondLen, len(signed))
	}

	excluded := signed[firstLen:secondStart]
	if len(excluded) < 2 || excluded[0] != '<' || excluded[len(excluded)-1] != '>' {
		t.Fatal("/ByteRange exclusion is not the /Contents hex string")
	}
	cmsPadded := make([]byte, hex.DecodedLen(len(excluded)-2))
	if _, err := hex.Decode(cmsPadded, excluded[1:len(excluded)-1]); err != nil {
		t.Fatalf("decode /Contents: %v", err)
	}
	var der asn1.RawValue
	rest, err := asn1.Unmarshal(cmsPadded, &der)
	if err != nil {
		t.Fatalf("parse CMS DER envelope: %v", err)
	}
	cms := cmsPadded[:len(cmsPadded)-len(rest)]
	p7, err := pkcs7.Parse(cms)
	if err != nil {
		t.Fatalf("parse CMS signature: %v", err)
	}
	covered := make([]byte, 0, firstLen+secondLen)
	covered = append(covered, signed[:firstLen]...)
	covered = append(covered, signed[secondStart:]...)
	p7.Content = covered
	if err := p7.Verify(); err != nil {
		t.Fatalf("verify detached CMS signature: %v", err)
	}
}

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
	if !bytes.HasPrefix(outData, inData) {
		t.Fatal("signed output does not preserve the source bytes verbatim")
	}
	if !bytes.Contains(outData, []byte("adbe.pkcs7.detached")) {
		t.Fatal("output missing adbe.pkcs7.detached marker")
	}
	if !bytes.Contains(outData, []byte("ByteRange")) {
		t.Fatal("output missing ByteRange")
	}
	verifyDetachedSignature(t, outData)
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

func TestSignVisibleWithReversedRect(t *testing.T) {
	signer, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), "test123")
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	visible := true
	// Inverted coordinate style some signers emit: y1 > y2.
	rect := Rectangle{X1: 0, Y1: 609, X2: 278, Y2: 550}
	outPath := filepath.Join(t.TempDir(), "signed-visible-reversed-rect.pdf")

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
	if !bytes.Contains(outData, []byte("/Rect [0 550 278 609]")) {
		t.Fatal("output missing normalized /Rect for reversed coordinates")
	}
	if bytes.Contains(outData, []byte("/BBox [0 0 278 -59]")) {
		t.Fatal("output contains negative BBox height")
	}
}

func TestSignXRefStreamSourcePureAppend(t *testing.T) {
	// Signing must never rewrite the source, xref-stream sources included: the
	// output starts with the original bytes verbatim and only appends the
	// signature's incremental update.
	signer, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), testPFXPassword)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	srcPath := filepath.Join("testdata", "xrefstream-sample.pdf")
	srcData, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read source file: %v", err)
	}

	visible := true
	// Typical production config values; normalization should handle y1 > y2.
	rect := Rectangle{X1: 0, Y1: 609, X2: 278, Y2: 550}
	outPath := filepath.Join(t.TempDir(), "xrefstream-sample.signed.pdf")

	err = signer.Sign(SignParams{
		Src:      srcPath,
		Dest:     outPath,
		Reason:   "Regulatory",
		Contact:  "Example Corp",
		Location: "Example Corp, Head Office",
		Visible:  &visible,
		Rect:     &rect,
	})
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	outData, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if len(outData) <= len(srcData) || !bytes.Equal(outData[:len(srcData)], srcData) {
		t.Fatal("output does not start with the source bytes verbatim; source was rewritten")
	}
	if !bytes.Contains(outData, []byte("adbe.pkcs7.detached")) || !bytes.Contains(outData, []byte("ByteRange")) {
		t.Fatal("output missing signature markers")
	}
	if !bytes.Contains(outData, []byte("/Rect [0 550 278 609]")) {
		t.Fatal("output missing normalized /Rect")
	}
}

func TestSignRealContractNotePreservesSource(t *testing.T) {
	const path = "testdata/mcx-SUN844.pdf"
	inData, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("real contract-note fixture not available: %v", err)
	}
	signer, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), testPFXPassword)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	visible := true
	rect := Rectangle{X1: 0, Y1: 609, X2: 278, Y2: 550}
	out, err := signer.SignBytes(inData, SignParams{
		Visible: &visible,
		Rect:    &rect,
		Reason:  "Regulatory",
	})
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}
	if !bytes.HasPrefix(out, inData) {
		t.Fatal("signed contract note does not preserve the source bytes verbatim")
	}
	verifyDetachedSignature(t, out)
	validateWithPDFCPU(t, out)
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
	if !bytes.HasPrefix(outData, inData) {
		t.Fatal("signed output does not preserve the source bytes verbatim")
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
	if !bytes.HasPrefix(outData, inData) {
		t.Fatal("signed output does not preserve the source bytes verbatim")
	}
	if !bytes.Contains(outData, []byte("adbe.pkcs7.detached")) {
		t.Fatal("output missing adbe.pkcs7.detached marker")
	}
	verifyDetachedSignature(t, outData)
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

func TestSignInPlace(t *testing.T) {
	signer, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), "test123")
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	inData, err := os.ReadFile(filepath.Join("testdata", "test.pdf"))
	if err != nil {
		t.Fatalf("read input file: %v", err)
	}

	inPath := filepath.Join(t.TempDir(), "in-place.pdf")
	if err := os.WriteFile(inPath, inData, 0o644); err != nil {
		t.Fatalf("write temp input: %v", err)
	}

	if err := signer.Sign(SignParams{Src: inPath}); err != nil {
		t.Fatalf("Sign in-place returned error: %v", err)
	}

	outData, err := os.ReadFile(inPath)
	if err != nil {
		t.Fatalf("read in-place output: %v", err)
	}
	if len(outData) <= len(inData) {
		t.Fatalf("expected in-place output larger than input: out=%d in=%d", len(outData), len(inData))
	}
	if !bytes.Contains(outData, []byte("ByteRange")) {
		t.Fatal("in-place output missing ByteRange")
	}
}

func TestSignNewDestinationKeepsSourcePermissions(t *testing.T) {
	signer, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), testPFXPassword)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	inData, err := os.ReadFile(filepath.Join("testdata", "test.pdf"))
	if err != nil {
		t.Fatalf("read input file: %v", err)
	}

	dir := t.TempDir()
	srcPath := filepath.Join(dir, "private.pdf")
	dstPath := filepath.Join(dir, "private-signed.pdf")
	if err := os.WriteFile(srcPath, inData, 0o600); err != nil {
		t.Fatalf("write private input: %v", err)
	}
	if err := signer.Sign(SignParams{Src: srcPath, Dest: dstPath}); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	st, err := os.Stat(dstPath)
	if err != nil {
		t.Fatalf("stat signed output: %v", err)
	}
	if got := st.Mode().Perm(); got != 0o600 {
		t.Fatalf("signed output mode = %04o, want 0600", got)
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

func TestSignAndEncryptInPlace(t *testing.T) {
	signer, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), "test123")
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	inData, err := os.ReadFile(filepath.Join("testdata", "test.pdf"))
	if err != nil {
		t.Fatalf("read input file: %v", err)
	}

	inPath := filepath.Join(t.TempDir(), "in-place-encrypt.pdf")
	if err := os.WriteFile(inPath, inData, 0o644); err != nil {
		t.Fatalf("write temp input: %v", err)
	}

	if err := signer.SignAndEncrypt(
		SignParams{Src: inPath},
		EncryptParams{Password: "secret"},
	); err != nil {
		t.Fatalf("SignAndEncrypt in-place returned error: %v", err)
	}

	outData, err := os.ReadFile(inPath)
	if err != nil {
		t.Fatalf("read in-place encrypted output: %v", err)
	}
	if len(outData) == 0 {
		t.Fatal("in-place encrypted output is empty")
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

// buildMultiPagePDF builds a PDF with n pages under a balanced page tree
// (fan-out 32), each page carrying a small content stream.
func buildMultiPagePDF(n int) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")
	offsets := []int{0} // index = object number
	obj := func(body string) int {
		offsets = append(offsets, b.Len())
		nr := len(offsets) - 1
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", nr, body)
		return nr
	}
	// Reserve: 1 = catalog, 2 = root Pages, 3 = font. Content + pages follow.
	obj("<< /Type /Catalog /Pages 2 0 R >>")
	rootPos := b.Len()
	rootPlaceholder := "<< /Type /Pages /Kids [" + strings.Repeat(" ", 12*100) + "] /Count " + fmt.Sprintf("%d", n) + " >>"
	obj(rootPlaceholder)
	obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

	// Leaf pages are grouped under intermediate nodes of 32 pages each.
	const fanout = 32
	var intermediates []int
	for start := 0; start < n; start += fanout {
		end := start + fanout
		if end > n {
			end = n
		}
		// Intermediate node written after its kids, so record kids first.
		var kids []int
		for p := start; p < end; p++ {
			content := fmt.Sprintf("BT /F1 12 Tf 20 750 Td (Page %d) Tj ET", p+1)
			c := obj(fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content), content))
			// Parent patched below via a fixed-width placeholder.
			kids = append(kids, obj(fmt.Sprintf("<< /Type /Page /Parent %s /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>", "XXXXXXXX", c)))
		}
		var kidsStr strings.Builder
		for _, k := range kids {
			fmt.Fprintf(&kidsStr, "%d 0 R ", k)
		}
		node := obj(fmt.Sprintf("<< /Type /Pages /Parent 2 0 R /Kids [%s] /Count %d >>", kidsStr.String(), end-start))
		intermediates = append(intermediates, node)
		for _, k := range kids {
			pos := offsets[k]
			i := bytes.Index(b.Bytes()[pos:], []byte("XXXXXXXX"))
			copy(b.Bytes()[pos+i:], []byte(fmt.Sprintf("%-8s", fmt.Sprintf("%d 0 R", node))))
		}
	}
	// Patch root /Kids into its placeholder.
	var rootKids strings.Builder
	for _, k := range intermediates {
		fmt.Fprintf(&rootKids, "%d 0 R ", k)
	}
	i := bytes.Index(b.Bytes()[rootPos:], []byte("/Kids ["))
	copy(b.Bytes()[rootPos+i+len("/Kids ["):], []byte(rootKids.String()))

	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(offsets))
	for _, o := range offsets[1:] {
		fmt.Fprintf(&b, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offsets), xref)
	return b.Bytes()
}

// Contract notes can run to thousands of pages: the signature must land on the
// requested page, at the requested coordinates, and the rest of the document
// must be untouched.
func TestSignLargeMultiPagePDFTargetsRequestedPage(t *testing.T) {
	const pages = 2000
	in := buildMultiPagePDF(pages)
	signer, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), testPFXPassword)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	visible := true
	rect := Rectangle{X1: 0, Y1: 609, X2: 278, Y2: 550}

	for _, page := range []int{1, 1234, pages} {
		t.Run(fmt.Sprintf("page%d", page), func(t *testing.T) {
			out, err := signer.SignBytes(in, SignParams{Page: page, Visible: &visible, Rect: &rect, Reason: "Regulatory"})
			if err != nil {
				t.Fatalf("SignBytes: %v", err)
			}
			if !bytes.HasPrefix(out, in) {
				t.Fatal("source bytes were rewritten")
			}
			// The page object flashsign rewrote must be the one whose content says "Page N".
			pi, err := parsePDF(in, page)
			if err != nil {
				t.Fatal(err)
			}
			incr := out[len(in):]
			if !bytes.Contains(incr, []byte(fmt.Sprintf("/P %d 0 R", pi.pageObjNr))) {
				t.Fatalf("widget /P does not reference page object %d", pi.pageObjNr)
			}
			marker := []byte(fmt.Sprintf("(Page %d) Tj", page))
			contentPos := bytes.Index(in, marker)
			pagePos := bytes.Index(in, []byte(fmt.Sprintf("\n%d 0 obj\n<< /Type /Page ", pi.pageObjNr)))
			if contentPos < 0 || pagePos < 0 || pagePos < contentPos || pagePos-contentPos > 200 {
				t.Fatalf("page object %d is not the one holding %q", pi.pageObjNr, marker)
			}
			if !bytes.Contains(incr, []byte("/Rect [0 550 278 609]")) {
				t.Fatal("widget /Rect does not honour the requested coordinates")
			}
			verifyDetachedSignature(t, out)
		})
	}
}

// The default appearance must lay text out exactly as OpenPDF does for the Java
// signer: 2pt left margin, column top at 70% of the box height minus the
// margin, 9pt leading, and lines that would fall below the box dropped. The
// expected baselines were read from jpdfsigner's own output for these heights.
func TestAppearanceMatchesOpenPDFLayout(t *testing.T) {
	st, err := resolveAppearance(Appearance{})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(st.colorOp); got != "0.0627 0.7098 0.2353 rg\n" {
		t.Fatalf("default colour op = %q", got)
	}
	for _, tc := range []struct {
		height    float64
		wantFirst string
		wantLines int
	}{
		{59, "2 30.3 Td", 4},
		{109, "2 65.3 Td", 4},
		{40, "2 17 Td", 2},
		{20, "2 3 Td", 1},
	} {
		out := string(appendAppearanceStream(nil, Rectangle{0, 0, 278, tc.height}, st, "Test Signer", "Regulatory", "Bangalore", testSigningTime()))
		if !strings.Contains(out, tc.wantFirst) {
			t.Errorf("height %v: first baseline: want %q in\n%s", tc.height, tc.wantFirst, out)
		}
		if got := strings.Count(out, " Tj"); got != tc.wantLines {
			t.Errorf("height %v: %d lines, want %d:\n%s", tc.height, got, tc.wantLines, out)
		}
		if !strings.Contains(out, "/F1 9 Tf") {
			t.Errorf("height %v: font size is not 9pt", tc.height)
		}
	}
}

func testSigningTime() time.Time { return time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC) }

func TestSetAppearance(t *testing.T) {
	signer, err := NewSignerFromPFX(filepath.Join("testdata", "test.pfx"), testPFXPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.SetAppearance(Appearance{FontSize: 12, FontBold: true, FontColor: "255,0,0"}); err != nil {
		t.Fatal(err)
	}
	visible := true
	rect := Rectangle{X1: 0, Y1: 550, X2: 278, Y2: 609}
	out, err := signer.SignBytes(buildSinglePagePDF(1024), SignParams{Visible: &visible, Rect: &rect})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/BaseFont /Helvetica-Bold", "/F1 12 Tf", "1 0 0 rg"} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("output lacks %q", want)
		}
	}
	for _, bad := range []string{"#12345", "300,0,0", "red"} {
		if err := signer.SetAppearance(Appearance{FontColor: bad}); err == nil {
			t.Errorf("SetAppearance accepted colour %q", bad)
		}
	}
	verifyDetachedSignature(t, out)
}
