package flashsign

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildPDFWithGens writes a minimal one-page PDF whose catalog, page and /Info
// objects carry the given (non-zero) generation numbers.
func buildPDFWithGens(catalogGen, pageGen, infoGen int) []byte {
	objs := []struct {
		nr, gen int
		body    string
	}{
		{1, catalogGen, "<< /Type /Catalog /Pages 2 0 R >>"},
		{2, 0, "<< /Type /Pages /Kids [3 " + fmt.Sprint(pageGen) + " R] /Count 1 >>"},
		{3, pageGen, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>"},
		{4, 0, "<< /Length 21 >>\nstream\nBT /F1 12 Tf ET\nendstream"},
		{5, infoGen, "<< /Producer (flashsign test) >>"},
	}

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n")
	offsets := make([]int64, len(objs)+1)
	for _, o := range objs {
		offsets[o.nr] = int64(buf.Len())
		fmt.Fprintf(&buf, "%d %d obj\n%s\nendobj\n", o.nr, o.gen, o.body)
	}

	xrefOffset := int64(buf.Len())
	buf.WriteString("xref\n0 6\n0000000000 65535 f \r\n")
	for _, o := range objs {
		fmt.Fprintf(&buf, "%010d %05d n \r\n", offsets[o.nr], o.gen)
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size 6 /Root 1 %d R /Info 5 %d R >>\nstartxref\n%d\n%%%%EOF\n",
		catalogGen, infoGen, xrefOffset)
	return buf.Bytes()
}

// Rewriting an object in an incremental update must echo the generation the
// object already had; emitting "N 0 obj" for a gen-2 catalog silently produces
// a document whose /Root reference resolves to nothing.
func TestIncrementPreservesGenerationNumbers(t *testing.T) {
	data := buildPDFWithGens(2, 3, 4)

	pi, err := parsePDF(data, 1)
	if err != nil {
		t.Fatalf("parsePDF: %v", err)
	}
	if pi.catalogGen != 2 || pi.pageGen != 3 || pi.infoGen != 4 {
		t.Fatalf("generations = catalog %d, page %d, info %d; want 2, 3, 4",
			pi.catalogGen, pi.pageGen, pi.infoGen)
	}

	signer := newGeneratedSigner(t)
	incr, _, err := signer.buildIncrement(nil, &pi, int64(len(data)), "", "", "",
		Rectangle{}, false, time.Unix(0, 0).UTC(), nil)
	if err != nil {
		t.Fatalf("buildIncrement: %v", err)
	}
	got := string(incr)

	for _, want := range []string{
		"\n1 2 obj\n",   // catalog rewritten at its own generation
		"\n3 3 obj\n",   // page rewritten at its own generation
		"/P 3 3 R",      // widget points at the page's real reference
		"/Root 1 2 R",   // trailer /Root matches
		"/Info 5 4 R",   // trailer /Info matches
		" 00002 n \r\n", // xref entry for the catalog
		" 00003 n \r\n", // xref entry for the page
	} {
		if !strings.Contains(got, want) {
			t.Errorf("increment missing %q", want)
		}
	}
	if strings.Contains(got, "\n1 0 obj\n") || strings.Contains(got, "/Root 1 0 R") {
		t.Error("increment still writes generation 0 for the catalog")
	}
}

// A /Prev chain that points back at a section already visited must be rejected
// rather than looped over forever.
func TestParseXrefChainRejectsCycle(t *testing.T) {
	data := buildPDFWithGens(0, 0, 0)

	xrefOffset := int64(bytes.LastIndex(data, []byte("xref\n0 6\n")))
	if xrefOffset < 0 {
		t.Fatal("fixture has no xref table")
	}
	// Point the trailer's /Prev at its own section.
	cyclic := bytes.Replace(data, []byte("/Size 6 /Root"),
		[]byte(fmt.Sprintf("/Prev %d /Size 6 /Root", xrefOffset)), 1)

	done := make(chan error, 1)
	go func() {
		_, err := parsePDF(cyclic, 1)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "cyclic") {
			t.Fatalf("parsePDF error = %v; want a cyclic /Prev chain error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("parsePDF did not terminate on a cyclic /Prev chain")
	}
}

// Stream bodies are delimited by /Length, because compressed data can contain
// the literal bytes "endstream".
func TestReadStreamDataUsesLength(t *testing.T) {
	body := "before endstream after"
	obj := fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream\n", len(body), body)
	data := []byte(obj)

	dictContent, dictEnd, err := readDictAt(data, 0)
	if err != nil {
		t.Fatalf("readDictAt: %v", err)
	}

	got, err := readStreamData(data, dictContent, dictEnd)
	if err != nil {
		t.Fatalf("readStreamData: %v", err)
	}
	if string(got) != body {
		t.Errorf("readStreamData() = %q, want %q", got, body)
	}
}

// Without a usable /Length (here: an indirect reference) the reader falls back
// to scanning for the keyword.
func TestReadStreamDataFallsBackToScan(t *testing.T) {
	body := "plain stream body"
	data := []byte(fmt.Sprintf("<< /Length 9 0 R >>\nstream\n%s\nendstream\n", body))

	dictContent, dictEnd, err := readDictAt(data, 0)
	if err != nil {
		t.Fatalf("readDictAt: %v", err)
	}

	got, err := readStreamData(data, dictContent, dictEnd)
	if err != nil {
		t.Fatalf("readStreamData: %v", err)
	}
	if string(got) != body {
		t.Errorf("readStreamData() = %q, want %q", got, body)
	}
}

func TestResolveArrayContentAcceptsEmptyDirectArray(t *testing.T) {
	content, err := resolveArrayContent(nil, nil, []byte("[]"))
	if err != nil {
		t.Fatalf("resolveArrayContent([]): %v", err)
	}
	if len(content) != 0 {
		t.Fatalf("resolveArrayContent([]) = %q, want empty", content)
	}
}

// A failed sign must leave the destination exactly as it was, rather than
// truncating it or replacing it with an unsigned copy.
func TestSignLeavesDestinationIntactOnFailure(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "broken.pdf")
	destPath := filepath.Join(dir, "out.pdf")

	if err := os.WriteFile(srcPath, []byte("%PDF-1.7\nnot really a pdf\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	const existing = "previous output"
	if err := os.WriteFile(destPath, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	signer := newGeneratedSigner(t)
	if err := signer.Sign(SignParams{Src: srcPath, Dest: destPath}); err == nil {
		t.Fatal("Sign() on a malformed PDF returned nil error")
	}

	got, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("read destination: %v", err)
	}
	if string(got) != existing {
		t.Errorf("destination = %q after a failed sign; want it untouched (%q)", got, existing)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".flashsign-") {
			t.Errorf("temp file %s left behind after a failed sign", e.Name())
		}
	}
}

// A startxref (or /Prev) offset pointing past the end of the file must produce
// an error, not a slice-bounds panic.
func TestParsePDFStartxrefBeyondEOF(t *testing.T) {
	pdf := []byte("%PDF-1.4\n1 0 obj\n<< >>\nendobj\nstartxref\n999999\n%%EOF\n")
	_, err := parsePDF(pdf, 1)
	if err == nil {
		t.Fatal("expected error for out-of-bounds startxref offset")
	}
}

// An xref entry whose offset lies past the end of the file must error too.
func TestParsePDFXrefEntryOffsetBeyondEOF(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")
	xrefOffset := buf.Len()
	// Object 1 (the catalog) claims to live at offset 9999999.
	buf.WriteString("xref\n0 2\n0000000000 65535 f \r\n0009999999 00000 n \r\n")
	fmt.Fprintf(&buf, "trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", xrefOffset)
	_, err := parsePDF(buf.Bytes(), 1)
	if err == nil {
		t.Fatal("expected error for out-of-bounds xref entry offset")
	}
}

// PDF real numbers do not allow exponent notation; appendFloat must never
// emit it, whatever the magnitude.
func TestAppendFloatNeverUsesExponent(t *testing.T) {
	for _, f := range []float64{0, 100.5, 612, 1234567, 1e7, 0.00001, -42.25} {
		out := appendFloat(nil, f)
		if bytes.ContainsAny(out, "eE") {
			t.Errorf("appendFloat(%v) = %q contains exponent notation", f, out)
		}
	}
}

func TestAppendPDFEscapedEscapesControlCharacters(t *testing.T) {
	got := appendPDFEscaped(nil, "line 1\nline 2\r\t\b\f(\\)")
	if want := `line 1\nline 2\r\t\b\f\(\\\)`; string(got) != want {
		t.Fatalf("appendPDFEscaped() = %q, want %q", got, want)
	}
}

// A trailer /Size that understates the real object count must not hand out
// new object numbers that collide with existing objects.
func TestParsePDFUnderstatedSizeAllocatesFreshObjNrs(t *testing.T) {
	data := buildPDFWithGens(0, 0, 0) // objects 1..5, /Size 6
	understated := bytes.Replace(data, []byte("/Size 6"), []byte("/Size 3"), 1)
	pi, err := parsePDF(understated, 1)
	if err != nil {
		t.Fatalf("parsePDF: %v", err)
	}
	if pi.nextObjNr != 6 {
		t.Fatalf("nextObjNr = %d; want 6 (highest existing object is 5)", pi.nextObjNr)
	}
}

func TestSignPreservesExistingAcroFormAndAnnotations(t *testing.T) {
	objs := []string{
		"<< /Type /Catalog /Pages 2 0 R /AcroForm 6 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Annots 7 0 R >>",
		"<< /Length 0 >>\nstream\n\nendstream",
		"<< /Type /Annot /Subtype /Widget /FT /Tx /T (Signature1) /Rect [0 0 10 10] >>",
		"<< /Fields 8 0 R /SigFlags 1 /NeedAppearances true /DA (/Helv 9 Tf) /DR << /Font << >> >> /CO [5 0 R] /Custom /Keep >>",
		"[5 0 R]",
		"[5 0 R]",
	}
	in := assembleTestPDF(objs, "")
	signer := newGeneratedSigner(t)
	out, err := signer.SignBytes(in, SignParams{})
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}
	incr := increment(t, in, out)

	for _, want := range []string{
		"/NeedAppearances true",
		"/DA (/Helv 9 Tf)",
		"/DR << /Font << >> >>",
		"/CO [5 0 R]",
		"/Custom /Keep",
		"/T (Signature2)",
		"/Fields [ 5 0 R 10 0 R]",
		"/Annots [ 5 0 R 10 0 R]",
		"/SigFlags 3",
	} {
		mustContain(t, incr, want, "signed form")
	}
	if bytes.Contains(incr, []byte("/SigFlags 1")) {
		t.Error("old /SigFlags value was duplicated in the updated form")
	}
}

func TestSignRejectsUnresolvableExistingAnnotations(t *testing.T) {
	objs := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Annots 99 0 R >>",
		"<< /Length 0 >>\nstream\n\nendstream",
	}
	in := assembleTestPDF(objs, "")
	_, err := newGeneratedSigner(t).SignBytes(in, SignParams{})
	if err == nil {
		t.Fatal("expected an error instead of silently dropping unresolvable annotations")
	}
}

func TestParserIgnoresKeysInsideNestedStringsAndComments(t *testing.T) {
	dict := []byte(`/DA (outer (inner) /Fields fake) /Fields [5 0 R]`)
	if got := string(extractDictValue(dict, "Fields")); got != "[5 0 R]" {
		t.Fatalf("/Fields = %q, want the top-level array", got)
	}
	withoutFields := appendDictWithoutKey(nil, dict, "Fields")
	if !bytes.Contains(withoutFields, []byte("/Fields fake")) {
		t.Fatal("removing the top-level /Fields damaged a nested literal string")
	}

	commented := []byte("<< /A 1 % >> inside a comment\n /B 2 >>")
	raw, _, err := readDictAt(commented, 0)
	if err != nil {
		t.Fatalf("readDictAt: %v", err)
	}
	if got := string(extractDictValue(raw, "B")); got != "2" {
		t.Fatalf("/B = %q, want 2", got)
	}
}

func TestLatestFreeXrefEntryDoesNotResurrectOldObject(t *testing.T) {
	base := buildPDFWithGens(0, 0, 0)
	oldXref := bytes.LastIndex(base, []byte("xref\n0 6\n"))
	if oldXref < 0 {
		t.Fatal("fixture has no xref table")
	}
	newXref := len(base) + 1 // appended section starts with a separator newline
	data := append([]byte(nil), base...)
	data = fmt.Appendf(data,
		"\nxref\n3 1\n0000000000 00001 f \r\ntrailer\n<< /Size 6 /Root 1 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n",
		oldXref, newXref)

	if _, err := parsePDF(data, 1); err == nil {
		t.Fatal("parsePDF resurrected an object freed by the latest xref section")
	}
}

// Signing an encrypted PDF cannot carry /Encrypt into the increment, so the
// parser must reject it instead of producing a silently corrupt document.
func TestParsePDFRejectsEncryptedSource(t *testing.T) {
	inData, err := os.ReadFile(filepath.Join("testdata", "test.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	var enc bytes.Buffer
	if err := encryptPDFStream(bytes.NewReader(inData), &enc, "secret", 128); err != nil {
		t.Fatalf("encrypt fixture: %v", err)
	}
	_, err = parsePDF(enc.Bytes(), 1)
	if err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Fatalf("parsePDF on encrypted source = %v; want an 'encrypted' error", err)
	}
}

// Xref/object streams from mainstream producers use /DecodeParms with a PNG
// predictor; readStreamData must undo it after inflating.
func TestReadStreamDataPNGPredictor(t *testing.T) {
	const columns = 4
	original := []byte{
		1, 0, 10, 0,
		1, 0, 20, 0,
		1, 0, 30, 1,
	}

	// Apply the PNG Up filter (type 2) forward, row by row.
	var filtered []byte
	prev := make([]byte, columns)
	for r := 0; r < len(original)/columns; r++ {
		row := original[r*columns : (r+1)*columns]
		filtered = append(filtered, 2)
		for i, b := range row {
			filtered = append(filtered, b-prev[i])
		}
		prev = row
	}

	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	if _, err := zw.Write(filtered); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	obj := fmt.Sprintf(
		"<< /Length %d /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns %d >> >>\nstream\n%s\nendstream\n",
		compressed.Len(), columns, compressed.Bytes())
	data := []byte(obj)

	dictContent, dictEnd, err := readDictAt(data, 0)
	if err != nil {
		t.Fatalf("readDictAt: %v", err)
	}
	got, err := readStreamData(data, dictContent, dictEnd)
	if err != nil {
		t.Fatalf("readStreamData: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("readStreamData() = %v, want %v", got, original)
	}
}

// A free xref entry's offset field is a free-list link, not a file position;
// consumers must refuse it rather than parse from a garbage offset.
func TestFreeEntriesAreNotDereferenced(t *testing.T) {
	data := []byte("7 0 obj\n[1 0 R]\nendobj\n")
	xref := map[int]xrefEntry{7: {free: true}}

	if _, err := resolveArrayContent(data, xref, []byte("7 0 R")); err == nil {
		t.Error("resolveArrayContent dereferenced a free object")
	}
	if _, err := readCompressedObject(data, xref, 7, 0, 3); err == nil {
		t.Error("readCompressedObject dereferenced a free object stream")
	}
}

// A null /AcroForm target and a null /Fields entry equal absent ones
// (PDF 32000-1 7.3.7, 7.3.10) and must not fail the sign.
func TestParsePDFNullAcroFormShapes(t *testing.T) {
	const content = "q Q\n"
	base := []string{
		"", // catalog, set per case
		"<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(content), content),
		"null",
	}

	for _, tc := range []struct{ name, catalog string }{
		{"indirect ref to null object", "<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>"},
		{"direct dict with null Fields", "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields null >> >>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs := append([]string(nil), base...)
			objs[0] = tc.catalog
			pi, err := parsePDF(assembleTestPDF(objs, ""), 1)
			if err != nil {
				t.Fatalf("parsePDF: %v", err)
			}
			if len(pi.existingFields) != 0 {
				t.Errorf("existingFields = %q, want empty", pi.existingFields)
			}
		})
	}
}

// Removing a dict key must not consume the newline that terminates a
// %-comment before it, or the following entry is spliced into the comment.
func TestAppendDictWithoutKeysPreservesEntryAfterComment(t *testing.T) {
	raw := []byte("/Fields [8 0 R] % note\n/SigFlags 1 /DA (/Helv 0 Tf)")
	got := appendDictWithoutKeys2(nil, raw, "Fields", "SigFlags")
	if !bytes.Contains(got, []byte("/DA (/Helv 0 Tf)")) {
		t.Errorf("kept entry lost: %q", got)
	}
	// The /DA must not sit on the comment's line.
	if i := bytes.Index(got, []byte("% note")); i >= 0 {
		rest := got[i:]
		if j := bytes.IndexByte(rest, '\n'); j < 0 || bytes.Contains(rest[:j], []byte("/DA")) {
			t.Errorf("/DA spliced into comment: %q", got)
		}
	}
}

// Field names may be literal, hex, or UTF-16BE strings; all must decode so
// SignatureN de-duplication sees them.
func TestDecodePDFString(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"(Signature1)", "Signature1"},
		{"<5369676E617475726531>", "Signature1"},
		{"<FEFF00530069006700six>", ""}, // invalid hex digits
		{"<FEFFryna>", ""},
		{"(Sig\\156ature1)", "Signature1"},
	} {
		got := string(decodePDFString([]byte(tc.in)))
		if got != tc.want {
			t.Errorf("decodePDFString(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// UTF-16BE with BOM: "Signature1".
	utf16 := []byte{0xFE, 0xFF}
	for _, c := range "Signature1" {
		utf16 = append(utf16, 0, byte(c))
	}
	hexed := []byte{'<'}
	for _, b := range utf16 {
		hexed = append(hexed, upperHexChars[b>>4], upperHexChars[b&0x0F])
	}
	hexed = append(hexed, '>')
	if got := string(decodePDFString(hexed)); got != "Signature1" {
		t.Errorf("decodePDFString(UTF-16BE hex) = %q, want %q", got, "Signature1")
	}
}

// buildHybridPDF hand-assembles a hybrid-reference file (PDF 32000-1 7.5.8.4)
// of the kind MS Word emits: the catalog lives in an object stream that only
// the trailer's /XRefStm companion stream cross-references, while the classic
// table marks that object free so pre-1.5 readers ignore it.
func buildHybridPDF() []byte {
	var b bytes.Buffer
	offsets := map[int]int{}
	obj := func(nr int, body string) {
		offsets[nr] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", nr, body)
	}

	b.WriteString("%PDF-1.5\n")
	obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
	obj(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>")

	// Object stream 4 holding the catalog (object 1) uncompressed.
	catalog := "<< /Type /Catalog /Pages 2 0 R >>"
	header := "1 0 "
	stmBody := header + catalog
	obj(4, fmt.Sprintf("<< /Type /ObjStm /N 1 /First %d /Length %d >>\nstream\n%s\nendstream",
		len(header), len(stmBody), stmBody))

	// Companion xref stream 5: entry for object 1 (type 2, in stream 4, index 0)
	// and for stream 4 itself (type 1). /W [1 4 2], uncompressed.
	var xs bytes.Buffer
	writeEntry := func(typ, f2, f3 int) {
		xs.WriteByte(byte(typ))
		xs.Write([]byte{byte(f2 >> 24), byte(f2 >> 16), byte(f2 >> 8), byte(f2)})
		xs.Write([]byte{byte(f3 >> 8), byte(f3)})
	}
	writeEntry(2, 4, 0)          // obj 1
	writeEntry(1, offsets[4], 0) // obj 4
	xrefStmOffset := b.Len()
	obj(5, fmt.Sprintf("<< /Type /XRef /Size 6 /W [1 4 2] /Index [1 1 4 1] /Length %d >>\nstream\n%s\nendstream",
		xs.Len(), xs.String()))

	// Classic table: objects 0-5, with 1, 4 and 5 hidden as free entries.
	xrefOffset := b.Len()
	b.WriteString("xref\n0 6\n")
	fmt.Fprintf(&b, "%010d %05d f \n", 0, 65535)
	fmt.Fprintf(&b, "%010d %05d f \n", 0, 0) // obj 1: only in /XRefStm
	fmt.Fprintf(&b, "%010d %05d n \n", offsets[2], 0)
	fmt.Fprintf(&b, "%010d %05d n \n", offsets[3], 0)
	fmt.Fprintf(&b, "%010d %05d f \n", 0, 0) // obj 4
	fmt.Fprintf(&b, "%010d %05d f \n", 0, 0) // obj 5
	fmt.Fprintf(&b, "trailer\n<< /Size 6 /Root 1 0 R /XRefStm %d >>\nstartxref\n%d\n%%%%EOF\n",
		xrefStmOffset, xrefOffset)
	return b.Bytes()
}

// A hybrid-reference file must resolve objects that only its /XRefStm stream
// lists, and sign as a pure append like any other source.
func TestSignHybridReferenceFile(t *testing.T) {
	in := buildHybridPDF()
	pi, err := parsePDF(in, 1)
	if err != nil {
		t.Fatalf("parsePDF hybrid: %v", err)
	}
	if pi.catalogObjNr != 1 || pi.pageObjNr != 3 {
		t.Fatalf("catalog/page = %d/%d, want 1/3", pi.catalogObjNr, pi.pageObjNr)
	}

	signer := newGeneratedSigner(t)
	out, err := signer.SignBytes(in, SignParams{Reason: "Regulatory"})
	if err != nil {
		t.Fatalf("SignBytes hybrid: %v", err)
	}
	if !bytes.HasPrefix(out, in) {
		t.Fatal("hybrid source was not preserved verbatim")
	}
	verifyDetachedSignature(t, out)
	validateWithPDFCPU(t, out)
}
