package flashsign

import (
	"bytes"
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
		Rectangle{}, false, time.Unix(0, 0).UTC())
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
