package flashsign

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// --- fixtures -------------------------------------------------------------

// newGeneratedSigner builds a signer from a freshly generated self-signed RSA
// certificate so accessibility tests do not depend on testdata/ being present.
func newGeneratedSigner(t *testing.T) *Signer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(20260729),
		Subject:               pkix.Name{CommonName: "FlashSign Test Signer", Organization: []string{"FlashSign Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	signer, err := NewSigner(Config{Key: key, Chain: []*x509.Certificate{cert}})
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	return signer
}

// testPDFOpts describes the synthetic fixture to generate.
type testPDFOpts struct {
	// tagged adds /StructTreeRoot + /MarkInfo << /Marked true >> + /Lang.
	tagged bool
	// markedOnly makes the document tagged via /MarkInfo only (no /StructTreeRoot).
	markedOnly bool
	// viewerPrefs is the raw /ViewerPreferences value written into the catalog
	// ("" omits the entry). Ignored when viewerPrefsIndirect is set.
	viewerPrefs string
	// viewerPrefsIndirect, when non-empty, emits /ViewerPreferences as an
	// indirect reference to an object holding this dict content.
	viewerPrefsIndirect string
	// structTreeNull writes /StructTreeRoot null (a stripped structure tree),
	// which must NOT count as tagged.
	structTreeNull bool
}

// Object layout of the generated fixture:
//
//	1 catalog, 2 pages, 3 page one (no /Tabs, no /Annots),
//	4 page two (/Tabs /S + existing link /Annots), 5 content stream,
//	6 link annotation, 7 struct tree root, 8 metadata stream,
//	9 optional /ViewerPreferences object, 10 info dict
func buildTestPDF(t *testing.T, opts testPDFOpts) []byte {
	t.Helper()

	catalog := "<< /Type /Catalog /Pages 2 0 R /Metadata 8 0 R"
	if opts.tagged || opts.markedOnly {
		catalog += " /Lang (en-IN) /MarkInfo << /Marked true /Suspects false >>"
		if !opts.markedOnly {
			catalog += " /StructTreeRoot 7 0 R"
		}
	}
	if opts.structTreeNull {
		catalog += " /StructTreeRoot null"
	}
	switch {
	case opts.viewerPrefsIndirect != "":
		catalog += " /ViewerPreferences 9 0 R"
	case opts.viewerPrefs != "":
		catalog += " /ViewerPreferences " + opts.viewerPrefs
	}
	catalog += " >>"

	// Keep the content stream free of external resources so pdfcpu validation of
	// the fixture itself passes.
	const content = "q 0 0 1 RG 1 w 20 20 200 100 re S Q\n"
	objs := []string{
		catalog,
		"<< /Type /Pages /Count 2 /Kids [3 0 R 4 0 R] >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /StructParents 0 /Resources << >> /Contents 5 0 R >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /StructParents 1 /Tabs /S /Resources << >> /Contents 5 0 R /Annots [6 0 R] >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(content), content),
		"<< /Type /Annot /Subtype /Link /Rect [20 20 120 40] /Border [0 0 0] /StructParent 2 /A << /Type /Action /S /URI /URI (https://example.com) >> >>",
		"<< /Type /StructTreeRoot >>",
		metadataStreamObj(),
		"<< >>", // placeholder, replaced below when viewer prefs are indirect
		"<< /Title (Sample Document) /Author (Example Corp) >>",
	}
	if opts.viewerPrefsIndirect != "" {
		objs[8] = opts.viewerPrefsIndirect
	}

	return assembleTestPDF(objs, "/Info 10 0 R /ID [<0102030405060708090A0B0C0D0E0F10> <0102030405060708090A0B0C0D0E0F10>] ")
}

func metadataStreamObj() string {
	const xmp = `<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?><x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title><rdf:Alt><rdf:li xml:lang="x-default">Sample Document</rdf:li></rdf:Alt></dc:title></rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="r"?>`
	return fmt.Sprintf("<< /Type /Metadata /Subtype /XML /Length %d >>\nstream\n%s\nendstream", len(xmp), xmp)
}

// assembleTestPDF writes objects 1..N with a classic xref table and trailer.
func assembleTestPDF(objs []string, trailerExtra string) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n%\xE2\xE3\xCF\xD3\n")

	offsets := make([]int, len(objs)+1)
	for i, o := range objs {
		offsets[i+1] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}

	xrefOffset := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for i := 1; i <= len(objs); i++ {
		fmt.Fprintf(&b, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R %s>>\nstartxref\n%d\n%%%%EOF\n",
		len(objs)+1, trailerExtra, xrefOffset)

	return b.Bytes()
}

// --- assertion helpers ----------------------------------------------------

// increment returns the appended incremental-update section of a signed PDF.
func increment(t *testing.T, in, out []byte) []byte {
	t.Helper()
	if len(out) <= len(in) {
		t.Fatalf("expected signed output larger than input: out=%d in=%d", len(out), len(in))
	}
	if !bytes.Equal(out[:len(in)], in) {
		t.Fatal("signed output does not preserve original bytes verbatim")
	}
	return out[len(in):]
}

// norm collapses whitespace runs to a single space so assertions do not depend
// on the exact spacing produced when raw dictionaries are spliced.
func norm(data []byte) string {
	var b bytes.Buffer
	space := false
	for _, c := range data {
		if c == ' ' || c == '\n' || c == '\r' || c == '\t' {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteByte(c)
	}
	return b.String()
}

func mustContain(t *testing.T, data []byte, want, what string) {
	t.Helper()
	if !bytes.Contains([]byte(norm(data)), []byte(norm([]byte(want)))) {
		t.Errorf("%s: expected to find %q", what, want)
	}
}

func mustNotContain(t *testing.T, data []byte, unwanted, what string) {
	t.Helper()
	if bytes.Contains([]byte(norm(data)), []byte(norm([]byte(unwanted)))) {
		t.Errorf("%s: expected NOT to find %q", what, unwanted)
	}
}

// mustNotContainRaw checks raw bytes without whitespace normalisation, for
// needles whose trailing delimiter matters (eg "/StructParent " vs
// "/StructParents").
func mustNotContainRaw(t *testing.T, data []byte, unwanted, what string) {
	t.Helper()
	if bytes.Contains(data, []byte(unwanted)) {
		t.Errorf("%s: expected NOT to find %q", what, unwanted)
	}
}

func mustCount(t *testing.T, data []byte, needle string, want int, what string) {
	t.Helper()
	if got := bytes.Count(data, []byte(needle)); got != want {
		t.Errorf("%s: expected %d occurrence(s) of %q, got %d", what, want, needle, got)
	}
}

// validateWithPDFCPU runs pdfcpu's relaxed validation over signed bytes to make
// sure the rewritten catalog/page/viewer-preference dicts stay well-formed.
func validateWithPDFCPU(t *testing.T, data []byte) {
	t.Helper()
	conf := model.NewDefaultConfiguration()
	conf.ValidationMode = model.ValidationRelaxed
	conf.ValidateLinks = false
	if err := api.Validate(bytes.NewReader(data), conf); err != nil {
		t.Fatalf("pdfcpu validation of signed PDF failed: %v", err)
	}
}

// --- tagged PDF signing ---------------------------------------------------

func TestSignTaggedPDFAddsAccessibilityEntries(t *testing.T) {
	signer := newGeneratedSigner(t)
	in := buildTestPDF(t, testPDFOpts{tagged: true, viewerPrefs: "<< /Direction /L2R >>"})

	out, err := signer.SignBytes(in, SignParams{})
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}
	incr := increment(t, in, out)

	// DisplayDocTitle added, existing viewer preferences preserved.
	mustContain(t, incr, "/ViewerPreferences", "catalog")
	mustContain(t, incr, "/DisplayDocTitle true", "catalog")
	mustContain(t, incr, "/Direction /L2R", "catalog")
	mustCount(t, incr, "/DisplayDocTitle", 1, "catalog")

	// Structure and language metadata preserved.
	mustContain(t, incr, "/StructTreeRoot 7 0 R", "catalog")
	mustContain(t, incr, "/MarkInfo << /Marked true /Suspects false >>", "catalog")
	mustContain(t, incr, "/Lang (en-IN)", "catalog")
	mustContain(t, incr, "/Metadata 8 0 R", "catalog")

	// Signature page gets /Tabs /S because a widget annotation was added.
	mustContain(t, incr, "/Tabs /S", "signature page")
	mustContain(t, incr, "/StructParents 0", "signature page")

	// Widget carries an alternate description for assistive technology.
	mustContain(t, incr, "/TU (Digital signature)", "signature widget")
	// No dangling structure-tree reference on the widget (note: the page's own
	// /StructParents entry must survive, hence the raw check).
	mustNotContainRaw(t, incr, "/StructParent ", "signature widget")

	// Trailer still references the original /Info and /ID.
	mustContain(t, incr, "/Info 10 0 R", "trailer")
	mustContain(t, incr, "/ID [<0102030405060708090A0B0C0D0E0F10>", "trailer")

	validateWithPDFCPU(t, out)
}

func TestSignTaggedPDFViaMarkInfoOnly(t *testing.T) {
	signer := newGeneratedSigner(t)
	in := buildTestPDF(t, testPDFOpts{markedOnly: true})

	out, err := signer.SignBytes(in, SignParams{})
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}
	incr := increment(t, in, out)

	mustContain(t, incr, "/ViewerPreferences << /DisplayDocTitle true >>", "catalog")
	mustContain(t, incr, "/Tabs /S", "signature page")
	validateWithPDFCPU(t, out)
}

func TestSignTaggedPDFPreservesExplicitDisplayDocTitle(t *testing.T) {
	signer := newGeneratedSigner(t)
	in := buildTestPDF(t, testPDFOpts{
		tagged:      true,
		viewerPrefs: "<< /Direction /L2R /DisplayDocTitle false /FitWindow true >>",
	})

	out, err := signer.SignBytes(in, SignParams{})
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}
	incr := increment(t, in, out)

	mustCount(t, incr, "/DisplayDocTitle", 1, "catalog")
	mustContain(t, incr, "/DisplayDocTitle false", "catalog")
	mustNotContain(t, incr, "/DisplayDocTitle true", "catalog")
	// Other viewer preferences survive the rewrite.
	mustContain(t, incr, "/Direction /L2R", "catalog")
	mustContain(t, incr, "/FitWindow true", "catalog")
	validateWithPDFCPU(t, out)
}

func TestSignTaggedPDFIndirectViewerPreferences(t *testing.T) {
	signer := newGeneratedSigner(t)
	in := buildTestPDF(t, testPDFOpts{
		tagged:              true,
		viewerPrefsIndirect: "<< /Direction /L2R >>",
	})

	out, err := signer.SignBytes(in, SignParams{})
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}
	incr := increment(t, in, out)

	// Catalog keeps the indirect reference; the referenced object is updated.
	mustContain(t, incr, "/ViewerPreferences 9 0 R", "catalog")
	mustContain(t, incr, "9 0 obj\n<< /Direction /L2R /DisplayDocTitle true >>", "viewer preferences object")
	mustCount(t, incr, "/DisplayDocTitle", 1, "increment")
	// The updated object must be listed in the increment's xref section.
	mustContain(t, incr, "9 1\n", "xref")
	validateWithPDFCPU(t, out)
}

func TestSignTaggedPDFPreservesExistingTabsAndAnnots(t *testing.T) {
	signer := newGeneratedSigner(t)
	in := buildTestPDF(t, testPDFOpts{tagged: true})

	// Page 2 already has /Tabs /S and a link annotation.
	out, err := signer.SignBytes(in, SignParams{Page: 2})
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}
	incr := increment(t, in, out)

	mustCount(t, incr, "/Tabs", 1, "signature page")
	mustContain(t, incr, "/Tabs /S", "signature page")
	// Existing annotation retained, widget appended.
	// Fixture has 10 objects, so /Size is 11: sig=11, widget=12.
	mustContain(t, incr, "/Annots [ 6 0 R 12 0 R]", "signature page")
	mustContain(t, incr, "/StructParents 1", "signature page")
	validateWithPDFCPU(t, out)
}

func TestSignUntaggedPDFLeavesAccessibilityEntriesAlone(t *testing.T) {
	signer := newGeneratedSigner(t)
	in := buildTestPDF(t, testPDFOpts{})

	out, err := signer.SignBytes(in, SignParams{})
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}
	incr := increment(t, in, out)

	mustNotContain(t, incr, "/DisplayDocTitle", "untagged catalog")
	mustNotContain(t, incr, "/ViewerPreferences", "untagged catalog")
	mustNotContain(t, incr, "/Tabs", "untagged signature page")
	mustNotContain(t, incr, "/TU (", "untagged signature widget")
	// Signature itself is unaffected.
	mustContain(t, incr, "adbe.pkcs7.detached", "signature dict")
	validateWithPDFCPU(t, out)
}

func TestSignUntaggedPDFKeepsExistingViewerPreferences(t *testing.T) {
	signer := newGeneratedSigner(t)
	in := buildTestPDF(t, testPDFOpts{viewerPrefs: "<< /Direction /R2L >>"})

	out, err := signer.SignBytes(in, SignParams{})
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}
	incr := increment(t, in, out)

	mustContain(t, incr, "/ViewerPreferences << /Direction /R2L >>", "untagged catalog")
	mustNotContain(t, incr, "/DisplayDocTitle", "untagged catalog")
	validateWithPDFCPU(t, out)
}

func TestSignVisibleOnTaggedPDF(t *testing.T) {
	signer := newGeneratedSigner(t)
	in := buildTestPDF(t, testPDFOpts{tagged: true, viewerPrefs: "<< /Direction /L2R >>"})

	visible := true
	rect := Rectangle{X1: 0, Y1: 609, X2: 278, Y2: 550}
	out, err := signer.SignBytes(in, SignParams{
		Visible:  &visible,
		Rect:     &rect,
		Reason:   "Regulatory",
		Contact:  "Example Corp",
		Location: "Example Corp, Head Office",
	})
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}
	incr := increment(t, in, out)

	// Visible signature behaviour is unchanged.
	mustContain(t, incr, "/Rect [0 550 278 609]", "signature widget")
	mustContain(t, incr, "/AP << /N ", "signature widget")
	mustContain(t, incr, "Digitally signed by ", "appearance stream")
	mustContain(t, incr, "/Reason (Regulatory)", "signature dict")

	// Accessibility entries still applied.
	mustContain(t, incr, "/DisplayDocTitle true", "catalog")
	mustContain(t, incr, "/Direction /L2R", "catalog")
	mustContain(t, incr, "/Tabs /S", "signature page")
	mustContain(t, incr, "/TU (Digital signature)", "signature widget")

	validateWithPDFCPU(t, out)
}

// --- encryption -----------------------------------------------------------

func TestEncryptConfAllowsScreenReaders(t *testing.T) {
	for _, keyLength := range []int{128, 256} {
		conf := newEncryptConf("secret", keyLength)
		p := conf.Permissions
		if p&model.PermissionExtractRev3 == 0 {
			t.Errorf("AES-%d: screen-reader/extract-for-accessibility permission (bit 10) not granted: %#x", keyLength, int(p))
		}
		if p&model.PermissionPrintRev2 == 0 || p&model.PermissionPrintRev3 == 0 {
			t.Errorf("AES-%d: printing permission lost: %#x", keyLength, int(p))
		}
		if p&model.PermissionModify != 0 {
			t.Errorf("AES-%d: modify permission unexpectedly granted: %#x", keyLength, int(p))
		}
		if got, want := int16(p), int16(-1337); got != want {
			t.Errorf("AES-%d: /P value = %d, want %d", keyLength, got, want)
		}
	}
}

func TestSignAndEncryptTaggedPDFStaysAccessible(t *testing.T) {
	for _, tc := range []struct {
		name   string
		aes256 bool
	}{{"AES-128", false}, {"AES-256", true}} {
		t.Run(tc.name, func(t *testing.T) {
			signer := newGeneratedSigner(t)
			dir := t.TempDir()
			srcPath := filepath.Join(dir, "tagged.pdf")
			if err := os.WriteFile(srcPath, buildTestPDF(t, testPDFOpts{tagged: true, viewerPrefs: "<< /Direction /L2R >>"}), 0o644); err != nil {
				t.Fatalf("write fixture: %v", err)
			}

			outPath := filepath.Join(dir, "tagged-signed-encrypted.pdf")
			const password = "test-accessibility-password"
			if err := signer.SignAndEncrypt(
				SignParams{Src: srcPath, Dest: outPath},
				EncryptParams{Password: password, AES256: tc.aes256},
			); err != nil {
				t.Fatalf("SignAndEncrypt: %v", err)
			}

			encrypted, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatalf("read encrypted output: %v", err)
			}

			// Dictionary keys/names are not encrypted, so the accessibility
			// entries can be asserted on the encrypted artefact directly.
			mustContain(t, encrypted, "/DisplayDocTitle true", "encrypted catalog")
			mustContain(t, encrypted, "/Direction/L2R", "encrypted catalog")
			mustContain(t, encrypted, "/StructTreeRoot", "encrypted catalog")
			mustContain(t, encrypted, "/MarkInfo", "encrypted catalog")
			mustContain(t, encrypted, "/Lang", "encrypted catalog")
			mustContain(t, encrypted, "/Metadata", "encrypted catalog")
			mustContain(t, encrypted, "/Tabs", "encrypted pages")
			mustContain(t, encrypted, "/TU", "encrypted signature widget")
			mustContain(t, encrypted, "adbe.pkcs7.detached", "encrypted signature")

			// Read back with the password and verify the effective permissions.
			readConf := model.NewAESConfiguration(password, password, 256)
			readConf.ValidationMode = model.ValidationRelaxed
			readConf.ValidateLinks = false
			ctx, err := api.ReadContext(bytes.NewReader(encrypted), readConf)
			if err != nil {
				t.Fatalf("read encrypted output with password: %v", err)
			}
			if ctx.E == nil {
				t.Fatal("encrypted output has no encryption dictionary")
			}
			p := ctx.E.P
			if p&int(model.PermissionExtractRev3) == 0 {
				t.Errorf("/P = %d does not grant screen-reader extraction (bit 10)", p)
			}
			if p&int(model.PermissionPrintRev3) == 0 || p&int(model.PermissionPrintRev2) == 0 {
				t.Errorf("/P = %d does not grant printing", p)
			}
			if p&int(model.PermissionModify) != 0 {
				t.Errorf("/P = %d unexpectedly grants modification", p)
			}

			// The document must still open (and decrypt) with the password.
			decPath := filepath.Join(dir, "decrypted.pdf")
			decConf := model.NewAESConfiguration(password, password, 256)
			decConf.ValidationMode = model.ValidationRelaxed
			decConf.ValidateLinks = false
			decConf.WriteObjectStream = false
			decConf.WriteXRefStream = false
			if err := api.DecryptFile(outPath, decPath, decConf); err != nil {
				t.Fatalf("decrypt output: %v", err)
			}
			decrypted, err := os.ReadFile(decPath)
			if err != nil {
				t.Fatalf("read decrypted output: %v", err)
			}
			mustContain(t, decrypted, "/DisplayDocTitle true", "decrypted catalog")
			mustContain(t, decrypted, "/Tabs", "decrypted pages")
			mustContain(t, decrypted, "adbe.pkcs7.detached", "decrypted signature")
		})
	}
}

// --- real tagged-document fixture (optional) ------------------------------

// TestSignRealAccessibleTaggedPDF exercises a real, externally produced tagged
// PDF when one is present. testdata/ is gitignored, so the test skips when the
// fixture is unavailable rather than reporting a code failure.
func TestSignRealAccessibleTaggedPDF(t *testing.T) {
	const fixture = "testdata/accessible-tagged.pdf"
	in, err := os.ReadFile(fixture)
	if err != nil {
		t.Skipf("fixture %s not available: %v", fixture, err)
	}

	signer := newGeneratedSigner(t)
	visible := true
	rect := Rectangle{X1: 0, Y1: 609, X2: 278, Y2: 550}
	out, err := signer.SignBytes(in, SignParams{
		Page:     1,
		Visible:  &visible,
		Rect:     &rect,
		Reason:   "Regulatory",
		Contact:  "Example Corp",
		Location: "Example Corp, Head Office",
	})
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}
	incr := increment(t, in, out)

	mustContain(t, incr, "/DisplayDocTitle true", "catalog")
	mustContain(t, incr, "/Direction/L2R", "catalog")
	mustContain(t, incr, "/StructTreeRoot", "catalog")
	mustContain(t, incr, "/MarkInfo", "catalog")
	mustContain(t, incr, "/Lang", "catalog")
	mustContain(t, incr, "/Tabs /S", "signature page")
	mustContain(t, incr, "/TU (Digital signature)", "signature widget")
	mustContain(t, incr, "/Rect [0 550 278 609]", "signature widget")

	validateWithPDFCPU(t, out)
}

// --- degenerate /ViewerPreferences and /StructTreeRoot cases ----------------

// setViewerPrefsGen rewrites the fixture so /ViewerPreferences references
// object 9 at a non-zero generation (same-length patches, offsets unchanged).
func setViewerPrefsGen(t *testing.T, pdf []byte, gen int) []byte {
	t.Helper()
	out := bytes.Replace(pdf, []byte("/ViewerPreferences 9 0 R"), []byte(fmt.Sprintf("/ViewerPreferences 9 %d R", gen)), 1)
	out = bytes.Replace(out, []byte("\n9 0 obj"), []byte(fmt.Sprintf("\n9 %d obj", gen)), 1)
	hdr := []byte("xref\n0 11\n")
	i := bytes.LastIndex(out, hdr)
	if i < 0 {
		t.Fatal("xref header not found in fixture")
	}
	// Entry line for object 9: 20 bytes each, line 0 is the free entry.
	genPos := i + len(hdr) + 20*9 + 11
	copy(out[genPos:genPos+5], fmt.Sprintf("%05d", gen))
	if bytes.Equal(out, pdf) {
		t.Fatal("generation patch did not change the fixture")
	}
	return out
}

func TestSignTaggedPDFNonzeroGenViewerPrefsMergesInline(t *testing.T) {
	signer := newGeneratedSigner(t)
	in := setViewerPrefsGen(t, buildTestPDF(t, testPDFOpts{
		tagged:              true,
		viewerPrefsIndirect: "<< /Direction /R2L >>",
	}), 2)

	out, err := signer.SignBytes(in, SignParams{})
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}
	incr := increment(t, in, out)

	// The gen-2 object must not be shadowed by a gen-0 rewrite; instead the
	// resolved preferences are merged inline into the catalog.
	mustNotContain(t, incr, "9 0 obj", "increment")
	mustNotContain(t, incr, "9 2 R", "rewritten catalog")
	mustContain(t, incr, "/ViewerPreferences << /Direction /R2L /DisplayDocTitle true >>", "catalog")
	mustCount(t, incr, "/DisplayDocTitle", 1, "catalog")
	validateWithPDFCPU(t, out)
}

func TestSignTaggedPDFUnresolvableViewerPrefsLeftUntouched(t *testing.T) {
	signer := newGeneratedSigner(t)
	in := bytes.Replace(
		buildTestPDF(t, testPDFOpts{tagged: true, viewerPrefsIndirect: "<< /Direction /R2L >>"}),
		[]byte("/ViewerPreferences 9 0 R"), []byte("/ViewerPreferences 99 0 R"), 1)
	// Same-length patch: drop a trailing space before >> to keep offsets stable.
	in = bytes.Replace(in, []byte("99 0 R >>"), []byte("99 0 R>>"), 1)
	if len(in) != len(buildTestPDF(t, testPDFOpts{tagged: true, viewerPrefsIndirect: "<< /Direction /R2L >>"})) {
		t.Fatal("unresolvable-ref patch changed fixture length")
	}

	out, err := signer.SignBytes(in, SignParams{})
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}
	incr := increment(t, in, out)

	// The dangling reference is preserved verbatim; no DisplayDocTitle is
	// invented, but the page-level accessibility entries still apply.
	mustContain(t, incr, "/ViewerPreferences 99 0 R", "catalog")
	mustNotContain(t, incr, "/DisplayDocTitle", "catalog")
	mustContain(t, incr, "/Tabs /S", "signature page")
	mustContain(t, incr, "/TU (Digital signature)", "signature widget")
}

func TestSignStructTreeRootNullIsUntagged(t *testing.T) {
	signer := newGeneratedSigner(t)
	in := buildTestPDF(t, testPDFOpts{structTreeNull: true})

	out, err := signer.SignBytes(in, SignParams{})
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}
	incr := increment(t, in, out)

	mustNotContain(t, incr, "/DisplayDocTitle", "catalog")
	mustNotContain(t, incr, "/Tabs", "signature page")
	mustNotContain(t, incr, "/TU (", "signature widget")
	mustContain(t, incr, "adbe.pkcs7.detached", "signature dict")
	validateWithPDFCPU(t, out)
}

// --- unit tests for the dict splicing / detection helpers ------------------

// Whitespace before a removed key is deliberately left in place (it is
// insignificant inside a dictionary and may terminate a %-comment), so the
// expected strings carry the leftover blanks.
func TestAppendDictWithoutKeys2(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "both keys present",
			raw:  "/Type /Catalog /AcroForm << /Fields [1 0 R] >> /Lang (en) /ViewerPreferences << /Direction /L2R >> /Pages 2 0 R",
			want: "/Type /Catalog  /Lang (en)  /Pages 2 0 R",
		},
		{
			name: "reverse order",
			raw:  "/ViewerPreferences << /Direction /L2R >> /Lang (en) /AcroForm 9 0 R /Pages 2 0 R",
			want: " /Lang (en)  /Pages 2 0 R",
		},
		{
			name: "only first key present",
			raw:  "/AcroForm 9 0 R /Pages 2 0 R",
			want: " /Pages 2 0 R",
		},
		{
			name: "only second key present",
			raw:  "/Pages 2 0 R /ViewerPreferences << /Direction /L2R >>",
			want: "/Pages 2 0 R ",
		},
		{
			name: "neither key present",
			raw:  "/Type /Catalog /Pages 2 0 R",
			want: "/Type /Catalog /Pages 2 0 R",
		},
		{
			name: "nested dict values are not confused with top level keys",
			raw:  "/Foo << /AcroForm 1 0 R /ViewerPreferences 2 0 R >> /Pages 2 0 R",
			want: "/Foo << /AcroForm 1 0 R /ViewerPreferences 2 0 R >> /Pages 2 0 R",
		},
		{
			name: "pretty printed values",
			raw:  "/Type /Catalog\n/AcroForm\n<< /Fields [] >>\n/ViewerPreferences\n<< /Direction /L2R >>\n/Pages 2 0 R",
			want: "/Type /Catalog\n\n\n/Pages 2 0 R",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(appendDictWithoutKeys2(nil, []byte(tt.raw), "AcroForm", "ViewerPreferences"))
			if got != tt.want {
				t.Errorf("appendDictWithoutKeys2()\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}

func TestAppendDictWithoutKeyPrettyPrinted(t *testing.T) {
	// Regression: the value scan must skip newlines between key and value,
	// otherwise the orphaned dict value would corrupt the rewritten object.
	raw := "/Type /Page\n/Annots\n[6 0 R]\n/Contents 5 0 R"
	got := string(appendDictWithoutKey(nil, []byte(raw), "Annots"))
	want := "/Type /Page\n\n/Contents 5 0 R"
	if got != want {
		t.Errorf("appendDictWithoutKey()\n got: %q\nwant: %q", got, want)
	}
}

func TestParsePDFAccessibilityDetection(t *testing.T) {
	tests := []struct {
		name            string
		opts            testPDFOpts
		wantTagged      bool
		wantVPObjNr     int
		wantVPRawHas    string
		wantPageHasTabs bool
		page            int
	}{
		{name: "untagged", opts: testPDFOpts{}, page: 1},
		{name: "tagged struct tree", opts: testPDFOpts{tagged: true}, wantTagged: true, page: 1},
		{name: "tagged mark info only", opts: testPDFOpts{markedOnly: true}, wantTagged: true, page: 1},
		{
			name:         "direct viewer prefs",
			opts:         testPDFOpts{tagged: true, viewerPrefs: "<< /Direction /L2R >>"},
			wantTagged:   true,
			wantVPRawHas: "/Direction /L2R",
			page:         1,
		},
		{
			name:         "indirect viewer prefs",
			opts:         testPDFOpts{tagged: true, viewerPrefsIndirect: "<< /Direction /R2L >>"},
			wantTagged:   true,
			wantVPObjNr:  9,
			wantVPRawHas: "/Direction /R2L",
			page:         1,
		},
		{
			name:            "page with existing tabs",
			opts:            testPDFOpts{tagged: true},
			wantTagged:      true,
			wantPageHasTabs: true,
			page:            2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pi, err := parsePDF(buildTestPDF(t, tt.opts), tt.page)
			if err != nil {
				t.Fatalf("parsePDF: %v", err)
			}
			if pi.tagged != tt.wantTagged {
				t.Errorf("tagged = %v, want %v", pi.tagged, tt.wantTagged)
			}
			if pi.viewerPrefsObjNr != tt.wantVPObjNr {
				t.Errorf("viewerPrefsObjNr = %d, want %d", pi.viewerPrefsObjNr, tt.wantVPObjNr)
			}
			if tt.wantVPRawHas != "" {
				mustContain(t, pi.viewerPrefsRaw, tt.wantVPRawHas, "viewerPrefsRaw")
			}
			if pi.pageHasTabs != tt.wantPageHasTabs {
				t.Errorf("pageHasTabs = %v, want %v", pi.pageHasTabs, tt.wantPageHasTabs)
			}
		})
	}
}

// TestSignTaggedXRefStreamPDF covers a tagged source whose catalog and pages
// live in object streams behind an xref stream: the parser resolves them out
// of the compressed streams, the source is signed as-is (never rewritten), and
// the accessibility entries must still be applied to the catalog and
// signature page in the appended increment.
func TestSignTaggedXRefStreamPDF(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "tagged-xrefstream.pdf")

	conf := model.NewDefaultConfiguration()
	conf.ValidationMode = model.ValidationRelaxed
	conf.ValidateLinks = false
	conf.WriteXRefStream = true
	conf.WriteObjectStream = true

	var compact bytes.Buffer
	src := buildTestPDF(t, testPDFOpts{tagged: true, viewerPrefs: "<< /Direction /L2R >>"})
	if err := api.Optimize(bytes.NewReader(src), &compact, conf); err != nil {
		t.Fatalf("build xref-stream fixture: %v", err)
	}
	if !bytes.Contains(compact.Bytes(), []byte("/Type/XRef")) && !bytes.Contains(compact.Bytes(), []byte("/Type /XRef")) {
		t.Skip("pdfcpu did not produce an xref stream fixture")
	}
	if err := os.WriteFile(srcPath, compact.Bytes(), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	signer := newGeneratedSigner(t)
	outPath := filepath.Join(dir, "signed.pdf")
	visible := true
	rect := Rectangle{X1: 0, Y1: 609, X2: 278, Y2: 550}
	if err := signer.Sign(SignParams{Src: srcPath, Dest: outPath, Page: 1, Visible: &visible, Rect: &rect}); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	out, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read signed output: %v", err)
	}

	mustContain(t, out, "/DisplayDocTitle true", "catalog")
	mustContain(t, out, "/Direction/L2R", "catalog")
	mustContain(t, out, "/StructTreeRoot", "catalog")
	mustContain(t, out, "/Tabs /S", "signature page")
	mustContain(t, out, "/TU (Digital signature)", "signature widget")
	mustContain(t, out, "/Rect [0 550 278 609]", "signature widget")
	// Only the signature page's /Tabs is visible in the raw bytes: the other
	// page keeps its own inside a compressed object stream, untouched.
	mustCount(t, out, "/Tabs", 1, "signature page")
	mustCount(t, out, "/DisplayDocTitle", 1, "catalog")

	// The source must survive verbatim: signing appends, never rewrites.
	if !bytes.HasPrefix(out, compact.Bytes()) {
		t.Error("signed output does not start with the source bytes verbatim")
	}

	validateWithPDFCPU(t, out)
}
