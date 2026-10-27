package flashsign

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// typstLikeStructTree is a structure tree shaped like the one Typst (krilla)
// writes: an inline flat /ParentTree, /ParentTreeNextKey, and a single
// /Document element as the root's only kid. Page one has /StructParents 0,
// page two /StructParents 1 and its link annotation /StructParent 2.
//
// Extra objects: 11 /Document, 12 and 13 the pages' parent-tree arrays, 14 the
// /Link element of the annotation.
func typstLikeStructTree(root string) testPDFOpts {
	if root == "" {
		root = "<< /Type /StructTreeRoot /K [11 0 R] /ParentTree << /Nums [0 12 0 R 1 13 0 R 2 14 0 R] >> /ParentTreeNextKey 3 /RoleMap << /Title /P >> >>"
	}
	return testPDFOpts{
		tagged:         true,
		viewerPrefs:    "<< /Direction /L2R >>",
		structTreeRoot: root,
		extraObjs: []string{
			"<< /Type /StructElem /S /Document /P 7 0 R /K [14 0 R] >>",
			"[14 0 R]",
			"[14 0 R]",
			"<< /Type /StructElem /S /Link /P 11 0 R /Pg 4 0 R /K << /Type /OBJR /Obj 6 0 R /Pg 4 0 R >> >>",
		},
	}
}

func signTagged(t *testing.T, signer *Signer, in []byte, visible bool) []byte {
	t.Helper()
	rect := Rectangle{X1: 0, Y1: 609, X2: 278, Y2: 550}
	out, err := signer.SignBytes(in, SignParams{Visible: &visible, Rect: &rect, Reason: "Regulatory", Location: "Example Corp, Head Office"})
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}
	if err := verifyPDFSignature(out); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
	validateWithPDFCPU(t, out)
	return out
}

// newObjNrs returns the object numbers the increment allocates for the widget
// and the /Form element of a signature on in.
func newObjNrs(t *testing.T, in []byte, visible bool) (widget, form int) {
	t.Helper()
	pi, err := parsePDF(in, 1)
	if err != nil {
		t.Fatalf("parsePDF: %v", err)
	}
	widget = pi.nextObjNr + 1
	form = pi.nextObjNr + 2
	if visible {
		form += 2 // appearance stream and font
	}
	return widget, form
}

func TestSignNestsWidgetInFormElement(t *testing.T) {
	for _, visible := range []bool{false, true} {
		t.Run(fmt.Sprintf("visible=%v", visible), func(t *testing.T) {
			signer := newGeneratedSigner(t)
			in := buildTestPDF(t, typstLikeStructTree(""))
			widget, form := newObjNrs(t, in, visible)
			incr := increment(t, in, signTagged(t, signer, in, visible))

			mustContain(t, incr, "/StructParent 3\n", "signature widget")
			mustContain(t, incr, fmt.Sprintf("%d 0 obj\n<<\n/Type /StructElem\n/S /Form\n/P 11 0 R\n/Pg 3 0 R\n/K << /Type /OBJR /Obj %d 0 R /Pg 3 0 R >>\n/Alt (Digital signature)", form, widget), "form element")
			mustContain(t, incr, fmt.Sprintf("/Nums [0 12 0 R 1 13 0 R 2 14 0 R 3 %d 0 R]", form), "parent tree")
			mustContain(t, incr, "/ParentTreeNextKey 4", "struct tree root")
			// Untouched root entries survive; the root keeps its single kid.
			mustContain(t, incr, "/RoleMap << /Title /P >>", "struct tree root")
			mustContain(t, incr, "/K [11 0 R]", "struct tree root")
			mustContain(t, incr, fmt.Sprintf("/K [14 0 R %d 0 R]", form), "document element")
			mustContain(t, incr, "/S /Document /P 7 0 R", "document element")

			// Existing accessibility entries are still applied.
			mustContain(t, incr, "/TU (Digital signature)", "signature widget")
			mustContain(t, incr, "/Tabs /S", "signature page")
			mustContain(t, incr, "/DisplayDocTitle true", "catalog")
		})
	}
}

// Signing twice adds a second /Form element under a fresh parent-tree key.
func TestResignNestsEachWidget(t *testing.T) {
	signer := newGeneratedSigner(t)
	in := buildTestPDF(t, typstLikeStructTree(""))
	once := signTagged(t, signer, in, true)
	_, firstForm := newObjNrs(t, in, true)
	_, secondForm := newObjNrs(t, once, true)
	incr := increment(t, once, signTagged(t, signer, once, true))

	mustContain(t, incr, "/StructParent 4\n", "second signature widget")
	mustContain(t, incr, fmt.Sprintf("2 14 0 R 3 %d 0 R 4 %d 0 R]", firstForm, secondForm), "parent tree")
	mustContain(t, incr, "/ParentTreeNextKey 5", "struct tree root")
	mustContain(t, incr, fmt.Sprintf("/K [14 0 R %d 0 R %d 0 R]", firstForm, secondForm), "document element")
}

func TestSignNestsWidgetIndirectParentTree(t *testing.T) {
	signer := newGeneratedSigner(t)
	opts := typstLikeStructTree("<< /Type /StructTreeRoot /K 11 0 R /ParentTree 15 0 R >>")
	opts.extraObjs = append(opts.extraObjs, "<< /Nums [0 12 0 R 1 13 0 R 2 14 0 R] >>")
	in := buildTestPDF(t, opts)
	_, form := newObjNrs(t, in, false)
	incr := increment(t, in, signTagged(t, signer, in, false))

	// No /ParentTreeNextKey in the source: the key follows the largest one.
	mustContain(t, incr, "/StructParent 3\n", "signature widget")
	mustContain(t, incr, "/ParentTree 15 0 R", "struct tree root")
	mustContain(t, incr, "/ParentTreeNextKey 4", "struct tree root")
	mustContain(t, incr, fmt.Sprintf("15 0 obj\n<<\n/Nums [0 12 0 R 1 13 0 R 2 14 0 R 3 %d 0 R]", form), "parent tree object")
	mustContain(t, incr, fmt.Sprintf("/K [14 0 R %d 0 R]", form), "document element")
}

// A /ParentTreeNextKey beyond the largest key is honoured.
func TestSignNestsWidgetHonoursParentTreeNextKey(t *testing.T) {
	signer := newGeneratedSigner(t)
	in := buildTestPDF(t, typstLikeStructTree("<< /Type /StructTreeRoot /K [11 0 R] /ParentTree << /Nums [0 12 0 R 1 13 0 R 2 14 0 R] >> /ParentTreeNextKey 9 >>"))
	incr := increment(t, in, signTagged(t, signer, in, false))
	mustContain(t, incr, "/StructParent 9\n", "signature widget")
	mustContain(t, incr, "/ParentTreeNextKey 10", "struct tree root")
}

// The /Form goes under the first top-level element only when it is the
// /Document element; otherwise it becomes a kid of the root.
func TestSignNestsWidgetPlacement(t *testing.T) {
	for name, tc := range map[string]struct {
		root, part string
		parent     int
		parentK    string
	}{
		"document first of several": {root: "<< /Type /StructTreeRoot /K [11 0 R 14 0 R] /ParentTree << /Nums [0 12 0 R 1 13 0 R 2 14 0 R] >> >>", parent: 11, parentK: "/K [14 0 R %d 0 R]"},
		"document as direct ref":    {root: "<< /Type /StructTreeRoot /K 11 0 R /ParentTree << /Nums [0 12 0 R 1 13 0 R 2 14 0 R] >> >>", parent: 11, parentK: "/K [14 0 R %d 0 R]"},
		"document not first":        {root: "<< /Type /StructTreeRoot /K [14 0 R 11 0 R] /ParentTree << /Nums [0 12 0 R 1 13 0 R 2 14 0 R] >> >>", parent: 7, parentK: "/K [14 0 R 11 0 R %d 0 R]"},
		"single non-document kid":   {root: "<< /Type /StructTreeRoot /K [15 0 R] /ParentTree << /Nums [0 12 0 R 1 13 0 R 2 14 0 R] >> >>", part: "<< /Type /StructElem /S /Part /P 7 0 R /K [11 0 R] >>", parent: 7, parentK: "/K [15 0 R %d 0 R]"},
		"no kids":                   {root: "<< /Type /StructTreeRoot /ParentTree << /Nums [0 12 0 R 1 13 0 R 2 14 0 R] >> >>", parent: 7, parentK: "/K %d 0 R"},
	} {
		t.Run(name, func(t *testing.T) {
			signer := newGeneratedSigner(t)
			opts := typstLikeStructTree(tc.root)
			if tc.part != "" {
				opts.extraObjs = append(opts.extraObjs, tc.part)
			}
			in := buildTestPDF(t, opts)
			_, form := newObjNrs(t, in, false)
			incr := increment(t, in, signTagged(t, signer, in, false))

			mustContain(t, incr, fmt.Sprintf("/S /Form\n/P %d 0 R", tc.parent), "form element")
			mustContain(t, incr, fmt.Sprintf(tc.parentK, form), "form parent")
			if tc.parent == 7 {
				mustNotContainRaw(t, incr, "\n11 0 obj\n", "document element")
			}
		})
	}
}

// Structure trees whose shape is not handled are left untouched, as before.
func TestSignLeavesUnsupportedStructTreesAlone(t *testing.T) {
	for name, root := range map[string]string{
		"no parent tree":          "<< /Type /StructTreeRoot /K [11 0 R] >>",
		"parent tree with kids":   "<< /Type /StructTreeRoot /K [11 0 R] /ParentTree << /Kids [12 0 R] >> /ParentTreeNextKey 3 >>",
		"null parent tree":        "<< /Type /StructTreeRoot /K [11 0 R] /ParentTree null >>",
		"unparsable nums":         "<< /Type /StructTreeRoot /K [11 0 R] /ParentTree << /Nums [0 12 0 R 1 2 0] >> >>",
		"dangling parent tree":    "<< /Type /StructTreeRoot /K [11 0 R] /ParentTree 99 0 R >>",
		"k refers to an array":    "<< /Type /StructTreeRoot /K 12 0 R /ParentTree << /Nums [0 12 0 R 1 13 0 R 2 14 0 R] >> >>",
		"parent tree with limits": "<< /Type /StructTreeRoot /K [11 0 R] /ParentTree << /Limits [0 2] /Nums [0 12 0 R 1 13 0 R 2 14 0 R] >> >>",
	} {
		t.Run(name, func(t *testing.T) {
			signer := newGeneratedSigner(t)
			in := buildTestPDF(t, typstLikeStructTree(root))
			incr := increment(t, in, signTagged(t, signer, in, true))

			mustNotContainRaw(t, incr, "/StructParent ", "signature widget")
			mustNotContain(t, incr, "/S /Form", "increment")
			mustNotContainRaw(t, incr, "\n7 0 obj\n", "struct tree root")
			// The rest of the accessibility handling is unaffected.
			mustContain(t, incr, "/TU (Digital signature)", "signature widget")
			mustContain(t, incr, "/Tabs /S", "signature page")
		})
	}
}

// The edit never rewrites an object the increment already rewrites.
func TestStructTreeEditSkipsReservedObjects(t *testing.T) {
	for name, root := range map[string]string{
		"parent tree is the catalog": "<< /Type /StructTreeRoot /K [11 0 R] /ParentTree 1 0 R >>",
		"top element is the page":    "<< /Type /StructTreeRoot /K [3 0 R] /ParentTree << /Nums [0 12 0 R] >> >>",
	} {
		t.Run(name, func(t *testing.T) {
			pi, err := parsePDF(buildTestPDF(t, typstLikeStructTree(root)), 1)
			if err != nil {
				t.Fatalf("parsePDF: %v", err)
			}
			if pi.structEdit.ok && pi.structEdit.parentObjNr == 3 {
				t.Fatal("struct tree edit would rewrite the signature page as the /Form parent")
			}
			if name == "parent tree is the catalog" && pi.structEdit.ok {
				t.Fatal("struct tree edit would rewrite the catalog as the parent tree")
			}
		})
	}
}

func TestSignUntaggedPDFAddsNoFormElement(t *testing.T) {
	signer := newGeneratedSigner(t)
	in := buildTestPDF(t, testPDFOpts{})
	incr := increment(t, in, signTagged(t, signer, in, true))
	mustNotContain(t, incr, "/S /Form", "increment")
	mustNotContainRaw(t, incr, "/StructParent ", "signature widget")
}

// In an encrypted document the rewritten objects keep their numbers, so their
// encrypted strings stay valid, and the result decrypts with the tree intact.
func TestSignAndEncryptNestsWidgetInFormElement(t *testing.T) {
	signer := newGeneratedSigner(t)
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "tagged.pdf")
	if err := os.WriteFile(srcPath, buildTestPDF(t, typstLikeStructTree("")), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	outPath := filepath.Join(dir, "signed-encrypted.pdf")
	const password = "test-accessibility-password"
	visible := true
	rect := Rectangle{X1: 0, Y1: 609, X2: 278, Y2: 550}
	if err := signer.SignAndEncrypt(SignParams{Src: srcPath, Dest: outPath, Visible: &visible, Rect: &rect}, EncryptParams{Password: password}); err != nil {
		t.Fatalf("SignAndEncrypt: %v", err)
	}
	encrypted, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if err := verifyPDFSignature(encrypted); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
	mustContain(t, encrypted, "/S /Form", "encrypted increment")
	mustContain(t, encrypted, "/StructParent 3\n", "encrypted signature widget")

	decPath := filepath.Join(dir, "decrypted.pdf")
	conf := model.NewAESConfiguration(password, password, 256)
	conf.ValidationMode = model.ValidationRelaxed
	conf.ValidateLinks = false
	conf.WriteObjectStream = false
	conf.WriteXRefStream = false
	if err := api.DecryptFile(outPath, decPath, conf); err != nil {
		t.Fatalf("decrypt output: %v", err)
	}
	decrypted, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatalf("read decrypted output: %v", err)
	}
	mustContain(t, decrypted, "/S/Form", "decrypted form element")
	mustContain(t, decrypted, "/ParentTreeNextKey 4", "decrypted struct tree root")
	mustContain(t, decrypted, "/StructParent 3", "decrypted signature widget")
	// The original string in the struct tree's link annotation decrypts intact.
	mustContain(t, decrypted, "(https://example.com)", "decrypted link annotation")
}

func TestMaxNumberTreeKey(t *testing.T) {
	for _, tc := range []struct {
		nums string
		want int
		ok   bool
	}{
		{"", -1, true},
		{"0 5 0 R", 0, true},
		{"0 5 0 R 1 166 0 R 6 6 0 R 2 [7 0 R 8 0 R]", 6, true},
		{"3 null 1 << /A 1 >> 2 (x)", 3, true},
		{"0 5 0 R 1", 0, false},
		{"0 /Name 1 2 0", 0, false},
		{"x 5 0 R", 0, false},
	} {
		got, ok := maxNumberTreeKey([]byte(tc.nums))
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("maxNumberTreeKey(%q) = %d, %v; want %d, %v", tc.nums, got, ok, tc.want, tc.ok)
		}
	}
}

func TestAppendKWithChild(t *testing.T) {
	for k, want := range map[string]string{
		"":                         "\n/K 9 0 R",
		"[]":                       "\n/K [9 0 R]",
		"[1 0 R 2 0 R]":            "\n/K [1 0 R 2 0 R\n9 0 R]",
		"[1 0 R % kids\n]":         "\n/K [1 0 R % kids\n9 0 R]",
		"3 0 R":                    "\n/K [3 0 R 9 0 R]",
		"0":                        "\n/K [0 9 0 R]",
		"<< /Type /MCR /MCID 0 >>": "\n/K [<< /Type /MCR /MCID 0 >> 9 0 R]",
	} {
		if got := string(appendKWithChild(nil, []byte(k), 9)); got != want {
			t.Errorf("appendKWithChild(%q) = %q, want %q", k, got, want)
		}
	}
}

func TestIsSingleIndirectRef(t *testing.T) {
	for val, want := range map[string]bool{
		"4 0 R":       true,
		" 12 3 R ":    true,
		"4 0 R 5 0 R": false,
		"[4 0 R]":     false,
		"4":           false,
		"":            false,
	} {
		if got := isSingleIndirectRef([]byte(val)); got != want {
			t.Errorf("isSingleIndirectRef(%q) = %v, want %v", val, got, want)
		}
	}
}

func TestAppendDictWithoutKeys(t *testing.T) {
	raw := []byte(" /Type /StructTreeRoot /K [1 0 R] /ParentTree << /Nums [0 1 0 R] >> /ParentTreeNextKey 1 /RoleMap << >> ")
	got := norm(appendDictWithoutKeys(nil, raw, "ParentTreeNextKey", "K", "ParentTree", "Missing"))
	if want := "/Type /StructTreeRoot /RoleMap << >>"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if !bytes.Equal(appendDictWithoutKeys(nil, raw), raw) {
		t.Error("no keys must copy the dict verbatim")
	}
}

// The /Form element's /Alt is only written when the document declares its
// language: PDF/UA-1 7.2 requires the language of every /Alt to be known.
func TestSignOmitsFormAltWithoutDocumentLanguage(t *testing.T) {
	signer := newGeneratedSigner(t)
	opts := typstLikeStructTree("")
	opts.noLang = true
	in := buildTestPDF(t, opts)
	_, form := newObjNrs(t, in, true)
	incr := increment(t, in, signTagged(t, signer, in, true))

	mustContain(t, incr, fmt.Sprintf("%d 0 obj\n<<\n/Type /StructElem\n/S /Form", form), "form element")
	mustNotContain(t, incr, "/Alt", "form element")
	mustContain(t, incr, "/TU (Digital signature)", "signature widget")
}

func TestSignNestsWidgetEdgeKids(t *testing.T) {
	for name, tc := range map[string]struct{ document, want string }{
		// A /K null is no kids, not a null kid.
		"null kids": {"<< /Type /StructElem /S /Document /P 7 0 R /K null >>", "/K %d 0 R"},
		// A comment closing the array must not swallow the appended kid.
		"trailing comment": {"<< /Type /StructElem /S /Document /P 7 0 R /K [14 0 R % kids\n] >>", "/K [14 0 R %% kids\n%d 0 R]"},
	} {
		t.Run(name, func(t *testing.T) {
			signer := newGeneratedSigner(t)
			opts := typstLikeStructTree("")
			opts.extraObjs[0] = tc.document
			in := buildTestPDF(t, opts)
			_, form := newObjNrs(t, in, true)
			out := signTagged(t, signer, in, true)
			validateWithPDFCPU(t, out)
			mustContainRaw(t, increment(t, in, out), fmt.Sprintf(tc.want, form), "document element")
		})
	}
}

// Encrypting a document whose structure tree sits in object streams keeps the
// tree: pdfcpu's writer would otherwise drop everything reachable only through
// objects it read from an object stream.
func TestSignAndEncryptKeepsStructTreeFromObjectStreams(t *testing.T) {
	dir := t.TempDir()
	conf := model.NewDefaultConfiguration()
	conf.ValidationMode = model.ValidationRelaxed
	conf.ValidateLinks = false
	conf.WriteXRefStream = true
	conf.WriteObjectStream = true
	var packed bytes.Buffer
	if err := api.Optimize(bytes.NewReader(buildTestPDF(t, typstLikeStructTree(""))), &packed, conf); err != nil {
		t.Fatalf("build object-stream fixture: %v", err)
	}
	if !bytes.Contains(packed.Bytes(), []byte("/ObjStm")) {
		t.Fatal("fixture has no object streams")
	}
	srcPath := filepath.Join(dir, "packed.pdf")
	if err := os.WriteFile(srcPath, packed.Bytes(), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	signer := newGeneratedSigner(t)
	outPath := filepath.Join(dir, "signed-encrypted.pdf")
	const password = "test-accessibility-password"
	visible := true
	rect := Rectangle{X1: 0, Y1: 609, X2: 278, Y2: 550}
	if err := signer.SignAndEncrypt(SignParams{Src: srcPath, Dest: outPath, Visible: &visible, Rect: &rect}, EncryptParams{Password: password}); err != nil {
		t.Fatalf("SignAndEncrypt: %v", err)
	}

	decPath := filepath.Join(dir, "decrypted.pdf")
	dconf := model.NewAESConfiguration(password, password, 256)
	dconf.ValidationMode = model.ValidationRelaxed
	dconf.ValidateLinks = false
	dconf.WriteObjectStream = false
	dconf.WriteXRefStream = false
	if err := api.DecryptFile(outPath, decPath, dconf); err != nil {
		t.Fatalf("decrypt output: %v", err)
	}
	decrypted, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatalf("read decrypted output: %v", err)
	}
	mustContain(t, decrypted, "/S/Document", "decrypted document element")
	mustContain(t, decrypted, "/S/Link", "decrypted link element")
	mustContain(t, decrypted, "/S/Form", "decrypted form element")
	mustContain(t, decrypted, "(https://example.com)", "decrypted link annotation")
}

// mustContainRaw is mustContain without whitespace normalisation.
func mustContainRaw(t *testing.T, data []byte, want, what string) {
	t.Helper()
	if !bytes.Contains(data, []byte(want)) {
		t.Errorf("%s: expected to find raw %q", what, want)
	}
}
