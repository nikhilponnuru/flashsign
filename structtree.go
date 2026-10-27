package flashsign

import "bytes"

// Nesting the signature widget in the structure tree (PDF/UA-1 7.18.1, 7.18.4).
//
// In a tagged document every annotation must be reachable from the structure
// tree, and a widget annotation must sit inside a /Form structure element.
// Signing therefore appends, next to the widget:
//
//   - a new /Form StructElem whose /K is an object reference (OBJR) to the
//     widget, attached as the last child of the document's top-level
//     /Document element, or of /StructTreeRoot when there is no such element.
//     Its /Alt repeats the widget's /TU description when the catalog declares
//     the document language: PDF/UA-1 7.2 requires the language of an /Alt to
//     be determinable, and the widget's /TU already describes the field;
//   - a /StructParent key on the widget, registered in the /ParentTree number
//     tree so the widget resolves back to its /Form element;
//   - a bumped /ParentTreeNextKey.
//
// Only the objects that change are rewritten, each under its own object number
// and generation, so strings they carry stay valid in encrypted documents. Any
// structure tree whose shape is not handled here (a /ParentTree with /Kids, a
// direct /StructTreeRoot, objects inside object streams of an encrypted
// document, ...) is left untouched, exactly as before: tagging the widget is
// best effort and never makes signing fail.

// structTreeEdit holds what the increment needs to nest the widget in the
// structure tree. ok is false when the tree must be left untouched.
type structTreeEdit struct {
	ok bool

	rootObjNr int
	rootGen   int
	rootRaw   []byte // raw /StructTreeRoot dict content

	// key is the widget's /StructParent and its new /ParentTree key.
	key int

	// The /ParentTree is either inline in the root (ptObjNr == 0) or a separate
	// flat number tree object. ptRaw is its dict content and ptNums the content
	// of its /Nums array (nil when absent).
	ptObjNr int
	ptGen   int
	ptRaw   []byte
	ptNums  []byte

	// Parent of the new /Form element: a top-level StructElem, or the root
	// itself when parentObjNr == 0. parentK is the parent's raw /K value (nil
	// when absent).
	parentObjNr int
	parentGen   int
	parentRaw   []byte
	parentK     []byte

	// alt writes an /Alt on the /Form element.
	alt bool
}

// resolveStructTreeEdit inspects the structure tree of a tagged document.
// reserved lists objects the increment already rewrites (catalog, page,
// viewer preferences); the edit is abandoned if it would rewrite one of them.
func resolveStructTreeEdit(data []byte, xref map[int]xrefEntry, catalogRaw []byte, size int, encrypted bool, reserved ...int) structTreeEdit {
	var e structTreeEdit

	// rewritable resolves a gen-0..n object that the increment may rewrite in
	// place under its own number.
	rewritable := func(val []byte) (int, int, []byte, bool) {
		if !isSingleIndirectRef(val) {
			return 0, 0, nil, false
		}
		objNr, gen, err := extractIndirectRef(val)
		if err != nil || objNr <= 0 || objNr >= size {
			return 0, 0, nil, false
		}
		entry, ok := xref[objNr]
		if !ok || entry.free || entry.gen != gen {
			return 0, 0, nil, false
		}
		// Objects in an object stream are not encrypted individually: their
		// strings would have to be re-encrypted when rewritten as top-level
		// objects. Leave such documents alone.
		if entry.compressed && encrypted {
			return 0, 0, nil, false
		}
		for _, r := range reserved {
			if r == objNr {
				return 0, 0, nil, false
			}
		}
		raw, err := resolveObjectDict(data, xref, objNr)
		if err != nil || raw == nil {
			return 0, 0, nil, false
		}
		return objNr, gen, raw, true
	}

	var ok bool
	e.rootObjNr, e.rootGen, e.rootRaw, ok = rewritable(extractDictValue(catalogRaw, "StructTreeRoot"))
	if !ok {
		return e
	}
	reserved = append(reserved, e.rootObjNr)

	// /ParentTree: a flat number tree, inline or indirect. Without one there is
	// no reliable way to pick a key that does not collide with the pages'
	// /StructParents, so the tree is left alone.
	ptVal := extractDictValue(e.rootRaw, "ParentTree")
	switch {
	case ptVal == nil || isPDFNull(ptVal):
		return e
	case isSingleIndirectRef(ptVal):
		e.ptObjNr, e.ptGen, e.ptRaw, ok = rewritable(ptVal)
		if !ok {
			return e
		}
		reserved = append(reserved, e.ptObjNr)
	default:
		e.ptRaw = extractDictContent(ptVal)
		if e.ptRaw == nil {
			return e
		}
	}
	// Only a flat tree is extended. A root node never carries /Limits; one that
	// does would need them widened as well.
	if findTopLevelKey(e.ptRaw, "Kids") >= 0 || findTopLevelKey(e.ptRaw, "Limits") >= 0 {
		return e
	}
	if nums := extractDictValue(e.ptRaw, "Nums"); nums != nil {
		if e.ptNums = extractArrayContent(nums); e.ptNums == nil && !bytes.Equal(bytes.TrimSpace(nums), []byte("[]")) {
			return e // eg an indirect /Nums array
		}
	}
	maxKey, ok := maxNumberTreeKey(e.ptNums)
	if !ok {
		return e
	}
	e.key = maxKey + 1
	if next := extractDictInt(e.rootRaw, "ParentTreeNextKey", -1); next > e.key {
		e.key = next
	}

	// Attach the /Form element under the document's top-level /Document
	// element when the producer emits one (Typst does), otherwise directly
	// under the root -- the same placement as the Java signer.
	rootK := extractDictValue(e.rootRaw, "K")
	first := rootK
	if content := extractArrayContent(rootK); content != nil {
		first = nil
		if f := bytes.Fields(content); len(f) >= 3 && bytes.Equal(f[2], []byte("R")) {
			first = bytes.Join(f[:3], []byte(" "))
		}
	}
	if isSingleIndirectRef(first) {
		if objNr, gen, raw, ok := rewritable(first); ok && isNameEqual(extractDictValue(raw, "S"), []byte("Document")) {
			e.parentObjNr, e.parentGen, e.parentRaw = objNr, gen, raw
			e.parentK = extractDictValue(raw, "K")
		}
	}
	if e.parentObjNr == 0 {
		e.parentK = rootK
	}
	if isPDFNull(e.parentK) {
		e.parentK = nil // no kids yet
	}

	// A /K that refers to another object is extended by wrapping it in an
	// array, which is only correct when it refers to a single element (a dict),
	// not to an array object.
	if isSingleIndirectRef(e.parentK) {
		objNr, _, err := extractIndirectRef(e.parentK)
		if err != nil {
			return e
		}
		if raw, err := resolveObjectDict(data, xref, objNr); err != nil || raw == nil {
			return e
		}
	}

	e.alt = findTopLevelKey(catalogRaw, "Lang") >= 0
	e.ok = true
	return e
}

// isSingleIndirectRef reports whether val is exactly one "N G R" reference.
// isIndirectRef only checks the trailing "G R", so it also accepts a list.
func isSingleIndirectRef(val []byte) bool {
	f := bytes.Fields(val)
	return len(f) == 3 && bytes.Equal(f[2], []byte("R")) && isIndirectRef(val)
}

// maxNumberTreeKey returns the largest key in the content of a number tree's
// /Nums array (-1 when empty). ok is false when the content cannot be parsed.
func maxNumberTreeKey(nums []byte) (int, bool) {
	maxKey := -1
	pos := 0
	for {
		pos = skipWhitespaceInSlice(nums, pos)
		if pos >= len(nums) {
			return maxKey, true
		}
		key, n := parseInt(nums, pos)
		if n == 0 || key < 0 {
			return 0, false
		}
		if key > maxKey {
			maxKey = key
		}
		pos = skipWhitespaceInSlice(nums, pos+n)
		if pos >= len(nums) {
			return 0, false
		}

		// The value: an indirect reference "N G R", or a direct object.
		if b := nums[pos]; b == '[' || b == '<' || b == '(' || b == '/' {
			pos = findValueEnd(nums, pos)
			continue
		}
		if bytes.HasPrefix(nums[pos:], []byte("null")) {
			pos += len("null")
			continue
		}
		_, n = parseInt(nums, pos)
		if n == 0 {
			return 0, false
		}
		pos = skipWhitespaceInSlice(nums, pos+n)
		_, n = parseInt(nums, pos)
		if n == 0 {
			return 0, false
		}
		pos = skipWhitespaceInSlice(nums, pos+n)
		if pos >= len(nums) || nums[pos] != 'R' {
			return 0, false
		}
		pos++
	}
}

// appendKWithChild writes a /K entry holding the existing kids k (a raw /K
// value, or nil) followed by the reference to child.
func appendKWithChild(buf, k []byte, childObjNr int) []byte {
	buf = append(buf, "\n/K "...)
	k = bytes.TrimSpace(k)
	switch {
	case len(k) == 0:
		return appendObjRef(buf, childObjNr, 0)
	case k[0] == '[':
		buf = append(buf, '[')
		if content := extractArrayContent(k); len(content) > 0 {
			buf = append(buf, content...)
			buf = append(buf, '\n') // also ends a trailing comment
		}
	default:
		// A single kid (element reference, MCID or MCR/OBJR dict).
		buf = append(buf, '[')
		buf = append(buf, k...)
		buf = append(buf, ' ')
	}
	buf = appendObjRef(buf, childObjNr, 0)
	return append(buf, ']')
}

// appendParentTree writes the content of the /ParentTree dict with key mapped
// to the /Form element appended to its /Nums.
func appendParentTree(buf []byte, e *structTreeEdit, formObjNr int) []byte {
	buf = appendDictWithoutKey(buf, e.ptRaw, "Nums")
	buf = append(buf, "\n/Nums ["...)
	if len(e.ptNums) > 0 {
		buf = append(buf, e.ptNums...)
		buf = append(buf, '\n') // also ends a trailing comment
	}
	buf = appendInt(buf, e.key)
	buf = append(buf, ' ')
	buf = appendObjRef(buf, formObjNr, 0)
	return append(buf, "]\n"...)
}
