package flashsign

import (
	"sync"
	"time"
)

// incrOffsets tracks placeholder positions within the increment buffer.
type incrOffsets struct {
	byteRangeInIncr    int
	contentsHexInIncr  int
	contentsHexEndIncr int
}

// slicePool provides reusable byte slices for building increments.
// Stores *[]byte to avoid interface boxing allocation on Put.
var slicePool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 32*1024)
		return &b
	},
}

// buildIncrement writes the incremental update into buf. fc is non-nil when the
// source document is encrypted: every string and stream the increment adds is
// then encrypted with the file key, except the signature /Contents value,
// which the spec leaves in the clear (PDF 32000-1 7.6.2).
func (s *Signer) buildIncrement(buf []byte, pi *pdfInfo, srcSize int64, reason, contact, location string, rect Rectangle, visible bool, signingTime time.Time, fc *fileCrypt) ([]byte, incrOffsets, error) {
	// Allocate object numbers.
	sigValueObjNr := pi.nextObjNr
	widgetObjNr := pi.nextObjNr + 1
	nextObj := pi.nextObjNr + 2
	appearanceObjNr := 0
	fontObjNr := 0
	if visible {
		appearanceObjNr = nextObj
		nextObj++
		fontObjNr = nextObj
		nextObj++
	}

	// Tagged (accessible) documents need /DisplayDocTitle plus /Tabs /S on the
	// page that receives the signature widget. Match the Java signer by adding
	// /DisplayDocTitle only when absent; an explicit producer setting is not
	// changed as a side effect of signing. resolveViewerPrefs uses -1 for an
	// unresolvable value that must be left untouched.
	addDisplayDocTitle := pi.tagged && findTopLevelKey(pi.viewerPrefsRaw, "DisplayDocTitle") < 0
	inlineViewerPrefs := addDisplayDocTitle && pi.viewerPrefsObjNr == 0
	updateViewerPrefsObj := addDisplayDocTitle && pi.viewerPrefsObjNr > 0
	addTabs := pi.tagged && !pi.pageHasTabs

	buf = buf[:0]
	buf = append(buf, '\n')

	// Track xref entries in a fixed-size array (max 7 objects: sig, widget,
	// appearance, font, catalog, page, viewer preferences). Rewritten objects
	// keep the generation they already had; new objects start at generation 0.
	type xrefEnt struct {
		objNr  int
		gen    int
		offset int64
	}
	var xrefEntries [7]xrefEnt
	xrefCount := 0
	baseOffset := srcSize

	recordOffset := func(objNr, gen int) {
		xrefEntries[xrefCount] = xrefEnt{objNr: objNr, gen: gen, offset: baseOffset + int64(len(buf))}
		xrefCount++
	}

	// appendObjHeader starts an object definition ("N G obj").
	appendObjHeader := func(buf []byte, objNr, gen int) []byte {
		buf = appendInt(buf, objNr)
		buf = append(buf, ' ')
		buf = appendInt(buf, gen)
		return append(buf, " obj\n<<"...)
	}

	var offsets incrOffsets

	// === Signature Value Dictionary ===
	recordOffset(sigValueObjNr, 0)
	buf = appendObjHeader(buf, sigValueObjNr, 0)
	buf = append(buf, "\n/Type /Sig\n/Filter /Adobe.PPKLite\n/SubFilter /adbe.pkcs7.detached\n"...)
	offsets.byteRangeInIncr = len(buf)
	buf = append(buf, byteRangePlaceholder...)
	buf = append(buf, '\n')
	buf = append(buf, "/Contents <"...)
	offsets.contentsHexInIncr = len(buf)
	buf = append(buf, s.contentsZeros...)
	offsets.contentsHexEndIncr = len(buf)
	buf = append(buf, ">\n"...)
	if s.signerNameStr != "" {
		buf = append(buf, "/Name "...)
		buf = appendPDFTextString(buf, s.signerNameStr, fc, sigValueObjNr, 0)
		buf = append(buf, '\n')
	}
	if reason != "" {
		buf = append(buf, "/Reason "...)
		buf = appendPDFTextString(buf, reason, fc, sigValueObjNr, 0)
		buf = append(buf, '\n')
	}
	if contact != "" {
		buf = append(buf, "/ContactInfo "...)
		buf = appendPDFTextString(buf, contact, fc, sigValueObjNr, 0)
		buf = append(buf, '\n')
	}
	if location != "" {
		buf = append(buf, "/Location "...)
		buf = appendPDFTextString(buf, location, fc, sigValueObjNr, 0)
		buf = append(buf, '\n')
	}
	var dateBuf [32]byte
	buf = append(buf, "/M "...)
	buf = appendPDFTextString(buf, string(appendPDFDate(dateBuf[:0], signingTime)), fc, sigValueObjNr, 0)
	buf = append(buf, "\n>>\nendobj\n\n"...)

	// === Widget Annotation ===
	recordOffset(widgetObjNr, 0)
	buf = appendObjHeader(buf, widgetObjNr, 0)
	var nameBuf [24]byte
	fieldName := appendInt(append(nameBuf[:0], "Signature"...), pi.signatureFieldNr)
	buf = append(buf, "\n/Type /Annot\n/Subtype /Widget\n/FT /Sig\n/T "...)
	buf = appendPDFTextString(buf, string(fieldName), fc, widgetObjNr, 0)
	buf = append(buf, "\n/V "...)
	buf = appendObjRef(buf, sigValueObjNr, 0)
	buf = append(buf, "\n/F 132\n/P "...)
	buf = appendObjRef(buf, pi.pageObjNr, pi.pageGen)
	buf = append(buf, '\n')
	if pi.tagged {
		// Alternate field description for assistive technology (PDF/UA-1 7.18.6.2).
		buf = append(buf, "/TU "...)
		buf = appendPDFTextString(buf, signatureFieldDescription, fc, widgetObjNr, 0)
		buf = append(buf, '\n')
	}
	if visible && rect.X1 != rect.X2 && rect.Y1 != rect.Y2 {
		buf = append(buf, "/Rect ["...)
		buf = appendFloat(buf, rect.X1)
		buf = append(buf, ' ')
		buf = appendFloat(buf, rect.Y1)
		buf = append(buf, ' ')
		buf = appendFloat(buf, rect.X2)
		buf = append(buf, ' ')
		buf = appendFloat(buf, rect.Y2)
		buf = append(buf, "]\n"...)
		if appearanceObjNr > 0 {
			buf = append(buf, "/AP << /N "...)
			buf = appendInt(buf, appearanceObjNr)
			buf = append(buf, " 0 R >>\n"...)
		}
	} else {
		buf = append(buf, "/Rect [0 0 0 0]\n"...)
	}
	buf = append(buf, ">>\nendobj\n\n"...)

	// === Appearance Stream (if visible) ===
	if visible && appearanceObjNr > 0 {
		width := rect.X2 - rect.X1
		height := rect.Y2 - rect.Y1

		// Font object.
		recordOffset(fontObjNr, 0)
		buf = appendInt(buf, fontObjNr)
		if s.appearance.bold {
			buf = append(buf, " 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>\nendobj\n\n"...)
		} else {
			buf = append(buf, " 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>\nendobj\n\n"...)
		}

		// Form XObject with placeholder /Length (patched after stream content).
		recordOffset(appearanceObjNr, 0)
		buf = appendObjHeader(buf, appearanceObjNr, 0)
		buf = append(buf, "\n/Type /XObject\n/Subtype /Form\n/FormType 1\n/BBox [0 0 "...)
		buf = appendFloat(buf, width)
		buf = append(buf, ' ')
		buf = appendFloat(buf, height)
		buf = append(buf, "]\n/Resources << /Font << /F1 "...)
		buf = appendInt(buf, fontObjNr)
		buf = append(buf, " 0 R >> >>\n/Length "...)
		lengthPos := len(buf)
		buf = append(buf, "      "...) // 6-char placeholder
		buf = append(buf, "\n>>\nstream\n"...)
		streamStart := len(buf)
		buf = appendAppearanceStream(buf, rect, s.appearance, s.signerNameStr, reason, location, signingTime)
		if fc != nil {
			ct := fc.encryptBytes(appearanceObjNr, 0, buf[streamStart:])
			buf = append(buf[:streamStart], ct...)
		}
		streamLen := len(buf) - streamStart
		buf = append(buf, "\nendstream\nendobj\n\n"...)
		// Patch /Length value in-place.
		patchDecimal(buf, lengthPos, 6, streamLen)
	}

	// === Modified Catalog ===
	recordOffset(pi.catalogObjNr, pi.catalogGen)
	buf = appendObjHeader(buf, pi.catalogObjNr, pi.catalogGen)
	// Copy raw catalog dict, removing /AcroForm (and /ViewerPreferences when it
	// is rewritten inline below). Everything else — /StructTreeRoot, /MarkInfo,
	// /Lang, /Metadata, /Outlines — is preserved verbatim.
	if inlineViewerPrefs {
		buf = appendDictWithoutKeys2(buf, pi.catalogRaw, "AcroForm", "ViewerPreferences")
	} else {
		buf = appendDictWithoutKey(buf, pi.catalogRaw, "AcroForm")
	}
	buf = append(buf, "\n/AcroForm <<"...)
	// Preserve all existing form-level behavior (/DR, /DA, /NeedAppearances,
	// /CO, /XFA, and producer-specific entries). Only /Fields and /SigFlags
	// need replacement to attach the new signature field and advertise that
	// the document contains signatures.
	if pi.acroFormRaw != nil {
		buf = appendDictWithoutKeys2(buf, pi.acroFormRaw, "Fields", "SigFlags")
	}
	buf = append(buf, "\n/Fields ["...)
	if len(pi.existingFields) > 0 {
		buf = append(buf, ' ')
		buf = append(buf, pi.existingFields...)
	}
	buf = append(buf, ' ')
	buf = appendObjRef(buf, widgetObjNr, 0)
	buf = append(buf, "] /SigFlags 3 >>"...)
	if inlineViewerPrefs {
		// Preserve existing viewer preferences (eg /Direction) and add the
		// missing /DisplayDocTitle entry for tagged documents.
		buf = append(buf, kwViewerPreferencesPrefix...)
		buf = appendDictWithoutKey(buf, pi.viewerPrefsRaw, "DisplayDocTitle")
		buf = append(buf, kwDisplayDocTitleTrue...)
	}
	buf = append(buf, "\n>>\nendobj\n\n"...)

	// === Modified /ViewerPreferences object (when referenced indirectly) ===
	if updateViewerPrefsObj {
		recordOffset(pi.viewerPrefsObjNr, 0)
		buf = appendObjHeader(buf, pi.viewerPrefsObjNr, 0)
		buf = appendDictWithoutKey(buf, pi.viewerPrefsRaw, "DisplayDocTitle")
		buf = append(buf, kwDisplayDocTitleTrue...)
		buf = append(buf, "\nendobj\n\n"...)
	}

	// === Modified Page ===
	recordOffset(pi.pageObjNr, pi.pageGen)
	buf = appendObjHeader(buf, pi.pageObjNr, pi.pageGen)
	// Copy raw page dict, removing /Annots. /StructParents and an existing
	// /Tabs are preserved verbatim.
	buf = appendDictWithoutKey(buf, pi.pageRaw, "Annots")
	buf = append(buf, "\n/Annots ["...)
	if len(pi.existingAnnots) > 0 {
		buf = append(buf, ' ')
		buf = append(buf, pi.existingAnnots...)
	}
	buf = append(buf, ' ')
	buf = appendObjRef(buf, widgetObjNr, 0)
	buf = append(buf, ']')
	if addTabs {
		// The signature widget is an annotation on this page, so tab order must
		// follow the structure tree (PDF/UA-1 7.18.3).
		buf = append(buf, kwTabsStructure...)
	}
	buf = append(buf, "\n>>\nendobj\n\n"...)

	// === Cross-reference table ===
	xrefOffset := baseOffset + int64(len(buf))
	buf = append(buf, "xref\n"...)

	// Sort xref entries by object number (insertion sort for small N).
	for i := 1; i < xrefCount; i++ {
		key := xrefEntries[i]
		j := i - 1
		for j >= 0 && xrefEntries[j].objNr > key.objNr {
			xrefEntries[j+1] = xrefEntries[j]
			j--
		}
		xrefEntries[j+1] = key
	}

	for i := 0; i < xrefCount; i++ {
		e := xrefEntries[i]
		buf = appendInt(buf, e.objNr)
		buf = append(buf, " 1\n"...)
		buf = appendZeroPad10(buf, e.offset)
		buf = append(buf, ' ')
		buf = appendZeroPad5(buf, e.gen)
		buf = append(buf, " n \r\n"...)
	}

	// === Trailer ===
	buf = append(buf, "trailer\n<<\n/Size "...)
	buf = appendInt(buf, nextObj)
	buf = append(buf, "\n/Root "...)
	buf = appendObjRef(buf, pi.catalogObjNr, pi.catalogGen)
	buf = append(buf, '\n')
	if pi.infoObjNr > 0 {
		buf = append(buf, "/Info "...)
		buf = appendObjRef(buf, pi.infoObjNr, pi.infoGen)
		buf = append(buf, '\n')
	}
	if len(pi.idArray) > 0 {
		buf = append(buf, "/ID "...)
		buf = append(buf, pi.idArray...)
		buf = append(buf, '\n')
	}
	if len(pi.encryptRaw) > 0 {
		buf = append(buf, "/Encrypt "...)
		buf = append(buf, pi.encryptRaw...)
		buf = append(buf, '\n')
	}
	buf = append(buf, "/Prev "...)
	buf = appendInt64(buf, pi.prevXrefOffset)
	buf = append(buf, "\n>>\nstartxref\n"...)
	buf = appendInt64(buf, xrefOffset)
	buf = append(buf, "\n%%EOF\n"...)

	return buf, offsets, nil
}

// appendPDFTextString writes s as a PDF string owned by object (objNr, gen):
// an escaped literal for plain documents, or the AES ciphertext as a hex
// string when the document is encrypted.
func appendPDFTextString(buf []byte, s string, fc *fileCrypt, objNr, gen int) []byte {
	if fc == nil {
		buf = append(buf, '(')
		buf = appendPDFEscaped(buf, s)
		return append(buf, ')')
	}
	ct := fc.encryptBytes(objNr, gen, []byte(s))
	buf = append(buf, '<')
	for _, b := range ct {
		buf = append(buf, upperHexChars[b>>4], upperHexChars[b&0x0F])
	}
	return append(buf, '>')
}

// appendDictWithoutKey copies raw dict content to buf, removing the specified
// top-level key entry. key is given without its leading slash.
func appendDictWithoutKey(buf []byte, raw []byte, key string) []byte {
	entryStart, valueEnd := dictKeyRange(raw, key)
	if entryStart < 0 {
		// Key not found, copy everything.
		return append(buf, raw...)
	}

	// Copy before + after the entry.
	buf = append(buf, raw[:entryStart]...)
	buf = append(buf, raw[valueEnd:]...)
	return buf
}

// appendDictWithoutKeys2 copies raw dict content to buf, removing both key entries.
func appendDictWithoutKeys2(buf []byte, raw []byte, keyA, keyB string) []byte {
	startA, endA := dictKeyRange(raw, keyA)
	startB, endB := dictKeyRange(raw, keyB)

	if startA < 0 {
		return appendDictWithoutKey(buf, raw, keyB)
	}
	if startB < 0 {
		return appendDictWithoutKey(buf, raw, keyA)
	}

	// Order the two removal ranges. Top-level key ranges never overlap
	// (findValueEnd stops before the next top-level key), so after ordering
	// startB >= endA always holds.
	if startB < startA {
		startA, endA, startB, endB = startB, endB, startA, endA
	}

	buf = append(buf, raw[:startA]...)
	buf = append(buf, raw[endA:startB]...)
	buf = append(buf, raw[endB:]...)
	return buf
}

// dictKeyRange returns the byte range [entryStart, valueEnd) covering a
// top-level /Key plus its value inside raw dict content, or (-1, -1) when the
// key is absent. Whitespace preceding the key is left in place: it is harmless
// inside a dictionary, and it may be the line ending that terminates a
// %-comment before the key.
func dictKeyRange(raw []byte, key string) (int, int) {
	pos := findTopLevelKey(raw, key)
	if pos < 0 {
		return -1, -1
	}

	// Skip past the key and any whitespace before the value.
	keyEnd := pos + 1 + len(key)
	for keyEnd < len(raw) && isSpace(raw[keyEnd]) {
		keyEnd++
	}

	return pos, findValueEnd(raw, keyEnd)
}

// resolveParams merges per-document SignParams with the Config defaults.
func (s *Signer) resolveParams(params SignParams) (reason, contact, location string, page int, rect Rectangle, visible bool) {
	reason = s.cfg.Reason
	if params.Reason != "" {
		reason = params.Reason
	}
	contact = s.cfg.Contact
	if params.Contact != "" {
		contact = params.Contact
	}
	location = s.cfg.Location
	if params.Location != "" {
		location = params.Location
	}
	page = s.cfg.Page
	if params.Page > 0 {
		page = params.Page
	}
	if page < 1 {
		page = 1
	}
	rect = s.cfg.Rect
	if params.Rect != nil {
		rect = *params.Rect
	}
	rect = normalizeRectangle(rect)
	visible = s.cfg.Visible
	if params.Visible != nil {
		visible = *params.Visible
	}
	return
}

func normalizeRectangle(rect Rectangle) Rectangle {
	if rect.X1 > rect.X2 {
		rect.X1, rect.X2 = rect.X2, rect.X1
	}
	if rect.Y1 > rect.Y2 {
		rect.Y1, rect.Y2 = rect.Y2, rect.Y1
	}
	return rect
}
