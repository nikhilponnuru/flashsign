package flashsign

import (
	"bytes"
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

// Package-level key byte slices for appendDictWithoutKey (avoids string concat + []byte alloc).
var (
	kwSlashAcroForm = []byte("/AcroForm")
	kwSlashAnnots   = []byte("/Annots")
)

func (s *Signer) buildIncrement(buf []byte, pi *pdfInfo, srcSize int64, reason, contact, location string, rect Rectangle, visible bool, signingTime time.Time) ([]byte, incrOffsets, error) {
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

	buf = buf[:0]
	buf = append(buf, '\n')

	// Track xref entries in a fixed-size array (max 6 objects: sig, widget, appearance, font, catalog, page).
	type xrefEnt struct {
		objNr  int
		offset int64
	}
	var xrefEntries [6]xrefEnt
	xrefCount := 0
	baseOffset := srcSize

	recordOffset := func(objNr int) {
		xrefEntries[xrefCount] = xrefEnt{objNr: objNr, offset: baseOffset + int64(len(buf))}
		xrefCount++
	}

	var offsets incrOffsets

	// === Signature Value Dictionary ===
	recordOffset(sigValueObjNr)
	buf = appendInt(buf, sigValueObjNr)
	buf = append(buf, " 0 obj\n<<\n/Type /Sig\n/Filter /Adobe.PPKLite\n/SubFilter /adbe.pkcs7.detached\n"...)
	offsets.byteRangeInIncr = len(buf)
	buf = append(buf, byteRangePlaceholder...)
	buf = append(buf, '\n')
	buf = append(buf, "/Contents <"...)
	offsets.contentsHexInIncr = len(buf)
	buf = append(buf, s.contentsZeros...)
	offsets.contentsHexEndIncr = len(buf)
	buf = append(buf, ">\n"...)
	if s.signerNameStr != "" {
		buf = append(buf, "/Name ("...)
		buf = appendPDFEscaped(buf, s.signerNameStr)
		buf = append(buf, ")\n"...)
	}
	if reason != "" {
		buf = append(buf, "/Reason ("...)
		buf = appendPDFEscaped(buf, reason)
		buf = append(buf, ")\n"...)
	}
	if contact != "" {
		buf = append(buf, "/ContactInfo ("...)
		buf = appendPDFEscaped(buf, contact)
		buf = append(buf, ")\n"...)
	}
	if location != "" {
		buf = append(buf, "/Location ("...)
		buf = appendPDFEscaped(buf, location)
		buf = append(buf, ")\n"...)
	}
	buf = append(buf, "/M ("...)
	buf = appendPDFDate(buf, signingTime)
	buf = append(buf, ")\n>>\nendobj\n\n"...)

	// === Widget Annotation ===
	recordOffset(widgetObjNr)
	buf = appendInt(buf, widgetObjNr)
	buf = append(buf, " 0 obj\n<<\n/Type /Annot\n/Subtype /Widget\n/FT /Sig\n/T (Signature1)\n/V "...)
	buf = appendInt(buf, sigValueObjNr)
	buf = append(buf, " 0 R\n/F 132\n/P "...)
	buf = appendInt(buf, pi.pageObjNr)
	buf = append(buf, " 0 R\n"...)
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
		recordOffset(fontObjNr)
		buf = appendInt(buf, fontObjNr)
		buf = append(buf, " 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>\nendobj\n\n"...)

		// Form XObject with placeholder /Length (patched after stream content).
		recordOffset(appearanceObjNr)
		buf = appendInt(buf, appearanceObjNr)
		buf = append(buf, " 0 obj\n<<\n/Type /XObject\n/Subtype /Form\n/FormType 1\n/BBox [0 0 "...)
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
		buf = appendAppearanceStream(buf, rect, s.signerNameStr, reason, location, signingTime)
		streamLen := len(buf) - streamStart
		buf = append(buf, "\nendstream\nendobj\n\n"...)
		// Patch /Length value in-place.
		patchDecimal(buf, lengthPos, 6, streamLen)
	}

	// === Modified Catalog ===
	recordOffset(pi.catalogObjNr)
	buf = appendInt(buf, pi.catalogObjNr)
	buf = append(buf, " 0 obj\n<<"...)
	// Copy raw catalog dict, removing /AcroForm.
	buf = appendDictWithoutKey(buf, pi.catalogRaw, kwSlashAcroForm)
	buf = append(buf, "\n/AcroForm << /Fields ["...)
	if pi.existingFields != nil && len(pi.existingFields) > 0 {
		buf = append(buf, ' ')
		buf = append(buf, pi.existingFields...)
	}
	buf = append(buf, ' ')
	buf = appendInt(buf, widgetObjNr)
	buf = append(buf, " 0 R] /SigFlags 3 >>"...)
	buf = append(buf, "\n>>\nendobj\n\n"...)

	// === Modified Page ===
	recordOffset(pi.pageObjNr)
	buf = appendInt(buf, pi.pageObjNr)
	buf = append(buf, " 0 obj\n<<"...)
	// Copy raw page dict, removing /Annots.
	buf = appendDictWithoutKey(buf, pi.pageRaw, kwSlashAnnots)
	buf = append(buf, "\n/Annots ["...)
	if pi.existingAnnots != nil && len(pi.existingAnnots) > 0 {
		buf = append(buf, ' ')
		buf = append(buf, pi.existingAnnots...)
	}
	buf = append(buf, ' ')
	buf = appendInt(buf, widgetObjNr)
	buf = append(buf, " 0 R]"...)
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
		buf = append(buf, " 00000 n \r\n"...)
	}

	// === Trailer ===
	buf = append(buf, "trailer\n<<\n/Size "...)
	buf = appendInt(buf, nextObj)
	buf = append(buf, "\n/Root "...)
	buf = appendInt(buf, pi.catalogObjNr)
	buf = append(buf, " 0 R\n"...)
	if pi.infoObjNr > 0 {
		buf = append(buf, "/Info "...)
		buf = appendInt(buf, pi.infoObjNr)
		buf = append(buf, " 0 R\n"...)
	}
	if pi.idArray != nil && len(pi.idArray) > 0 {
		buf = append(buf, "/ID "...)
		buf = append(buf, pi.idArray...)
		buf = append(buf, '\n')
	}
	buf = append(buf, "/Prev "...)
	buf = appendInt64(buf, pi.prevXrefOffset)
	buf = append(buf, "\n>>\nstartxref\n"...)
	buf = appendInt64(buf, xrefOffset)
	buf = append(buf, "\n%%EOF\n"...)

	return buf, offsets, nil
}

// appendDictWithoutKey copies raw dict content to buf, removing the specified key entry.
// key must be a package-level []byte like kwSlashAcroForm (avoids string alloc).
func appendDictWithoutKey(buf []byte, raw []byte, key []byte) []byte {
	pos := findTopLevelKey(raw, key)
	if pos < 0 {
		// Key not found, copy everything.
		return append(buf, raw...)
	}

	// Find the start of this entry (trim preceding newline/space).
	entryStart := pos
	for entryStart > 0 && isSpace(raw[entryStart-1]) {
		entryStart--
	}

	// Skip past the key.
	keyEnd := pos + len(key)
	// Skip whitespace after key.
	for keyEnd < len(raw) && raw[keyEnd] == ' ' {
		keyEnd++
	}

	// Find end of value.
	valueEnd := findValueEnd(raw, keyEnd)

	// Copy before + after the entry.
	buf = append(buf, raw[:entryStart]...)
	buf = append(buf, raw[valueEnd:]...)
	return buf
}

// findTopLevelKey finds a /Key at the top level (depth 0) of dict content.
func findTopLevelKey(dict []byte, key []byte) int {
	depth := 0
	inString := false

	for i := 0; i < len(dict); {
		b := dict[i]

		if inString {
			if b == '\\' && i+1 < len(dict) {
				i += 2
				continue
			}
			if b == ')' {
				inString = false
			}
			i++
			continue
		}

		switch b {
		case '(':
			inString = true
			i++
			continue
		case '<':
			if i+1 < len(dict) && dict[i+1] == '<' {
				depth++
				i += 2
				continue
			}
		case '>':
			if i+1 < len(dict) && dict[i+1] == '>' {
				depth--
				i += 2
				continue
			}
		}

		if depth == 0 && b == '/' && bytes.HasPrefix(dict[i:], key) {
			endOfKey := i + len(key)
			if endOfKey >= len(dict) || isPDFDelimiter(dict[endOfKey]) {
				return i
			}
		}

		i++
	}
	return -1
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
