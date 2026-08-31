package flashsign

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"fmt"
	"io"
	"sync"
)

// pdfInfo holds the minimal PDF metadata needed for signing.
type pdfInfo struct {
	nextObjNr        int
	prevXrefOffset   int64
	catalogObjNr     int
	catalogGen       int // generation of the catalog object, echoed by the rewrite
	pageObjNr        int
	pageGen          int    // generation of the signature page object
	catalogRaw       []byte // raw catalog dict content (between << and >>)
	pageRaw          []byte // raw page dict content
	acroFormRaw      []byte // raw /AcroForm dict content, or nil when absent
	existingFields   []byte // raw /Fields array content, or nil
	existingAnnots   []byte // raw /Annots array content, or nil
	signatureFieldNr int    // first unused SignatureN field name
	infoObjNr        int    // /Info object number, or 0
	infoGen          int    // /Info generation
	idArray          []byte // raw /ID array bytes including [ ], or nil

	// Encryption state, set only for encrypted documents (see parsePDFAny).
	encryptRaw     []byte // raw trailer /Encrypt value, echoed into the increment's trailer
	encryptDictRaw []byte // raw /Encrypt dict content
	idFirst        []byte // decoded first /ID element, input to key derivation

	// Accessibility (tagged PDF) related state.
	tagged           bool   // /StructTreeRoot present or /MarkInfo << /Marked true >>
	viewerPrefsObjNr int    // gen-0 indirect /ViewerPreferences object to rewrite; 0 = inline/absent; -1 = leave untouched
	viewerPrefsRaw   []byte // raw /ViewerPreferences dict content, or nil when absent
	pageHasTabs      bool   // target page already has a top-level /Tabs entry
}

// xrefEntry represents a cross-reference entry.
type xrefEntry struct {
	offset      int64
	gen         int
	free        bool
	compressed  bool
	objStreamNr int
	index       int
}

// Package-level keyword byte slices to avoid repeated string-to-bytes conversions.
var (
	kwObj       = []byte("obj")
	kwXref      = []byte("xref")
	kwTrailer   = []byte("trailer")
	kwStream    = []byte("stream")
	kwEndstream = []byte("endstream")
	kwStartxref = []byte("startxref")
	kwPage      = []byte("Page")
)

// xrefMapPool provides reusable maps for xref parsing.
var xrefMapPool = sync.Pool{
	New: func() any { return make(map[int]xrefEntry, 64) },
}

// parsePDF parses a PDF byte slice and extracts the minimal info needed for
// signing. Encrypted documents are rejected: appending an increment to one
// requires encrypting the new strings with the file key, which only the
// password-aware SignAndEncrypt path (via parsePDFAny) can do.
func parsePDF(data []byte, targetPage int) (pdfInfo, error) {
	pi, err := parsePDFAny(data, targetPage)
	if err == nil && pi.encryptRaw != nil {
		return pdfInfo{}, fmt.Errorf("PDF is encrypted; decrypt it before signing")
	}
	return pi, err
}

// parsePDFAny is parsePDF without the encryption gate; for an encrypted
// document it also resolves the /Encrypt dict and the first /ID element.
// Returns pdfInfo by value (zero allocation for the struct).
func parsePDFAny(data []byte, targetPage int) (pdfInfo, error) {
	if targetPage < 1 {
		targetPage = 1
	}

	// Find startxref offset.
	prevXrefOffset, err := findStartxref(data)
	if err != nil {
		return pdfInfo{}, fmt.Errorf("find startxref: %w", err)
	}

	// Parse xref chain to build complete object table.
	xref, trailer, err := parseXrefChain(data, prevXrefOffset)
	if err != nil {
		return pdfInfo{}, fmt.Errorf("parse xref: %w", err)
	}
	defer func() {
		clear(xref)
		xrefMapPool.Put(xref)
	}()

	var encryptDictRaw, idFirst []byte
	if trailer.encryptRaw != nil {
		encryptDictRaw = resolveDictOrRef(data, xref, trailer.encryptRaw)
		if encryptDictRaw == nil {
			return pdfInfo{}, fmt.Errorf("cannot resolve /Encrypt dictionary")
		}
		if ids := extractArrayContent(trailer.idArray); ids != nil {
			first := skipWhitespaceInSlice(ids, 0)
			idFirst = decodePDFString(ids[first:findValueEnd(ids, first)])
		}
		if len(idFirst) == 0 {
			return pdfInfo{}, fmt.Errorf("encrypted PDF has no usable /ID")
		}
	}

	// Read catalog object.
	catalogRaw, err := resolveObjectDict(data, xref, trailer.rootObjNr)
	if err != nil {
		return pdfInfo{}, fmt.Errorf("read catalog object %d: %w", trailer.rootObjNr, err)
	}

	// Extract /Pages reference from catalog.
	pagesVal := extractDictValue(catalogRaw, "Pages")
	if pagesVal == nil {
		return pdfInfo{}, fmt.Errorf("catalog has no /Pages entry")
	}
	pagesObjNr, _, err := extractIndirectRef(pagesVal)
	if err != nil {
		return pdfInfo{}, fmt.Errorf("parse /Pages ref: %w", err)
	}

	// Walk page tree to find target page.
	pageObjNr, pageRaw, err := resolvePageFromTree(data, xref, pagesObjNr, targetPage)
	if err != nil {
		return pdfInfo{}, fmt.Errorf("resolve page %d: %w", targetPage, err)
	}

	// Extract existing /AcroForm /Fields if present.
	var acroFormRaw, existingFields []byte
	acroFormVal := extractDictValue(catalogRaw, "AcroForm")
	if acroFormVal != nil && !isPDFNull(acroFormVal) {
		// /AcroForm can be a direct dict or indirect ref.
		if isIndirectRef(acroFormVal) {
			objNr, _, err := extractIndirectRef(acroFormVal)
			if err != nil {
				return pdfInfo{}, fmt.Errorf("parse /AcroForm ref: %w", err)
			}
			acroFormRaw, err = resolveOptionalDict(data, xref, objNr)
			if err != nil {
				return pdfInfo{}, fmt.Errorf("resolve /AcroForm object %d: %w", objNr, err)
			}
		} else if bytes.HasPrefix(bytes.TrimSpace(acroFormVal), []byte("<<")) {
			acroFormRaw = extractDictContent(acroFormVal)
		} else {
			return pdfInfo{}, fmt.Errorf("invalid /AcroForm value")
		}
		if acroFormRaw != nil {
			// A null /Fields equals an absent one (PDF 32000-1 7.3.7).
			fieldsVal := extractDictValue(acroFormRaw, "Fields")
			if fieldsVal != nil && !isPDFNull(fieldsVal) {
				existingFields, err = resolveArrayContent(data, xref, fieldsVal)
				if err != nil {
					return pdfInfo{}, fmt.Errorf("resolve /AcroForm /Fields: %w", err)
				}
			}
		}
	}

	signatureFieldNr := nextSignatureFieldNumber(data, xref, existingFields)

	// Extract existing /Annots if present.
	var existingAnnots []byte
	annotsVal := extractDictValue(pageRaw, "Annots")
	if annotsVal != nil && !isPDFNull(annotsVal) {
		existingAnnots, err = resolveArrayContent(data, xref, annotsVal)
		if err != nil {
			return pdfInfo{}, fmt.Errorf("resolve page /Annots: %w", err)
		}
	}

	// Accessibility state: tagged documents need /DisplayDocTitle and /Tabs /S.
	// Untagged documents skip the extra catalog/page scans entirely.
	tagged := isTaggedCatalog(data, xref, catalogRaw)
	var vpObjNr int
	var vpRaw []byte
	pageHasTabs := false
	if tagged {
		vpObjNr, vpRaw = resolveViewerPrefs(data, xref, catalogRaw)
		if vpObjNr > 0 && (vpObjNr == trailer.rootObjNr || vpObjNr == pageObjNr) {
			// Degenerate self-reference; leave viewer preferences untouched.
			vpObjNr, vpRaw = -1, nil
		} else if vpObjNr >= trailer.size {
			// Object exists but lies beyond the trailer /Size (understated in
			// sloppy real-world files); merge inline instead of emitting an
			// object number the increment reserves for new objects.
			vpObjNr = 0
		}
		pageHasTabs = findTopLevelKey(pageRaw, "Tabs") >= 0
	}

	// Sloppy producers understate the trailer /Size; allocating new object
	// numbers from it would then collide with existing objects. Trust whichever
	// is larger: /Size or the highest object number actually cross-referenced.
	nextObjNr := trailer.size
	for objNr := range xref {
		if objNr >= nextObjNr {
			nextObjNr = objNr + 1
		}
	}

	return pdfInfo{
		nextObjNr:        nextObjNr,
		prevXrefOffset:   prevXrefOffset,
		catalogObjNr:     trailer.rootObjNr,
		catalogGen:       xref[trailer.rootObjNr].gen,
		pageObjNr:        pageObjNr,
		pageGen:          xref[pageObjNr].gen,
		catalogRaw:       catalogRaw,
		pageRaw:          pageRaw,
		acroFormRaw:      acroFormRaw,
		existingFields:   existingFields,
		existingAnnots:   existingAnnots,
		signatureFieldNr: signatureFieldNr,
		infoObjNr:        trailer.infoObjNr,
		infoGen:          trailer.infoGen,
		idArray:          trailer.idArray,
		encryptRaw:       trailer.encryptRaw,
		encryptDictRaw:   encryptDictRaw,
		idFirst:          idFirst,

		tagged:           tagged,
		viewerPrefsObjNr: vpObjNr,
		viewerPrefsRaw:   vpRaw,
		pageHasTabs:      pageHasTabs,
	}, nil
}

// startxrefSearchWindow is how far back from EOF the trailing "startxref" is
// looked for. Generous enough to survive producers that append a little junk
// after %%EOF.
const startxrefSearchWindow = 2048

// findStartxref finds the byte offset of the most recent xref from the PDF tail.
func findStartxref(data []byte) (int64, error) {
	searchStart := len(data) - startxrefSearchWindow
	if searchStart < 0 {
		searchStart = 0
	}
	tail := data[searchStart:]

	idx := bytes.LastIndex(tail, kwStartxref)
	if idx == -1 {
		return 0, fmt.Errorf("startxref not found")
	}

	rest := tail[idx+len(kwStartxref):]
	i := 0
	for i < len(rest) && isSpace(rest[i]) {
		i++
	}
	j := i
	for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		j++
	}
	if j == i {
		return 0, fmt.Errorf("no offset after startxref")
	}
	var offset int64
	for k := i; k < j; k++ {
		offset = offset*10 + int64(rest[k]-'0')
	}
	return offset, nil
}

// trailerInfo holds fields extracted from a PDF trailer.
type trailerInfo struct {
	size       int
	rootObjNr  int
	rootGen    int
	infoObjNr  int
	infoGen    int
	idArray    []byte
	prevXref   int64
	xrefStm    int64  // hybrid-reference file: offset of the companion xref stream, or 0
	encryptRaw []byte // raw /Encrypt value, or nil when unencrypted
}

// parseXrefChain follows the /Prev chain to build a complete xref table.
// Uses a pooled map to avoid per-call map allocation.
func parseXrefChain(data []byte, startOffset int64) (map[int]xrefEntry, trailerInfo, error) {
	xref := xrefMapPool.Get().(map[int]xrefEntry)
	clear(xref)

	var firstTrailer trailerInfo
	first := true

	// A /Prev chain that loops back on itself would otherwise spin forever, so
	// remember the sections already visited. Kept as a fixed array: the chain is
	// short in practice and this keeps the parser allocation-free.
	const maxXrefSections = 64
	var visited [maxXrefSections]int64
	visitedCount := 0

	offset := startOffset
	for offset >= 0 {
		for _, seen := range visited[:visitedCount] {
			if seen == offset {
				clear(xref)
				xrefMapPool.Put(xref)
				return nil, trailerInfo{}, fmt.Errorf("cyclic /Prev chain at offset %d", offset)
			}
		}
		if visitedCount == maxXrefSections {
			clear(xref)
			xrefMapPool.Put(xref)
			return nil, trailerInfo{}, fmt.Errorf("xref chain longer than %d sections", maxXrefSections)
		}
		visited[visitedCount] = offset
		visitedCount++

		var trailer trailerInfo
		var err error

		if offset >= int64(len(data)) {
			clear(xref)
			xrefMapPool.Put(xref)
			return nil, trailerInfo{}, fmt.Errorf("xref offset %d beyond end of file (%d bytes)", offset, len(data))
		}

		// Determine if this is a traditional xref table or xref stream.
		if bytes.HasPrefix(data[offset:], kwXref) {
			trailer, err = parseTraditionalXref(data, offset, xref)
			if err == nil && trailer.xrefStm > 0 {
				// Hybrid-reference file (PDF 32000-1 7.5.8.4): objects held in
				// object streams are listed only in this companion xref stream,
				// which readers consult after the table and before /Prev.
				if trailer.xrefStm >= int64(len(data)) {
					err = fmt.Errorf("/XRefStm offset %d beyond end of file", trailer.xrefStm)
				} else {
					_, err = parseXrefStream(data, trailer.xrefStm, xref, true)
				}
			}
		} else {
			trailer, err = parseXrefStream(data, offset, xref, false)
		}
		if err != nil {
			// Return map to pool on error.
			clear(xref)
			xrefMapPool.Put(xref)
			return nil, trailerInfo{}, fmt.Errorf("parse xref at offset %d: %w", offset, err)
		}

		if first {
			firstTrailer = trailer
			first = false
		}

		if trailer.prevXref > 0 {
			offset = trailer.prevXref
		} else {
			offset = -1
		}
	}

	return xref, firstTrailer, nil
}

// parseTraditionalXref parses a traditional "xref\n..." cross-reference table.
// Writes entries directly into xref with "first write wins" semantics.
func parseTraditionalXref(data []byte, offset int64, xref map[int]xrefEntry) (trailerInfo, error) {
	pos := int(offset)

	// Skip "xref" keyword and whitespace.
	if !bytes.HasPrefix(data[pos:], kwXref) {
		return trailerInfo{}, fmt.Errorf("expected 'xref' at offset %d", offset)
	}
	pos += 4
	pos = skipWhitespace(data, pos)

	// Parse subsections until "trailer" keyword.
	for pos < len(data) {
		if bytes.HasPrefix(data[pos:], kwTrailer) {
			break
		}

		// Parse subsection header: startObjNr count
		startObjNr, n := parseInt(data, pos)
		if n == 0 {
			break
		}
		pos += n
		pos = skipWhitespace(data, pos)

		count, n := parseInt(data, pos)
		if n == 0 {
			return trailerInfo{}, fmt.Errorf("expected count in xref subsection")
		}
		pos += n
		pos = skipWhitespace(data, pos)

		// Parse entries line by line (handles 20-byte and non-standard entries).
		for i := 0; i < count; i++ {
			if pos >= len(data) {
				return trailerInfo{}, fmt.Errorf("truncated xref entry")
			}
			// Find end of line.
			lineEnd := pos
			for lineEnd < len(data) && data[lineEnd] != '\n' && data[lineEnd] != '\r' {
				lineEnd++
			}
			line := data[pos:lineEnd]

			// Skip past line ending.
			if lineEnd < len(data) && data[lineEnd] == '\r' {
				lineEnd++
			}
			if lineEnd < len(data) && data[lineEnd] == '\n' {
				lineEnd++
			}
			pos = lineEnd

			// Parse "OOOOOOOOOO GGGGG f/n" (at least 18 meaningful bytes).
			if len(line) < 18 {
				continue
			}
			entryOffset := parseInt64Bytes(line, 0, 10)
			gen := parseIntBytes(line, 11, 16)
			inUse := false
			for _, b := range line[16:] {
				if b == 'n' {
					inUse = true
					break
				}
				if b == 'f' {
					break
				}
			}

			objNr := startObjNr + i
			if objNr > 0 {
				if _, exists := xref[objNr]; !exists {
					xref[objNr] = xrefEntry{offset: entryOffset, gen: gen, free: !inUse}
				}
			}
		}
		pos = skipWhitespace(data, pos)
	}

	// Parse trailer dict.
	trailerPos := bytes.Index(data[pos:], kwTrailer)
	if trailerPos == -1 {
		return trailerInfo{}, fmt.Errorf("trailer not found")
	}
	pos += trailerPos + 7
	pos = skipWhitespace(data, pos)

	trailer, err := parseTrailerDict(data, pos)
	if err != nil {
		return trailerInfo{}, err
	}

	return trailer, nil
}

// parseXrefStream parses a cross-reference stream object (PDF 1.5+).
// Writes entries directly into xref with "first write wins" semantics.
//
// hybrid is set when the stream is a classic table's /XRefStm companion. Such a
// table lists the objects that live in object streams as free (so readers
// without object-stream support ignore them), and the stream's entries take
// precedence over those free entries.
func parseXrefStream(data []byte, offset int64, xref map[int]xrefEntry, hybrid bool) (trailerInfo, error) {
	pos := int(offset)

	// Skip object header: "N G obj"
	pos = skipPastKeyword(data, pos, kwObj)
	if pos < 0 {
		return trailerInfo{}, fmt.Errorf("obj keyword not found at offset %d", offset)
	}

	// Read the stream dict.
	dictContent, dictEnd, err := readDictAt(data, pos)
	if err != nil {
		return trailerInfo{}, fmt.Errorf("read xref stream dict: %w", err)
	}

	// Extract trailer fields from the stream dict (which serves as the trailer).
	trailer := extractTrailerFields(dictContent)

	// Extract /W array (column widths).
	wVal := extractDictValue(dictContent, "W")
	if wVal == nil {
		return trailerInfo{}, fmt.Errorf("xref stream missing /W")
	}
	wArr := extractArrayContent(wVal)
	if wArr == nil {
		return trailerInfo{}, fmt.Errorf("invalid /W array")
	}
	w := parseIntArray(wArr)
	if len(w) < 3 {
		return trailerInfo{}, fmt.Errorf("/W array must have 3 elements, got %d", len(w))
	}
	entrySize := w[0] + w[1] + w[2]
	if entrySize == 0 {
		return trailerInfo{}, fmt.Errorf("invalid /W entry size")
	}

	// Extract /Index array (optional, defaults to [0 Size]).
	var indexPairs [][2]int
	indexVal := extractDictValue(dictContent, "Index")
	if indexVal != nil {
		indexArr := extractArrayContent(indexVal)
		if indexArr != nil {
			nums := parseIntArray(indexArr)
			for i := 0; i+1 < len(nums); i += 2 {
				indexPairs = append(indexPairs, [2]int{nums[i], nums[i+1]})
			}
		}
	}
	if len(indexPairs) == 0 {
		indexPairs = [][2]int{{0, trailer.size}}
	}

	// Read and decompress stream data.
	streamData, err := readStreamData(data, dictContent, dictEnd)
	if err != nil {
		return trailerInfo{}, fmt.Errorf("read xref stream data: %w", err)
	}

	// Parse entries from stream data — write directly into xref.
	dataPos := 0
	for _, pair := range indexPairs {
		startObj := pair[0]
		count := pair[1]
		for i := 0; i < count; i++ {
			if dataPos+entrySize > len(streamData) {
				break
			}
			entryType := readUint(streamData[dataPos:dataPos+w[0]], w[0])
			field2 := readUint(streamData[dataPos+w[0]:dataPos+w[0]+w[1]], w[1])
			field3 := readUint(streamData[dataPos+w[0]+w[1]:dataPos+entrySize], w[2])
			dataPos += entrySize

			objNr := startObj + i
			switch {
			case w[0] == 0 || entryType == 1: // type 1: regular object
				if objNr > 0 {
					if existing, exists := xref[objNr]; !exists || (hybrid && existing.free) {
						xref[objNr] = xrefEntry{offset: int64(field2), gen: int(field3)}
					}
				}
			case entryType == 2: // type 2: compressed object
				if objNr > 0 {
					if existing, exists := xref[objNr]; !exists || (hybrid && existing.free) {
						xref[objNr] = xrefEntry{compressed: true, objStreamNr: int(field2), index: int(field3)}
					}
				}
			case entryType == 0: // free; do not resurrect an older /Prev entry
				if objNr > 0 {
					if _, exists := xref[objNr]; !exists {
						xref[objNr] = xrefEntry{free: true, gen: int(field3)}
					}
				}
			}
		}
	}

	return trailer, nil
}

// readUint reads an unsigned integer from n big-endian bytes.
func readUint(b []byte, n int) int {
	val := 0
	for i := 0; i < n; i++ {
		val = val<<8 | int(b[i])
	}
	return val
}

// readStreamData reads and optionally decompresses stream data after a dict.
func readStreamData(data []byte, dictContent []byte, dictEnd int) ([]byte, error) {
	pos := skipWhitespace(data, dictEnd)

	// Expect "stream" keyword.
	if !bytes.HasPrefix(data[pos:], kwStream) {
		return nil, fmt.Errorf("expected 'stream' keyword at %d", pos)
	}
	pos += len(kwStream)
	// Skip \r\n or \n after "stream".
	if pos < len(data) && data[pos] == '\r' {
		pos++
	}
	if pos < len(data) && data[pos] == '\n' {
		pos++
	}

	streamBytes, ok := streamBytesByLength(data, dictContent, pos)
	if !ok {
		// No usable /Length (missing, or an indirect reference): fall back to
		// scanning for the keyword.
		endIdx := bytes.Index(data[pos:], kwEndstream)
		if endIdx == -1 {
			return nil, fmt.Errorf("endstream not found")
		}
		streamBytes = bytes.TrimRight(data[pos:pos+endIdx], " \r\n")
	}

	// Check /Filter.
	filterVal := extractDictValue(dictContent, "Filter")
	if filterVal != nil && bytes.Contains(filterVal, []byte("FlateDecode")) {
		inflated, err := inflateBytes(streamBytes)
		if err != nil {
			return nil, err
		}
		return applyDecodeParms(dictContent, inflated)
	}
	return streamBytes, nil
}

// applyDecodeParms undoes the /DecodeParms predictor applied before Flate
// compression. Xref and object streams from mainstream producers (Acrobat,
// Chrome, Ghostscript) near-universally use a PNG predictor.
func applyDecodeParms(dictContent, data []byte) ([]byte, error) {
	parms := extractDictValue(dictContent, "DecodeParms")
	if parms == nil {
		return data, nil
	}
	// A single-filter pipeline may still wrap its parms in a one-element array.
	if arr := extractArrayContent(parms); arr != nil {
		parms = arr
	}
	parmsDict := extractDictContent(parms)
	if parmsDict == nil {
		// null, or a form this parser cannot use: nothing to undo.
		return data, nil
	}

	predictor := extractDictInt(parmsDict, "Predictor", 1)
	if predictor <= 1 {
		return data, nil
	}
	if predictor < 10 {
		return nil, fmt.Errorf("unsupported /Predictor %d (only PNG predictors are supported)", predictor)
	}
	columns := extractDictInt(parmsDict, "Columns", 1)
	colors := extractDictInt(parmsDict, "Colors", 1)
	bpc := extractDictInt(parmsDict, "BitsPerComponent", 8)
	bytesPerPixel := (colors*bpc + 7) / 8
	rowLen := (columns*colors*bpc + 7) / 8
	return unpredictPNG(data, rowLen, bytesPerPixel)
}

// unpredictPNG reverses PNG row filtering (RFC 2083): each row is one filter
// tag byte followed by rowLen filtered bytes.
func unpredictPNG(data []byte, rowLen, bytesPerPixel int) ([]byte, error) {
	if rowLen <= 0 {
		return nil, fmt.Errorf("invalid predictor row length %d", rowLen)
	}
	if bytesPerPixel <= 0 {
		bytesPerPixel = 1
	}
	stride := rowLen + 1
	if len(data)%stride != 0 {
		return nil, fmt.Errorf("predictor data length %d is not a multiple of row size %d", len(data), stride)
	}

	rows := len(data) / stride
	out := make([]byte, 0, rows*rowLen)
	prev := make([]byte, rowLen)
	cur := make([]byte, rowLen)

	for r := 0; r < rows; r++ {
		filterType := data[r*stride]
		copy(cur, data[r*stride+1:(r+1)*stride])

		switch filterType {
		case 0: // None
		case 1: // Sub
			for i := bytesPerPixel; i < rowLen; i++ {
				cur[i] += cur[i-bytesPerPixel]
			}
		case 2: // Up
			for i := 0; i < rowLen; i++ {
				cur[i] += prev[i]
			}
		case 3: // Average
			for i := 0; i < rowLen; i++ {
				left := 0
				if i >= bytesPerPixel {
					left = int(cur[i-bytesPerPixel])
				}
				cur[i] += byte((left + int(prev[i])) / 2)
			}
		case 4: // Paeth
			for i := 0; i < rowLen; i++ {
				var left, upLeft byte
				if i >= bytesPerPixel {
					left = cur[i-bytesPerPixel]
					upLeft = prev[i-bytesPerPixel]
				}
				cur[i] += paethPredictor(left, prev[i], upLeft)
			}
		default:
			return nil, fmt.Errorf("invalid PNG filter type %d", filterType)
		}

		out = append(out, cur...)
		prev, cur = cur, prev
	}
	return out, nil
}

func paethPredictor(a, b, c byte) byte {
	p := int(a) + int(b) - int(c)
	pa, pb, pc := absInt(p-int(a)), absInt(p-int(b)), absInt(p-int(c))
	if pa <= pb && pa <= pc {
		return a
	}
	if pb <= pc {
		return b
	}
	return c
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// extractDictInt reads an integer dict entry, returning def when absent or
// unparsable.
func extractDictInt(dict []byte, key string, def int) int {
	v := extractDictValue(dict, key)
	if v == nil {
		return def
	}
	n, w := parseInt(v, skipWhitespaceInSlice(v, 0))
	if w == 0 {
		return def
	}
	return n
}

// streamBytesByLength delimits the stream body using the dict's /Length, which
// is authoritative: scanning for "endstream" misreads compressed data that
// happens to contain those bytes. Reports false when /Length is absent, is an
// indirect reference, or does not land on an "endstream" keyword — in which
// case it cannot be trusted and the caller scans instead.
func streamBytesByLength(data []byte, dictContent []byte, pos int) ([]byte, bool) {
	lenVal := extractDictValue(dictContent, "Length")
	if lenVal == nil {
		return nil, false
	}
	n, width := parseInt(lenVal, skipWhitespaceInSlice(lenVal, 0))
	if width == 0 || n < 0 || pos+n > len(data) {
		return nil, false
	}
	if !bytes.HasPrefix(data[skipWhitespace(data, pos+n):], kwEndstream) {
		return nil, false
	}
	return data[pos : pos+n], true
}

// maxInflatedStream caps how far a FlateDecode stream may expand, so a
// crafted deflate bomb in an xref or object stream cannot exhaust memory.
// Real xref/object streams sit orders of magnitude below this.
const maxInflatedStream = 256 << 20

// inflateBytes decompresses FlateDecode data.
// PDF FlateDecode uses zlib (RFC 1950) wrapping deflate. We try zlib first,
// falling back to raw deflate for non-standard producers.
func inflateBytes(compressed []byte) ([]byte, error) {
	var r io.ReadCloser
	zr, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		// Fallback to raw deflate for non-standard streams.
		r = flate.NewReader(bytes.NewReader(compressed))
	} else {
		r = zr
	}
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, maxInflatedStream+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxInflatedStream {
		return nil, fmt.Errorf("decompressed stream exceeds %d bytes", maxInflatedStream)
	}
	return out, nil
}

// parseTrailerDict parses a trailer dictionary at pos.
func parseTrailerDict(data []byte, pos int) (trailerInfo, error) {
	dictContent, _, err := readDictAt(data, pos)
	if err != nil {
		return trailerInfo{}, fmt.Errorf("parse trailer dict: %w", err)
	}
	return extractTrailerFields(dictContent), nil
}

// extractTrailerFields extracts trailer-relevant fields from raw dict content.
func extractTrailerFields(dict []byte) trailerInfo {
	var t trailerInfo

	if v := extractDictValue(dict, "Size"); v != nil {
		p := skipWhitespaceInSlice(v, 0)
		t.size, _ = parseInt(v, p)
	}
	if v := extractDictValue(dict, "Root"); v != nil {
		t.rootObjNr, t.rootGen, _ = extractIndirectRef(v)
	}
	if v := extractDictValue(dict, "Info"); v != nil {
		t.infoObjNr, t.infoGen, _ = extractIndirectRef(v)
	}
	if v := extractDictValue(dict, "Prev"); v != nil {
		p := skipWhitespaceInSlice(v, 0)
		t.prevXref, _ = parseInt64(v, p)
	}
	if v := extractDictValue(dict, "ID"); v != nil {
		// Store the raw /ID value including the array brackets.
		t.idArray = v
	}
	if v := extractDictValue(dict, "Encrypt"); v != nil && !isPDFNull(v) {
		t.encryptRaw = v
	}
	if v := extractDictValue(dict, "XRefStm"); v != nil {
		p := skipWhitespaceInSlice(v, 0)
		n, w := parseInt(v, p)
		if w > 0 && n > 0 {
			t.xrefStm = int64(n)
		}
	}

	return t
}

// readDictAt reads a PDF dictionary at pos, returning the content between << and >>
// and the position after the closing >>.
func readDictAt(data []byte, pos int) ([]byte, int, error) {
	pos = skipWhitespace(data, pos)
	if pos+2 > len(data) || data[pos] != '<' || data[pos+1] != '<' {
		return nil, 0, fmt.Errorf("expected '<<' at %d, got %q", pos, safeSlice(data, pos, pos+2))
	}
	pos += 2
	start := pos
	depth := 1

	for pos < len(data) && depth > 0 {
		b := data[pos]
		switch {
		case b == '%':
			pos = skipPDFComment(data, pos)
			continue
		case b == '(':
			pos = skipPDFStringLiteral(data, pos)
			continue
		case b == '<' && pos+1 < len(data) && data[pos+1] == '<':
			depth++
			pos += 2
			continue
		case b == '>' && pos+1 < len(data) && data[pos+1] == '>':
			depth--
			if depth == 0 {
				content := data[start:pos]
				return content, pos + 2, nil
			}
			pos += 2
			continue
		}
		pos++
	}

	return nil, 0, fmt.Errorf("unmatched dict at offset %d", start-2)
}

// resolveObjectDict reads the dict content for a given object number,
// handling both regular and compressed objects.
func resolveObjectDict(data []byte, xref map[int]xrefEntry, objNr int) ([]byte, error) {
	entry, ok := xref[objNr]
	if !ok {
		return nil, fmt.Errorf("object %d not in xref", objNr)
	}
	if entry.free {
		return nil, fmt.Errorf("object %d is free", objNr)
	}

	if entry.compressed {
		return readCompressedObject(data, xref, entry.objStreamNr, entry.index, objNr)
	}

	return readObjectDictAt(data, entry.offset)
}

// resolveOptionalDict resolves an indirect reference whose target may
// legitimately be absent: an undefined or freed object is the null object
// (PDF 32000-1 7.3.10) and a null dict entry equals an omitted one (7.3.7), so
// both report (nil, nil) rather than an error.
func resolveOptionalDict(data []byte, xref map[int]xrefEntry, objNr int) ([]byte, error) {
	entry, ok := xref[objNr]
	if !ok || entry.free {
		return nil, nil
	}
	if entry.compressed {
		obj, err := readCompressedObject(data, xref, entry.objStreamNr, entry.index, objNr)
		if err != nil {
			return nil, err
		}
		if isPDFNull(obj) {
			return nil, nil
		}
		return obj, nil
	}
	pos := skipPastKeyword(data, int(entry.offset), kwObj)
	if pos < 0 {
		return nil, fmt.Errorf("obj keyword not found at offset %d", entry.offset)
	}
	if bytes.HasPrefix(data[pos:], []byte("null")) {
		return nil, nil
	}
	content, _, err := readDictAt(data, pos)
	return content, err
}

// readObjectDictAt reads the dict content of a regular object at the given offset.
func readObjectDictAt(data []byte, offset int64) ([]byte, error) {
	pos := int(offset)
	pos = skipPastKeyword(data, pos, kwObj)
	if pos < 0 {
		return nil, fmt.Errorf("obj keyword not found at offset %d", offset)
	}
	content, _, err := readDictAt(data, pos)
	return content, err
}

// readCompressedObject reads an object from a compressed object stream.
func readCompressedObject(data []byte, xref map[int]xrefEntry, objStreamNr int, index int, targetObjNr int) ([]byte, error) {
	// Read the object stream.
	streamEntry, ok := xref[objStreamNr]
	if !ok {
		return nil, fmt.Errorf("object stream %d not in xref", objStreamNr)
	}
	if streamEntry.free {
		// A free entry's offset field is a free-list link, not a file position.
		return nil, fmt.Errorf("object stream %d is free", objStreamNr)
	}
	if streamEntry.compressed {
		return nil, fmt.Errorf("nested compressed object streams not supported")
	}

	pos := int(streamEntry.offset)
	pos = skipPastKeyword(data, pos, kwObj)
	if pos < 0 {
		return nil, fmt.Errorf("obj keyword not found for object stream %d", objStreamNr)
	}

	dictContent, dictEnd, err := readDictAt(data, pos)
	if err != nil {
		return nil, fmt.Errorf("read object stream dict: %w", err)
	}

	// Get /N (number of objects) and /First (offset to first object).
	nVal := extractDictValue(dictContent, "N")
	firstVal := extractDictValue(dictContent, "First")
	if nVal == nil || firstVal == nil {
		return nil, fmt.Errorf("object stream missing /N or /First")
	}
	n, _ := parseInt(nVal, skipWhitespaceInSlice(nVal, 0))
	first, _ := parseInt(firstVal, skipWhitespaceInSlice(firstVal, 0))

	// Read and decompress stream data.
	streamData, err := readStreamData(data, dictContent, dictEnd)
	if err != nil {
		return nil, fmt.Errorf("decompress object stream: %w", err)
	}

	// Scan the header's N "objNr offset" pairs, keeping only the two the target
	// needs: its own start, and the next object's start, which bounds it. This
	// avoids materialising all N entries just to read one.
	if index < 0 || index >= n {
		return nil, fmt.Errorf("index %d out of range for object stream (has %d objects)", index, n)
	}
	start, end := -1, len(streamData)
	foundObjNr := 0
	hpos := 0
	for i := 0; i < n; i++ {
		hpos = skipWhitespaceInSlice(streamData, hpos)
		objNr, w := parseInt(streamData, hpos)
		if w == 0 {
			break
		}
		hpos += w
		hpos = skipWhitespaceInSlice(streamData, hpos)
		off, w := parseInt(streamData, hpos)
		if w == 0 {
			break
		}
		hpos += w

		switch i {
		case index:
			foundObjNr, start = objNr, first+off
		case index + 1:
			end = first + off
		}
	}

	if start < 0 {
		return nil, fmt.Errorf("truncated object stream header: object %d not listed", targetObjNr)
	}
	if foundObjNr != targetObjNr {
		return nil, fmt.Errorf("object number mismatch: expected %d, got %d", targetObjNr, foundObjNr)
	}
	if end > len(streamData) {
		end = len(streamData)
	}
	if start > end {
		return nil, fmt.Errorf("object %d lies outside its object stream", targetObjNr)
	}

	objData := bytes.TrimSpace(streamData[start:end])

	// If it's a dict, extract the content between << and >>.
	if bytes.HasPrefix(objData, []byte("<<")) {
		content, _, err := readDictAt(objData, 0)
		if err != nil {
			return nil, fmt.Errorf("parse compressed object dict: %w", err)
		}
		return content, nil
	}

	return objData, nil
}

// findTopLevelKey returns the index of the "/key" entry at the top level
// (depth 0) of raw dict content, or -1 when the key is absent. key is given
// without its leading slash, as for extractDictValue.
func findTopLevelKey(dict []byte, key string) int {
	depth := 0

	for i := 0; i < len(dict); {
		switch dict[i] {
		case '%':
			i = skipPDFComment(dict, i)
			continue
		case '(':
			i = skipPDFStringLiteral(dict, i)
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
		case '/':
			if depth == 0 && isKeyAt(dict, i+1, key) {
				return i
			}
		}
		i++
	}
	return -1
}

// isKeyAt reports whether dict[pos:] starts with key followed by a PDF
// delimiter, so that "/N" does not match inside "/Name". Comparing the
// sub-slice against a string directly avoids the copy a []byte(key)
// conversion would cost on every call.
func isKeyAt(dict []byte, pos int, key string) bool {
	end := pos + len(key)
	if end > len(dict) || string(dict[pos:end]) != key {
		return false
	}
	return end == len(dict) || isPDFDelimiter(dict[end])
}

// extractDictValue extracts the value for /Key from raw dict content bytes.
// key is given without its leading slash. Returns nil if the key is not found.
func extractDictValue(dict []byte, key string) []byte {
	pos := findTopLevelKey(dict, key)
	if pos < 0 {
		return nil
	}
	// Skip all whitespace after the key so pretty-printed dicts
	// ("/Key\n<< ... >>") resolve correctly too.
	valStart := pos + 1 + len(key)
	for valStart < len(dict) && isSpace(dict[valStart]) {
		valStart++
	}
	return dict[valStart:findValueEnd(dict, valStart)]
}

// skipPDFStringLiteral returns the index just past the ')' that closes the
// string literal starting at data[pos] == '(', or len(data) if it is
// unterminated.
func skipPDFStringLiteral(data []byte, pos int) int {
	depth := 1
	for i := pos + 1; i < len(data); {
		switch data[i] {
		case '\\':
			i++
			if i < len(data) && data[i] == '\r' {
				i++
				if i < len(data) && data[i] == '\n' {
					i++
				}
			} else if i < len(data) {
				i++
			}
		case '(':
			depth++
			i++
		case ')':
			depth--
			i++
			if depth == 0 {
				return i
			}
		default:
			i++
		}
	}
	return len(data)
}

// findValueEnd finds the end of a PDF value starting at pos.
func findValueEnd(dict []byte, pos int) int {
	if pos >= len(dict) {
		return pos
	}

	b := dict[pos]
	switch {
	case b == '<' && pos+1 < len(dict) && dict[pos+1] == '<':
		// Dict value: find matching >>
		depth := 1
		i := pos + 2
		for i < len(dict) && depth > 0 {
			if dict[i] == '%' {
				i = skipPDFComment(dict, i)
				continue
			}
			if dict[i] == '(' {
				i = skipPDFStringLiteral(dict, i)
				continue
			}
			if dict[i] == '<' && i+1 < len(dict) && dict[i+1] == '<' {
				depth++
				i += 2
				continue
			}
			if dict[i] == '>' && i+1 < len(dict) && dict[i+1] == '>' {
				depth--
				i += 2
				continue
			}
			i++
		}
		return i
	case b == '[':
		// Array: find matching ]
		depth := 1
		i := pos + 1
		for i < len(dict) && depth > 0 {
			if dict[i] == '%' {
				i = skipPDFComment(dict, i)
				continue
			}
			if dict[i] == '(' {
				i = skipPDFStringLiteral(dict, i)
				continue
			}
			if dict[i] == '[' {
				depth++
			}
			if dict[i] == ']' {
				depth--
			}
			i++
		}
		return i
	case b == '(':
		// String literal: find matching )
		return skipPDFStringLiteral(dict, pos)
	case b == '<':
		// Hex string: find >
		i := pos + 1
		for i < len(dict) && dict[i] != '>' {
			i++
		}
		if i < len(dict) {
			return i + 1
		}
		return i
	case b == '/':
		// Name: ends at delimiter or whitespace
		i := pos + 1
		for i < len(dict) && !isPDFDelimiter(dict[i]) {
			i++
		}
		return i
	default:
		// Number, boolean, null, or indirect ref (N G R)
		// Scan to next PDF delimiter, but handle "N G R" pattern.
		i := pos
		for i < len(dict) && !isPDFStructDelimiter(dict[i]) {
			i++
		}
		// Trim trailing whitespace.
		for i > pos && isSpace(dict[i-1]) {
			i--
		}
		return i
	}
}

// extractIndirectRef parses "N G R" from value bytes.
// Zero-allocation: parses backwards from the trailing 'R'.
func extractIndirectRef(val []byte) (int, int, error) {
	// Trim trailing whitespace.
	end := len(val)
	for end > 0 && isSpace(val[end-1]) {
		end--
	}
	if end == 0 || val[end-1] != 'R' {
		return 0, 0, fmt.Errorf("not an indirect ref: %q", val)
	}
	end-- // skip 'R'

	// Skip whitespace before 'R'.
	for end > 0 && isSpace(val[end-1]) {
		end--
	}

	// Parse gen number (backwards).
	genEnd := end
	for end > 0 && val[end-1] >= '0' && val[end-1] <= '9' {
		end--
	}
	if end == genEnd {
		return 0, 0, fmt.Errorf("not an indirect ref: %q", val)
	}
	gen := 0
	mul := 1
	for i := genEnd - 1; i >= end; i-- {
		gen += int(val[i]-'0') * mul
		mul *= 10
	}

	// Skip whitespace before gen.
	for end > 0 && isSpace(val[end-1]) {
		end--
	}

	// Parse obj number (backwards).
	objEnd := end
	for end > 0 && val[end-1] >= '0' && val[end-1] <= '9' {
		end--
	}
	if end == objEnd {
		return 0, 0, fmt.Errorf("not an indirect ref: %q", val)
	}
	objNr := 0
	mul = 1
	for i := objEnd - 1; i >= end; i-- {
		objNr += int(val[i]-'0') * mul
		mul *= 10
	}

	return objNr, gen, nil
}

// isIndirectRef checks if value bytes look like "N G R".
// Zero-allocation: checks trailing 'R' then verifies digits before it.
func isIndirectRef(val []byte) bool {
	end := len(val)
	for end > 0 && isSpace(val[end-1]) {
		end--
	}
	if end == 0 || val[end-1] != 'R' {
		return false
	}
	end--
	// Need at least whitespace + digit + whitespace + digit before 'R'.
	for end > 0 && isSpace(val[end-1]) {
		end--
	}
	if end == 0 || val[end-1] < '0' || val[end-1] > '9' {
		return false
	}
	return true
}

// extractArrayContent returns the content bytes inside [ ].
func extractArrayContent(val []byte) []byte {
	val = bytes.TrimSpace(val)
	if len(val) >= 2 && val[0] == '[' && val[len(val)-1] == ']' {
		return bytes.TrimSpace(val[1 : len(val)-1])
	}
	return nil
}

// extractDictContent returns the content bytes inside << >>.
func extractDictContent(val []byte) []byte {
	val = bytes.TrimSpace(val)
	if len(val) >= 4 && val[0] == '<' && val[1] == '<' {
		end := bytes.LastIndex(val, []byte(">>"))
		if end > 1 {
			return val[2:end]
		}
	}
	return nil
}

// resolveArrayContent resolves an array value which may be direct or indirect.
// It returns the content inside [ ] (without brackets). Existing fields and
// annotations must never be silently dropped, so malformed or unresolvable
// values are reported to the caller.
func resolveArrayContent(data []byte, xref map[int]xrefEntry, val []byte) ([]byte, error) {
	val = bytes.TrimSpace(val)
	if len(val) > 0 && val[0] == '[' {
		if len(val) < 2 || val[len(val)-1] != ']' {
			return nil, fmt.Errorf("malformed direct array near %q", safeSlice(val, 0, 80))
		}
		return bytes.TrimSpace(val[1 : len(val)-1]), nil
	}
	if !isIndirectRef(val) {
		return nil, fmt.Errorf("expected an array or indirect reference, got %q", val)
	}

	objNr, _, err := extractIndirectRef(val)
	if err != nil {
		return nil, err
	}
	entry, ok := xref[objNr]
	if !ok {
		return nil, fmt.Errorf("array object %d not in xref", objNr)
	}
	if entry.free {
		// A free entry's offset field is a free-list link, not a file position.
		return nil, fmt.Errorf("array object %d is free", objNr)
	}

	var objData []byte
	if entry.compressed {
		objData, err = readCompressedObject(data, xref, entry.objStreamNr, entry.index, objNr)
		if err != nil {
			return nil, fmt.Errorf("read compressed array object %d: %w", objNr, err)
		}
	} else {
		pos := skipPastKeyword(data, int(entry.offset), kwObj)
		if pos < 0 {
			return nil, fmt.Errorf("obj keyword not found for array object %d", objNr)
		}
		objData = data[skipWhitespace(data, pos):]
	}

	objData = bytes.TrimSpace(objData)
	if len(objData) == 0 || objData[0] != '[' {
		return nil, fmt.Errorf("object %d is not an array", objNr)
	}
	end := findMatchingBracket(objData, 0)
	if end < 0 {
		return nil, fmt.Errorf("array object %d is unterminated", objNr)
	}
	return bytes.TrimSpace(objData[1:end]), nil
}

// resolvePageFromTree walks the page tree to find the target page.
func resolvePageFromTree(data []byte, xref map[int]xrefEntry, pagesObjNr int, targetPage int) (int, []byte, error) {
	return walkPageTree(data, xref, pagesObjNr, targetPage, 0)
}

func walkPageTree(data []byte, xref map[int]xrefEntry, objNr int, targetPage int, depth int) (int, []byte, error) {
	if depth > 50 {
		return 0, nil, fmt.Errorf("page tree too deep")
	}

	dict, err := resolveObjectDict(data, xref, objNr)
	if err != nil {
		return 0, nil, err
	}

	typeVal := extractDictValue(dict, "Type")

	// Compare type without string conversion (zero-alloc).
	if isNameEqual(typeVal, kwPage) {
		if targetPage == 1 {
			return objNr, dict, nil
		}
		return 0, nil, fmt.Errorf("page not found")
	}

	// It's a Pages node. Get /Kids array.
	kidsVal := extractDictValue(dict, "Kids")
	if kidsVal == nil {
		return 0, nil, fmt.Errorf("no /Kids in Pages node %d", objNr)
	}
	kidsContent := extractArrayContent(kidsVal)
	if kidsContent == nil {
		return 0, nil, fmt.Errorf("invalid /Kids array in Pages node %d", objNr)
	}

	// Parse indirect refs from Kids array (stack buffer avoids alloc for typical trees).
	var kidBuf [16]int
	kidRefs := parseIndirectRefs(kidsContent, kidBuf[:0])
	currentPage := 0

	for _, kidObjNr := range kidRefs {
		kidDict, err := resolveObjectDict(data, xref, kidObjNr)
		if err != nil {
			continue
		}

		kidType := extractDictValue(kidDict, "Type")

		count := 0
		if isNameEqual(kidType, kwPage) {
			count = 1
		} else if cVal := extractDictValue(kidDict, "Count"); cVal != nil {
			count, _ = parseInt(cVal, skipWhitespaceInSlice(cVal, 0))
		}

		if currentPage+count >= targetPage {
			return walkPageTree(data, xref, kidObjNr, targetPage-currentPage, depth+1)
		}
		currentPage += count
	}

	return 0, nil, fmt.Errorf("page %d not found in tree", targetPage)
}

// isNameEqual checks if a PDF name value (like "/Page") equals the given name (like "Page").
// Zero-allocation: compares bytes directly without string conversion.
func isNameEqual(val []byte, name []byte) bool {
	if val == nil {
		return false
	}
	val = bytes.TrimSpace(val)
	if len(val) > 0 && val[0] == '/' {
		val = val[1:]
	}
	return bytes.Equal(val, name)
}

// parseIndirectRefs extracts all "N G R" patterns from array content bytes.
// Accepts a pre-allocated buffer to avoid heap allocation for small arrays.
func parseIndirectRefs(content []byte, refs []int) []int {
	pos := 0
	for {
		pos = skipWhitespaceInSlice(content, pos)
		if pos >= len(content) {
			break
		}
		// Parse first number (obj number).
		objNr, n := parseInt(content, pos)
		if n == 0 {
			// Skip non-digit token.
			for pos < len(content) && !isSpace(content[pos]) {
				pos++
			}
			continue
		}
		pos += n

		pos = skipWhitespaceInSlice(content, pos)
		if pos >= len(content) {
			break
		}
		// Parse second number (gen number).
		_, n = parseInt(content, pos)
		if n == 0 {
			continue
		}
		pos += n

		pos = skipWhitespaceInSlice(content, pos)
		if pos >= len(content) {
			break
		}
		// Check for 'R'.
		if content[pos] == 'R' && (pos+1 >= len(content) || isSpace(content[pos+1]) || content[pos+1] == ']') {
			refs = append(refs, objNr)
			pos++
		}
	}
	return refs
}

// nextSignatureFieldNumber mirrors OpenPDF's automatic SignatureN naming and
// avoids duplicate field names when a document is signed more than once.
func nextSignatureFieldNumber(data []byte, xref map[int]xrefEntry, fields []byte) int {
	if len(fields) == 0 {
		return 1
	}

	used := make(map[int]struct{})
	seen := make(map[int]struct{})
	var visit func([]byte, int)
	visit = func(content []byte, depth int) {
		if depth > 50 {
			return
		}
		var refBuf [16]int
		for _, objNr := range parseIndirectRefs(content, refBuf[:0]) {
			if _, ok := seen[objNr]; ok {
				continue
			}
			seen[objNr] = struct{}{}

			dict, err := resolveObjectDict(data, xref, objNr)
			if err != nil {
				continue
			}
			if name := decodePDFString(extractDictValue(dict, "T")); bytes.HasPrefix(name, []byte("Signature")) {
				nr, n := parseInt(name, len("Signature"))
				if n > 0 && len("Signature")+n == len(name) && nr > 0 {
					used[nr] = struct{}{}
				}
			}
			if kids := extractDictValue(dict, "Kids"); kids != nil {
				kidsContent, err := resolveArrayContent(data, xref, kids)
				if err == nil {
					visit(kidsContent, depth+1)
				}
			}
		}
	}
	visit(fields, 0)

	for nr := 1; ; nr++ {
		if _, exists := used[nr]; !exists {
			return nr
		}
	}
}

// decodePDFString decodes a PDF string object into raw bytes, accepting both
// literal '(...)' and hex '<...>' forms, and converting Latin-only UTF-16BE
// content, so a field name is recognised regardless of how its producer
// encoded it.
func decodePDFString(val []byte) []byte {
	val = bytes.TrimSpace(val)
	var out []byte
	if len(val) >= 2 && val[0] == '<' && val[len(val)-1] == '>' {
		out = decodeHexString(val[1 : len(val)-1])
	} else {
		out = extractLiteralString(val)
	}
	return stripUTF16BE(out)
}

// decodeHexString decodes the content of a PDF hex string (between < and >).
// An odd final digit implies a trailing 0 (PDF 32000-1 7.3.4.3).
func decodeHexString(h []byte) []byte {
	out := make([]byte, 0, len(h)/2)
	var hi byte
	hasHi := false
	for _, c := range h {
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			v = c - 'A' + 10
		default:
			if isSpace(c) {
				continue
			}
			return nil
		}
		if !hasHi {
			hi, hasHi = v, true
		} else {
			out = append(out, hi<<4|v)
			hasHi = false
		}
	}
	if hasHi {
		out = append(out, hi<<4)
	}
	return out
}

// stripUTF16BE converts a UTF-16BE string (BOM FE FF) holding only Latin
// characters to single bytes; anything else is returned unchanged.
func stripUTF16BE(s []byte) []byte {
	if len(s) < 2 || s[0] != 0xFE || s[1] != 0xFF {
		return s
	}
	out := make([]byte, 0, (len(s)-2)/2)
	for i := 2; i+1 < len(s); i += 2 {
		if s[i] != 0 {
			return s
		}
		out = append(out, s[i+1])
	}
	return out
}

// extractLiteralString decodes the ASCII subset needed for PDF field names.
// It handles the escapes allowed in literal strings, including octal escapes.
func extractLiteralString(val []byte) []byte {
	val = bytes.TrimSpace(val)
	if len(val) < 2 || val[0] != '(' || val[len(val)-1] != ')' {
		return nil
	}
	out := make([]byte, 0, len(val)-2)
	for i := 1; i < len(val)-1; i++ {
		if val[i] != '\\' {
			out = append(out, val[i])
			continue
		}
		i++
		if i >= len(val)-1 {
			break
		}
		switch val[i] {
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case '\n':
			// A backslash followed by a line ending is a continuation.
		case '\r':
			if i+1 < len(val)-1 && val[i+1] == '\n' {
				i++
			}
		default:
			if val[i] >= '0' && val[i] <= '7' {
				n := int(val[i] - '0')
				for count := 1; count < 3 && i+1 < len(val)-1 && val[i+1] >= '0' && val[i+1] <= '7'; count++ {
					i++
					n = n*8 + int(val[i]-'0')
				}
				out = append(out, byte(n))
			} else {
				out = append(out, val[i])
			}
		}
	}
	return out
}

// Helper functions.

func isSpace(b byte) bool {
	return b == 0 || b == ' ' || b == '\n' || b == '\r' || b == '\t' || b == '\f'
}

func isPDFDelimiter(b byte) bool {
	return isSpace(b) ||
		b == '/' || b == '<' || b == '>' || b == '[' || b == ']' ||
		b == '(' || b == ')'
}

func isPDFStructDelimiter(b byte) bool {
	return b == '/' || b == '<' || b == '>' || b == '[' || b == ']'
}

func skipWhitespace(data []byte, pos int) int {
	for {
		for pos < len(data) && isSpace(data[pos]) {
			pos++
		}
		if pos >= len(data) || data[pos] != '%' {
			return pos
		}
		pos = skipPDFComment(data, pos)
	}
}

func skipWhitespaceInSlice(data []byte, pos int) int {
	for {
		for pos < len(data) && isSpace(data[pos]) {
			pos++
		}
		if pos >= len(data) || data[pos] != '%' {
			return pos
		}
		pos = skipPDFComment(data, pos)
	}
}

func skipPDFComment(data []byte, pos int) int {
	for pos < len(data) && data[pos] != '\n' && data[pos] != '\r' {
		pos++
	}
	return pos
}

// skipPastKeyword finds keyword in data starting at pos and returns the position
// after the keyword plus any trailing whitespace. Uses []byte keyword to avoid allocation.
// Reports -1 for an out-of-range pos, which callers get from untrusted xref offsets.
func skipPastKeyword(data []byte, pos int, keyword []byte) int {
	if pos < 0 || pos > len(data) {
		return -1
	}
	idx := bytes.Index(data[pos:], keyword)
	if idx == -1 {
		return -1
	}
	result := pos + idx + len(keyword)
	// Skip whitespace after keyword.
	for result < len(data) && isSpace(data[result]) {
		result++
	}
	return result
}

func parseInt(data []byte, pos int) (int, int) {
	start := pos
	neg := false
	if pos < len(data) && data[pos] == '-' {
		neg = true
		pos++
	}
	val := 0
	for pos < len(data) && data[pos] >= '0' && data[pos] <= '9' {
		val = val*10 + int(data[pos]-'0')
		pos++
	}
	if pos == start || (neg && pos == start+1) {
		return 0, 0
	}
	if neg {
		val = -val
	}
	return val, pos - start
}

func parseIntArray(content []byte) []int {
	var result []int
	pos := 0
	for {
		pos = skipWhitespaceInSlice(content, pos)
		if pos >= len(content) {
			break
		}
		v, n := parseInt(content, pos)
		if n == 0 {
			pos++
			continue
		}
		result = append(result, v)
		pos += n
	}
	return result
}

func findMatchingBracket(data []byte, pos int) int {
	if pos >= len(data) || data[pos] != '[' {
		return -1
	}
	depth := 1
	i := pos + 1
	for i < len(data) && depth > 0 {
		if data[i] == '%' {
			i = skipPDFComment(data, i)
			continue
		}
		if data[i] == '(' {
			i = skipPDFStringLiteral(data, i)
			continue
		}
		if data[i] == '[' {
			depth++
		}
		if data[i] == ']' {
			depth--
			if depth == 0 {
				return i
			}
		}
		i++
	}
	return -1
}

func safeSlice(data []byte, start, end int) []byte {
	if start < 0 {
		start = 0
	}
	if end > len(data) {
		end = len(data)
	}
	if start >= end {
		return nil
	}
	return data[start:end]
}

// parseInt64 parses an int64 from data starting at pos (like parseInt but int64).
func parseInt64(data []byte, pos int) (int64, int) {
	start := pos
	var val int64
	for pos < len(data) && data[pos] >= '0' && data[pos] <= '9' {
		val = val*10 + int64(data[pos]-'0')
		pos++
	}
	if pos == start {
		return 0, 0
	}
	return val, pos - start
}

// parseInt64Bytes parses an int64 from a fixed byte range, skipping leading spaces.
func parseInt64Bytes(data []byte, start, end int) int64 {
	for start < end && (data[start] == ' ' || data[start] == '0') {
		start++
	}
	if start == end {
		return 0
	}
	var val int64
	for i := start; i < end; i++ {
		if data[i] >= '0' && data[i] <= '9' {
			val = val*10 + int64(data[i]-'0')
		}
	}
	return val
}

// parseIntBytes parses an int from a fixed byte range, skipping leading spaces.
func parseIntBytes(data []byte, start, end int) int {
	for start < end && (data[start] == ' ' || data[start] == '0') {
		start++
	}
	if start == end {
		return 0
	}
	val := 0
	for i := start; i < end; i++ {
		if data[i] >= '0' && data[i] <= '9' {
			val = val*10 + int(data[i]-'0')
		}
	}
	return val
}
