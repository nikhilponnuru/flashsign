package flashsign

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"fmt"
	"io"
)

// pdfInfo holds the minimal PDF metadata needed for signing.
type pdfInfo struct {
	nextObjNr      int
	prevXrefOffset int64
	catalogObjNr   int
	pageObjNr      int
	catalogRaw     []byte // raw catalog dict content (between << and >>)
	pageRaw        []byte // raw page dict content
	existingFields []byte // raw /Fields array content, or nil
	existingAnnots []byte // raw /Annots array content, or nil
	infoObjNr      int    // /Info object number, or 0
	infoGen        int    // /Info generation
	idArray        []byte // raw /ID array bytes including [ ], or nil
}

// xrefEntry represents a cross-reference entry.
type xrefEntry struct {
	offset      int64
	gen         int
	compressed  bool
	objStreamNr int
	index       int
}

// parsePDF parses a PDF byte slice and extracts the minimal info needed for signing.
func parsePDF(data []byte, targetPage int) (*pdfInfo, error) {
	if targetPage < 1 {
		targetPage = 1
	}

	// Find startxref offset.
	prevXrefOffset, err := findStartxref(data)
	if err != nil {
		return nil, fmt.Errorf("find startxref: %w", err)
	}

	// Parse xref chain to build complete object table.
	xref, trailer, err := parseXrefChain(data, prevXrefOffset)
	if err != nil {
		return nil, fmt.Errorf("parse xref: %w", err)
	}

	// Read catalog object.
	catalogRaw, err := resolveObjectDict(data, xref, trailer.rootObjNr)
	if err != nil {
		return nil, fmt.Errorf("read catalog object %d: %w", trailer.rootObjNr, err)
	}

	// Extract /Pages reference from catalog.
	pagesVal := extractDictValue(catalogRaw, "Pages")
	if pagesVal == nil {
		return nil, fmt.Errorf("catalog has no /Pages entry")
	}
	pagesObjNr, _, err := extractIndirectRef(pagesVal)
	if err != nil {
		return nil, fmt.Errorf("parse /Pages ref: %w", err)
	}

	// Walk page tree to find target page.
	pageObjNr, pageRaw, err := resolvePageFromTree(data, xref, pagesObjNr, targetPage)
	if err != nil {
		return nil, fmt.Errorf("resolve page %d: %w", targetPage, err)
	}

	// Extract existing /AcroForm /Fields if present.
	var existingFields []byte
	acroFormVal := extractDictValue(catalogRaw, "AcroForm")
	if acroFormVal != nil {
		// /AcroForm can be a direct dict or indirect ref.
		var acroDict []byte
		if isIndirectRef(acroFormVal) {
			objNr, _, err := extractIndirectRef(acroFormVal)
			if err == nil {
				acroDict, _ = resolveObjectDict(data, xref, objNr)
			}
		} else if bytes.HasPrefix(bytes.TrimSpace(acroFormVal), []byte("<<")) {
			acroDict = extractDictContent(acroFormVal)
		}
		if acroDict != nil {
			fieldsVal := extractDictValue(acroDict, "Fields")
			if fieldsVal != nil {
				existingFields = resolveArrayContent(data, xref, fieldsVal)
			}
		}
	}

	// Extract existing /Annots if present.
	var existingAnnots []byte
	annotsVal := extractDictValue(pageRaw, "Annots")
	if annotsVal != nil {
		existingAnnots = resolveArrayContent(data, xref, annotsVal)
	}

	pi := &pdfInfo{
		nextObjNr:      trailer.size,
		prevXrefOffset: prevXrefOffset,
		catalogObjNr:   trailer.rootObjNr,
		pageObjNr:      pageObjNr,
		catalogRaw:     catalogRaw,
		pageRaw:        pageRaw,
		existingFields: existingFields,
		existingAnnots: existingAnnots,
		infoObjNr:      trailer.infoObjNr,
		infoGen:        trailer.infoGen,
		idArray:        trailer.idArray,
	}
	return pi, nil
}

// parsePDFReader parses a PDF from an io.ReadSeeker.
func parsePDFReader(src io.ReadSeeker, srcSize int64, targetPage int) (*pdfInfo, error) {
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek start: %w", err)
	}
	data := make([]byte, srcSize)
	if _, err := io.ReadFull(src, data); err != nil {
		return nil, fmt.Errorf("read source: %w", err)
	}
	return parsePDF(data, targetPage)
}

// findStartxref finds the byte offset of the most recent xref from the PDF tail.
func findStartxref(data []byte) (int64, error) {
	// Search the last 1KB.
	searchStart := len(data) - 1024
	if searchStart < 0 {
		searchStart = 0
	}
	tail := data[searchStart:]

	idx := bytes.LastIndex(tail, []byte("startxref"))
	if idx == -1 {
		return 0, fmt.Errorf("startxref not found")
	}

	rest := tail[idx+len("startxref"):]
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
	size      int
	rootObjNr int
	rootGen   int
	infoObjNr int
	infoGen   int
	idArray   []byte
	prevXref  int64
}

// parseXrefChain follows the /Prev chain to build a complete xref table.
func parseXrefChain(data []byte, startOffset int64) (map[int]xrefEntry, trailerInfo, error) {
	xref := make(map[int]xrefEntry)
	var firstTrailer trailerInfo
	first := true

	offset := startOffset
	for offset >= 0 {
		var entries map[int]xrefEntry
		var trailer trailerInfo
		var err error

		// Determine if this is a traditional xref table or xref stream.
		if offset < int64(len(data)) && bytes.HasPrefix(data[offset:], []byte("xref")) {
			entries, trailer, err = parseTraditionalXref(data, offset)
		} else {
			entries, trailer, err = parseXrefStream(data, offset)
		}
		if err != nil {
			return nil, trailerInfo{}, fmt.Errorf("parse xref at offset %d: %w", offset, err)
		}

		// Merge entries: earlier entries take precedence (most recent xref wins).
		for objNr, entry := range entries {
			if _, exists := xref[objNr]; !exists {
				xref[objNr] = entry
			}
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
func parseTraditionalXref(data []byte, offset int64) (map[int]xrefEntry, trailerInfo, error) {
	entries := make(map[int]xrefEntry)
	pos := int(offset)

	// Skip "xref" keyword and whitespace.
	if !bytes.HasPrefix(data[pos:], []byte("xref")) {
		return nil, trailerInfo{}, fmt.Errorf("expected 'xref' at offset %d", offset)
	}
	pos += 4
	pos = skipWhitespace(data, pos)

	// Parse subsections until "trailer" keyword.
	for pos < len(data) {
		if bytes.HasPrefix(data[pos:], []byte("trailer")) {
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
			return nil, trailerInfo{}, fmt.Errorf("expected count in xref subsection")
		}
		pos += n
		pos = skipWhitespace(data, pos)

		// Parse entries line by line (handles 20-byte and non-standard entries).
		for i := 0; i < count; i++ {
			if pos >= len(data) {
				return nil, trailerInfo{}, fmt.Errorf("truncated xref entry")
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
			if inUse && objNr > 0 {
				entries[objNr] = xrefEntry{offset: entryOffset, gen: gen}
			}
		}
		pos = skipWhitespace(data, pos)
	}

	// Parse trailer dict.
	trailerPos := bytes.Index(data[pos:], []byte("trailer"))
	if trailerPos == -1 {
		return nil, trailerInfo{}, fmt.Errorf("trailer not found")
	}
	pos += trailerPos + 7
	pos = skipWhitespace(data, pos)

	trailer, err := parseTrailerDict(data, pos)
	if err != nil {
		return nil, trailerInfo{}, err
	}

	return entries, trailer, nil
}

// parseXrefStream parses a cross-reference stream object (PDF 1.5+).
func parseXrefStream(data []byte, offset int64) (map[int]xrefEntry, trailerInfo, error) {
	pos := int(offset)

	// Skip object header: "N G obj"
	pos = skipPastKeyword(data, pos, "obj")
	if pos < 0 {
		return nil, trailerInfo{}, fmt.Errorf("obj keyword not found at offset %d", offset)
	}

	// Read the stream dict.
	dictContent, dictEnd, err := readDictAt(data, pos)
	if err != nil {
		return nil, trailerInfo{}, fmt.Errorf("read xref stream dict: %w", err)
	}

	// Extract trailer fields from the stream dict (which serves as the trailer).
	trailer := extractTrailerFields(dictContent)

	// Extract /W array (column widths).
	wVal := extractDictValue(dictContent, "W")
	if wVal == nil {
		return nil, trailerInfo{}, fmt.Errorf("xref stream missing /W")
	}
	wArr := extractArrayContent(wVal)
	if wArr == nil {
		return nil, trailerInfo{}, fmt.Errorf("invalid /W array")
	}
	w := parseIntArray(wArr)
	if len(w) < 3 {
		return nil, trailerInfo{}, fmt.Errorf("/W array must have 3 elements, got %d", len(w))
	}
	entrySize := w[0] + w[1] + w[2]
	if entrySize == 0 {
		return nil, trailerInfo{}, fmt.Errorf("invalid /W entry size")
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
		return nil, trailerInfo{}, fmt.Errorf("read xref stream data: %w", err)
	}

	// Parse entries from stream data.
	entries := make(map[int]xrefEntry)
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
					entries[objNr] = xrefEntry{offset: int64(field2), gen: int(field3)}
				}
			case entryType == 2: // type 2: compressed object
				if objNr > 0 {
					entries[objNr] = xrefEntry{compressed: true, objStreamNr: int(field2), index: int(field3)}
				}
			}
			// type 0: free entry, skip
		}
	}

	return entries, trailer, nil
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
	pos := dictEnd
	pos = skipWhitespace(data, pos)

	// Expect "stream" keyword.
	if !bytes.HasPrefix(data[pos:], []byte("stream")) {
		return nil, fmt.Errorf("expected 'stream' keyword at %d", pos)
	}
	pos += 6
	// Skip \r\n or \n after "stream".
	if pos < len(data) && data[pos] == '\r' {
		pos++
	}
	if pos < len(data) && data[pos] == '\n' {
		pos++
	}

	// Find "endstream".
	endIdx := bytes.Index(data[pos:], []byte("endstream"))
	if endIdx == -1 {
		return nil, fmt.Errorf("endstream not found")
	}
	streamBytes := data[pos : pos+endIdx]
	// Trim trailing whitespace.
	streamBytes = bytes.TrimRight(streamBytes, " \r\n")

	// Check /Filter.
	filterVal := extractDictValue(dictContent, "Filter")
	if filterVal != nil && bytes.Contains(filterVal, []byte("FlateDecode")) {
		return inflateBytes(streamBytes)
	}
	return streamBytes, nil
}

// inflateBytes decompresses FlateDecode data.
// PDF FlateDecode uses zlib (RFC 1950) wrapping deflate. We try zlib first,
// falling back to raw deflate for non-standard producers.
func inflateBytes(compressed []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		// Fallback to raw deflate for non-standard streams.
		fr := flate.NewReader(bytes.NewReader(compressed))
		defer fr.Close()
		return io.ReadAll(fr)
	}
	defer r.Close()
	return io.ReadAll(r)
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
		case b == '(' :
			// Skip string literal.
			pos++
			for pos < len(data) {
				if data[pos] == '\\' {
					pos += 2
					continue
				}
				if data[pos] == ')' {
					pos++
					break
				}
				pos++
			}
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

	if entry.compressed {
		return readCompressedObject(data, xref, entry.objStreamNr, entry.index, objNr)
	}

	return readObjectDictAt(data, entry.offset)
}

// readObjectDictAt reads the dict content of a regular object at the given offset.
func readObjectDictAt(data []byte, offset int64) ([]byte, error) {
	pos := int(offset)
	pos = skipPastKeyword(data, pos, "obj")
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
	if streamEntry.compressed {
		return nil, fmt.Errorf("nested compressed object streams not supported")
	}

	pos := int(streamEntry.offset)
	pos = skipPastKeyword(data, pos, "obj")
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

	// Parse header: N pairs of (objNum offset).
	type objEntry struct {
		objNr  int
		offset int
	}
	entries := make([]objEntry, 0, n)
	hpos := 0
	for i := 0; i < n; i++ {
		hpos = skipWhitespaceInSlice(streamData, hpos)
		objNr, nn := parseIntInSlice(streamData, hpos)
		hpos += nn
		hpos = skipWhitespaceInSlice(streamData, hpos)
		off, nn := parseIntInSlice(streamData, hpos)
		hpos += nn
		entries = append(entries, objEntry{objNr: objNr, offset: first + off})
	}

	// Find the target entry by index.
	if index >= len(entries) {
		return nil, fmt.Errorf("index %d out of range for object stream (has %d objects)", index, len(entries))
	}
	entry := entries[index]
	if entry.objNr != targetObjNr {
		return nil, fmt.Errorf("object number mismatch: expected %d, got %d", targetObjNr, entry.objNr)
	}

	// Extract the object data.
	start := entry.offset
	var end int
	if index+1 < len(entries) {
		end = entries[index+1].offset
	} else {
		end = len(streamData)
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

// extractDictValue extracts the value for /Key from raw dict content bytes.
// Returns nil if the key is not found.
func extractDictValue(dict []byte, key string) []byte {
	searchKey := "/" + key
	keyBytes := []byte(searchKey)

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

		// Only match at top level.
		if depth == 0 && b == '/' && bytes.HasPrefix(dict[i:], keyBytes) {
			endOfKey := i + len(keyBytes)
			// Ensure the key is followed by a delimiter.
			if endOfKey >= len(dict) || isPDFDelimiter(dict[endOfKey]) {
				// Extract the value starting after the key.
				valStart := endOfKey
				for valStart < len(dict) && dict[valStart] == ' ' {
					valStart++
				}
				valEnd := findValueEnd(dict, valStart)
				return dict[valStart:valEnd]
			}
		}

		i++
	}
	return nil
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
			if dict[i] == '(' {
				i++
				for i < len(dict) {
					if dict[i] == '\\' {
						i += 2
						continue
					}
					if dict[i] == ')' {
						i++
						break
					}
					i++
				}
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
			if dict[i] == '(' {
				i++
				for i < len(dict) {
					if dict[i] == '\\' {
						i += 2
						continue
					}
					if dict[i] == ')' {
						i++
						break
					}
					i++
				}
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
		i := pos + 1
		for i < len(dict) {
			if dict[i] == '\\' {
				i += 2
				continue
			}
			if dict[i] == ')' {
				return i + 1
			}
			i++
		}
		return i
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
// Returns the content inside [ ] (without brackets).
func resolveArrayContent(data []byte, xref map[int]xrefEntry, val []byte) []byte {
	val = bytes.TrimSpace(val)
	if len(val) > 0 && val[0] == '[' {
		return extractArrayContent(val)
	}
	// Might be an indirect ref to an array object.
	if isIndirectRef(val) {
		objNr, _, err := extractIndirectRef(val)
		if err != nil {
			return nil
		}
		entry, ok := xref[objNr]
		if !ok || entry.compressed {
			return nil
		}
		pos := int(entry.offset)
		pos = skipPastKeyword(data, pos, "obj")
		if pos < 0 {
			return nil
		}
		pos = skipWhitespace(data, pos)
		if pos < len(data) && data[pos] == '[' {
			end := findMatchingBracket(data, pos)
			if end > pos {
				return bytes.TrimSpace(data[pos+1 : end])
			}
		}
	}
	return nil
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
	typeName := ""
	if typeVal != nil {
		typeName = string(bytes.TrimLeft(bytes.TrimSpace(typeVal), "/"))
	}

	if typeName == "Page" {
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

	// Parse indirect refs from Kids array.
	kidRefs := parseIndirectRefs(kidsContent)
	currentPage := 0

	for _, kidObjNr := range kidRefs {
		kidDict, err := resolveObjectDict(data, xref, kidObjNr)
		if err != nil {
			continue
		}

		kidType := extractDictValue(kidDict, "Type")
		kidTypeName := ""
		if kidType != nil {
			kidTypeName = string(bytes.TrimLeft(bytes.TrimSpace(kidType), "/"))
		}

		count := 0
		if kidTypeName == "Page" {
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

// parseIndirectRefs extracts all "N G R" patterns from array content bytes.
// Zero-allocation: walks bytes directly instead of using bytes.Fields.
func parseIndirectRefs(content []byte) []int {
	var refs []int
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

// Helper functions.

func isSpace(b byte) bool {
	return b == ' ' || b == '\n' || b == '\r' || b == '\t'
}

func isPDFDelimiter(b byte) bool {
	return b == ' ' || b == '\n' || b == '\r' || b == '\t' ||
		b == '/' || b == '<' || b == '>' || b == '[' || b == ']' ||
		b == '(' || b == ')'
}

func isPDFStructDelimiter(b byte) bool {
	return b == '/' || b == '<' || b == '>' || b == '[' || b == ']'
}

func skipWhitespace(data []byte, pos int) int {
	for pos < len(data) && isSpace(data[pos]) {
		pos++
	}
	// Also skip PDF comments (% to end of line).
	if pos < len(data) && data[pos] == '%' {
		for pos < len(data) && data[pos] != '\n' && data[pos] != '\r' {
			pos++
		}
		return skipWhitespace(data, pos)
	}
	return pos
}

func skipWhitespaceInSlice(data []byte, pos int) int {
	for pos < len(data) && isSpace(data[pos]) {
		pos++
	}
	return pos
}

func skipPastKeyword(data []byte, pos int, keyword string) int {
	kw := []byte(keyword)
	idx := bytes.Index(data[pos:], kw)
	if idx == -1 {
		return -1
	}
	result := pos + idx + len(kw)
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

func parseIntInSlice(data []byte, pos int) (int, int) {
	return parseInt(data, pos)
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
		if data[i] == '(' {
			i++
			for i < len(data) {
				if data[i] == '\\' {
					i += 2
					continue
				}
				if data[i] == ')' {
					i++
					break
				}
				i++
			}
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
