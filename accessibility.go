package flashsign

import "bytes"

// Accessibility support for tagged (PDF/UA style) documents.
//
// Signing a tagged PDF must not degrade its accessibility. Two catalog/page level
// entries are required once a signature widget is added:
//
//   - /ViewerPreferences << /DisplayDocTitle true >> so assistive technology
//     announces the document title instead of the file name (PDF/UA-1 7.1).
//   - /Tabs /S on every page carrying annotations, so the tab/reading order of
//     the annotations follows the structure tree (PDF/UA-1 7.18.3). FlashSign
//     always adds a signature widget annotation to the signature page, so that
//     page needs /Tabs /S even for invisible signatures.
//
// Everything already present in the catalog (/StructTreeRoot, /MarkInfo, /Lang,
// /Metadata, /Outlines, existing /ViewerPreferences entries such as /Direction)
// and in the page dict (/StructParents, existing /Tabs, /Annots) is preserved:
// the increment builder copies the raw dictionaries and only rewrites the keys
// it must change.
//
// Note on /StructParent for the signature widget: PDF/UA-1 7.18.1 wants
// annotations referenced from the structure tree. That requires appending a
// /Form structure element, extending /StructTreeRoot /K and the /ParentTree
// number tree plus /ParentTreeNextKey. Emitting a /StructParent without those
// edits would create a dangling entry, which is worse than omitting it, so
// FlashSign only adds the widget's /TU description (PDF/UA-1 7.18.6.2) and
// leaves the structure tree untouched.

var (
	kwSlashTabs               = []byte("/Tabs")
	kwSlashViewerPreferences  = []byte("/ViewerPreferences")
	kwSlashDisplayDocTitle    = []byte("/DisplayDocTitle")
	kwDisplayDocTitleTrue     = []byte(" /DisplayDocTitle true >>")
	kwViewerPreferencesPrefix = []byte("\n/ViewerPreferences <<")
	kwTabsStructure           = []byte("\n/Tabs /S")
)

// signatureFieldDescription is the /TU (alternate field name) used for the
// signature widget so screen readers announce something meaningful.
const signatureFieldDescription = "Digital signature"

// isTaggedCatalog reports whether the document catalog describes a tagged PDF.
// A /StructTreeRoot entry, or /MarkInfo with /Marked true, marks the document
// as tagged.
func isTaggedCatalog(data []byte, xref map[int]xrefEntry, catalogRaw []byte) bool {
	if extractDictValue(catalogRaw, "StructTreeRoot") != nil {
		return true
	}

	markInfo := extractDictValue(catalogRaw, "MarkInfo")
	if markInfo == nil {
		return false
	}

	markInfoDict := resolveDictOrRef(data, xref, markInfo)
	if markInfoDict == nil {
		return false
	}

	return isPDFTrue(extractDictValue(markInfoDict, "Marked"))
}

// resolveViewerPrefs returns the /ViewerPreferences object number (0 when the
// value is a direct dict or missing) and its raw dict content (nil when absent
// or unresolvable).
func resolveViewerPrefs(data []byte, xref map[int]xrefEntry, catalogRaw []byte) (int, []byte) {
	val := extractDictValue(catalogRaw, "ViewerPreferences")
	if val == nil {
		return 0, nil
	}

	if isIndirectRef(val) {
		objNr, _, err := extractIndirectRef(val)
		if err != nil {
			return 0, nil
		}
		raw, err := resolveObjectDict(data, xref, objNr)
		if err != nil {
			return 0, nil
		}
		return objNr, raw
	}

	return 0, extractDictContent(val)
}

// resolveDictOrRef returns the raw dict content for a value that is either a
// direct dict or an indirect reference to one.
func resolveDictOrRef(data []byte, xref map[int]xrefEntry, val []byte) []byte {
	if isIndirectRef(val) {
		objNr, _, err := extractIndirectRef(val)
		if err != nil {
			return nil
		}
		raw, err := resolveObjectDict(data, xref, objNr)
		if err != nil {
			return nil
		}
		return raw
	}
	return extractDictContent(val)
}

// isPDFTrue reports whether a raw PDF value is the boolean true.
func isPDFTrue(val []byte) bool {
	return bytes.HasPrefix(bytes.TrimLeft(val, " \t\r\n"), []byte("true"))
}
