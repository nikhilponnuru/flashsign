package flashsign

import (
	"strings"
	"time"
)

// buildAppearanceStream generates a PDF content stream for the visible signature box.
func buildAppearanceStream(rect Rectangle, signerName, reason, location string, signingTime time.Time) []byte {
	width := rect.X2 - rect.X1
	height := rect.Y2 - rect.Y1

	lineCount := 3 // "Digitally signed by:", signer name, date
	if reason != "" {
		lineCount++
	}
	if location != "" {
		lineCount++
	}

	padding := 4.0
	availableHeight := height - 2*padding
	fontSize := availableHeight / (float64(lineCount) * 1.3)
	if fontSize > 10 {
		fontSize = 10
	}
	if fontSize < 4 {
		fontSize = 4
	}
	lineHeight := fontSize * 1.3
	startY := height - padding - fontSize

	// Pre-estimate capacity: typical appearance stream is ~300-500 bytes.
	buf := make([]byte, 0, 512)

	// Background and border.
	buf = append(buf, "q\n1 1 0.8 rg\n0 0 "...)
	buf = appendFloat(buf, width)
	buf = append(buf, ' ')
	buf = appendFloat(buf, height)
	buf = append(buf, " re f\n0 0 0 RG 0.5 w\n0 0 "...)
	buf = appendFloat(buf, width)
	buf = append(buf, ' ')
	buf = appendFloat(buf, height)
	buf = append(buf, " re S\nQ\n"...)

	// Text block.
	buf = append(buf, "BT\n/F1 "...)
	buf = appendFloat(buf, fontSize)
	buf = append(buf, " Tf\n0 0.4 0 rg\n4 "...)
	buf = appendFloat(buf, startY)
	buf = append(buf, " Td ("...)
	buf = append(buf, pdfEscapeString("Digitally signed by:")...)
	buf = append(buf, ") Tj\n0 "...)
	buf = appendFloat(buf, -lineHeight)
	buf = append(buf, " Td ("...)
	buf = append(buf, pdfEscapeString(signerName)...)
	buf = append(buf, ") Tj\n0 "...)
	buf = appendFloat(buf, -lineHeight)
	buf = append(buf, " Td ("...)
	buf = append(buf, pdfEscapeString("Date: "+signingTime.UTC().Format("2006-01-02 15:04:05 UTC"))...)
	buf = append(buf, ") Tj\n"...)

	if reason != "" {
		buf = append(buf, "0 "...)
		buf = appendFloat(buf, -lineHeight)
		buf = append(buf, " Td ("...)
		buf = append(buf, pdfEscapeString("Reason: "+reason)...)
		buf = append(buf, ") Tj\n"...)
	}

	if location != "" {
		buf = append(buf, "0 "...)
		buf = appendFloat(buf, -lineHeight)
		buf = append(buf, " Td ("...)
		buf = append(buf, pdfEscapeString("Location: "+location)...)
		buf = append(buf, ") Tj\n"...)
	}

	buf = append(buf, "ET\n"...)
	return buf
}

var pdfStringReplacer = strings.NewReplacer(`\`, `\\`, `(`, `\(`, `)`, `\)`)

func pdfEscapeString(s string) string {
	return pdfStringReplacer.Replace(s)
}
