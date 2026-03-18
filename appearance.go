package flashsign

import "time"

// appendAppearanceStream appends a PDF content stream for the visible signature
// box directly into buf. Zero allocations.
func appendAppearanceStream(buf []byte, rect Rectangle, signerName, reason, location string, signingTime time.Time) []byte {
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
	buf = appendPDFEscaped(buf, "Digitally signed by:")
	buf = append(buf, ") Tj\n0 "...)
	buf = appendFloat(buf, -lineHeight)
	buf = append(buf, " Td ("...)
	buf = appendPDFEscaped(buf, signerName)
	buf = append(buf, ") Tj\n0 "...)
	buf = appendFloat(buf, -lineHeight)
	buf = append(buf, " Td (Date: "...)
	buf = appendDateDisplay(buf, signingTime)
	buf = append(buf, ") Tj\n"...)

	if reason != "" {
		buf = append(buf, "0 "...)
		buf = appendFloat(buf, -lineHeight)
		buf = append(buf, " Td (Reason: "...)
		buf = appendPDFEscaped(buf, reason)
		buf = append(buf, ") Tj\n"...)
	}

	if location != "" {
		buf = append(buf, "0 "...)
		buf = appendFloat(buf, -lineHeight)
		buf = append(buf, " Td (Location: "...)
		buf = appendPDFEscaped(buf, location)
		buf = append(buf, ") Tj\n"...)
	}

	buf = append(buf, "ET\n"...)
	return buf
}

// appendDateDisplay appends "2006-01-02 15:04:05 UTC" format to buf.
// Zero allocations (replaces time.Format).
func appendDateDisplay(buf []byte, t time.Time) []byte {
	t = t.UTC()
	y, mo, d := t.Date()
	hh, mm, ss := t.Clock()
	// YYYY-MM-DD
	buf = append(buf, byte('0'+y/1000), byte('0'+(y/100)%10), byte('0'+(y/10)%10), byte('0'+y%10))
	buf = append(buf, '-')
	buf = append(buf, byte('0'+int(mo)/10), byte('0'+int(mo)%10))
	buf = append(buf, '-')
	buf = append(buf, byte('0'+d/10), byte('0'+d%10))
	buf = append(buf, ' ')
	// HH:MM:SS
	buf = append(buf, byte('0'+hh/10), byte('0'+hh%10))
	buf = append(buf, ':')
	buf = append(buf, byte('0'+mm/10), byte('0'+mm%10))
	buf = append(buf, ':')
	buf = append(buf, byte('0'+ss/10), byte('0'+ss%10))
	buf = append(buf, " UTC"...)
	return buf
}
