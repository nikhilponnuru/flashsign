package flashsign

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// Appearance controls the text of the visible signature box. Zero values give
// the look of the Java signer (OpenPDF's layer-2 default): 9pt Helvetica in
// rgb(16,181,60).
type Appearance struct {
	FontSize  float64 // in points; 0 = 9
	FontBold  bool    // Helvetica-Bold instead of Helvetica
	FontColor string  // "#RRGGBB" or "r,g,b" (0-255); "" = "#10B53C"
}

const (
	defaultFontSize  = 9.0
	defaultFontColor = "#10B53C" // rgb(16,181,60)

	// OpenPDF lays the text out in a column that starts appearanceMargin in
	// from the left, and runs from the bottom of the box up to 70% of its
	// height (the top 30% is reserved for its optional "signed by" section).
	appearanceMargin     = 2.0
	appearanceTopSection = 0.3
)

// appearanceStyle is the resolved Appearance, precomputed once per Signer.
type appearanceStyle struct {
	fontSize float64
	bold     bool
	colorOp  []byte // "r g b rg\n" with components in 0..1
}

func resolveAppearance(a Appearance) (appearanceStyle, error) {
	st := appearanceStyle{fontSize: a.FontSize, bold: a.FontBold}
	if st.fontSize <= 0 {
		st.fontSize = defaultFontSize
	}
	color := strings.TrimSpace(a.FontColor)
	if color == "" {
		color = defaultFontColor
	}
	r, g, b, err := parseRGB(color)
	if err != nil {
		return st, err
	}
	var buf []byte
	buf = appendFloat(buf, round4(float64(r)/255))
	buf = append(buf, ' ')
	buf = appendFloat(buf, round4(float64(g)/255))
	buf = append(buf, ' ')
	buf = appendFloat(buf, round4(float64(b)/255))
	st.colorOp = append(buf, " rg\n"...)
	return st, nil
}

// parseRGB accepts "#RRGGBB" / "RRGGBB" or "r,g,b" with 0-255 components.
func parseRGB(s string) (r, g, b int, err error) {
	if strings.Contains(s, ",") {
		parts := strings.Split(s, ",")
		if len(parts) != 3 {
			return 0, 0, 0, fmt.Errorf("invalid font color %q: want r,g,b", s)
		}
		var v [3]int
		for i, p := range parts {
			v[i], err = strconv.Atoi(strings.TrimSpace(p))
			if err != nil || v[i] < 0 || v[i] > 255 {
				return 0, 0, 0, fmt.Errorf("invalid font color %q: components must be 0-255", s)
			}
		}
		return v[0], v[1], v[2], nil
	}
	h := strings.TrimPrefix(s, "#")
	if len(h) != 6 {
		return 0, 0, 0, fmt.Errorf("invalid font color %q: want #RRGGBB or r,g,b", s)
	}
	n, err := strconv.ParseUint(h, 16, 32)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid font color %q: %w", s, err)
	}
	return int(n >> 16), int(n >> 8 & 0xFF), int(n & 0xFF), nil
}

func round4(v float64) float64 { return math.Round(v*1e4) / 1e4 }
func round2(v float64) float64 { return math.Round(v*1e2) / 1e2 }

// appendAppearanceStream appends the PDF content stream for the visible
// signature box directly into buf. Zero allocations.
//
// It reproduces OpenPDF's default layer-2 text, line by line:
//
//	Digitally signed by <name>
//	Date: yyyy.MM.dd HH:mm:ss z
//	Reason: <reason>      (when set)
//	Location: <location>  (when set)
//
// with leading equal to the font size, the first baseline one leading below
// the column top, and any line whose baseline would fall below the box
// dropped — exactly what OpenPDF's ColumnText does when the box is short.
func appendAppearanceStream(buf []byte, rect Rectangle, st appearanceStyle, signerName, reason, location string, signingTime time.Time) []byte {
	height := rect.Y2 - rect.Y1
	columnTop := height*(1-appearanceTopSection) - appearanceMargin
	leading := st.fontSize
	y := round2(columnTop - leading)

	buf = append(buf, "BT\n/F1 "...)
	buf = appendFloat(buf, st.fontSize)
	buf = append(buf, " Tf\n"...)
	buf = append(buf, st.colorOp...)
	buf = appendFloat(buf, appearanceMargin)
	buf = append(buf, ' ')
	buf = appendFloat(buf, y)
	buf = append(buf, " Td\n"...)
	buf = appendFloat(buf, leading)
	buf = append(buf, " TL\n"...)

	// Each line is written only while its baseline is still inside the box.
	if y >= 0 {
		buf = append(buf, "(Digitally signed by "...)
		buf = appendPDFEscaped(buf, signerName)
		buf = append(buf, ") Tj T*\n"...)
		y = round2(y - leading)
	}
	if y >= 0 {
		buf = append(buf, "(Date: "...)
		buf = appendDateDisplay(buf, signingTime)
		buf = append(buf, ") Tj T*\n"...)
		y = round2(y - leading)
	}
	if reason != "" && y >= 0 {
		buf = append(buf, "(Reason: "...)
		buf = appendPDFEscaped(buf, reason)
		buf = append(buf, ") Tj T*\n"...)
		y = round2(y - leading)
	}
	if location != "" && y >= 0 {
		buf = append(buf, "(Location: "...)
		buf = appendPDFEscaped(buf, location)
		buf = append(buf, ") Tj T*\n"...)
	}

	buf = append(buf, "ET\n"...)
	return buf
}

// appendDateDisplay appends the signing time as "yyyy.MM.dd HH:mm:ss z" in the
// process's local time zone, the format Java's SimpleDateFormat produces for
// the OpenPDF appearance. Zero allocations (replaces time.Format).
func appendDateDisplay(buf []byte, t time.Time) []byte {
	t = t.In(time.Local)
	y, mo, d := t.Date()
	hh, mm, ss := t.Clock()
	zone, _ := t.Zone()
	// yyyy.MM.dd
	buf = append(buf, byte('0'+y/1000), byte('0'+(y/100)%10), byte('0'+(y/10)%10), byte('0'+y%10))
	buf = append(buf, '.')
	buf = append(buf, byte('0'+int(mo)/10), byte('0'+int(mo)%10))
	buf = append(buf, '.')
	buf = append(buf, byte('0'+d/10), byte('0'+d%10))
	buf = append(buf, ' ')
	// HH:mm:ss
	buf = append(buf, byte('0'+hh/10), byte('0'+hh%10))
	buf = append(buf, ':')
	buf = append(buf, byte('0'+mm/10), byte('0'+mm%10))
	buf = append(buf, ':')
	buf = append(buf, byte('0'+ss/10), byte('0'+ss%10))
	buf = append(buf, ' ')
	buf = append(buf, zone...)
	return buf
}
