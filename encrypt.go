package flashsign

import (
	"io"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// accessiblePermissions allows printing plus text extraction for accessibility
// (PDF 32000-1 Table 22 bit 10, "ALLOW_SCREENREADERS" in iText/OpenPDF terms).
// Without bit 10 screen readers refuse to read the encrypted document, which
// silently destroys the accessibility of a tagged PDF. Copy/extract for other
// purposes (bit 5), modification and assembly stay disallowed.
const accessiblePermissions = model.PermissionsPrint | model.PermissionExtractRev3

func newEncryptConf(password string, keyLength int) *model.Configuration {
	if keyLength != 128 && keyLength != 256 {
		keyLength = 128
	}
	conf := model.NewAESConfiguration(password, password, keyLength)
	conf.Permissions = accessiblePermissions
	// The encrypted document is signed afterwards by appending an increment,
	// which needs its dictionaries readable: object streams would be encrypted
	// wholesale, so write plain objects with a classic xref table.
	conf.WriteObjectStream = false
	conf.WriteXRefStream = false
	conf.Optimize = false
	conf.OptimizeBeforeWriting = false
	conf.OptimizeResourceDicts = false
	conf.ValidateLinks = false
	return conf
}

func encryptPDFStream(rs io.ReadSeeker, w io.Writer, password string, keyLength int) error {
	conf := newEncryptConf(password, keyLength)
	conf.Cmd = model.ENCRYPT

	ctx, err := api.ReadContext(rs, conf)
	if err != nil {
		return err
	}

	return api.WriteContext(ctx, w)
}
