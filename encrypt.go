package flashsign

import (
	"context"
	"io"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
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
	if err := decodeObjectStreamObjects(ctx); err != nil {
		return err
	}

	return api.WriteContext(ctx, w)
}

// decodeObjectStreamObjects parses every object read from an object stream.
// pdfcpu keeps those objects as raw text until something dereferences them,
// and its writer copies such text out verbatim without following the
// references inside it, so everything reachable only through them (the whole
// structure tree of a tagged PDF) would be dropped, and strings in them would
// be left unencrypted.
func decodeObjectStreamObjects(ctx *model.Context) error {
	for _, entry := range ctx.Table {
		if lazy, ok := entry.Object.(types.LazyObjectStreamObject); ok {
			o, err := lazy.DecodedObject(context.Background())
			if err != nil {
				return err
			}
			// As pdfcpu's own dereferencing does.
			model.ProcessRefCounts(ctx.XRefTable, o)
			entry.Object = o
		}
	}
	return nil
}
