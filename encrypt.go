package flashsign

import (
	"io"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// encryptPDF applies AES encryption to a PDF file.
func encryptPDF(inputPath, outputPath, password string, keyLength int) error {
	if keyLength != 128 && keyLength != 256 {
		keyLength = 128
	}
	conf := model.NewAESConfiguration(password, password, keyLength)
	conf.Permissions = model.PermissionsPrint
	return api.EncryptFile(inputPath, outputPath, conf)
}

func newEncryptConf(password string, keyLength int) *model.Configuration {
	if keyLength != 128 && keyLength != 256 {
		keyLength = 128
	}
	conf := model.NewAESConfiguration(password, password, keyLength)
	conf.Permissions = model.PermissionsPrint
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
