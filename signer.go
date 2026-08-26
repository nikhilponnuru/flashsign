package flashsign

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// hashPoolSHA256 provides reusable SHA-256 hash instances.
var hashPoolSHA256 = sync.Pool{
	New: func() any {
		return sha256.New()
	},
}

// hashPoolSHA384 provides reusable SHA-384 hash instances.
var hashPoolSHA384 = sync.Pool{
	New: func() any {
		return sha512.New384()
	},
}

func (s *Signer) acquireDigest() hash.Hash {
	if s.keyType == keyTypeECDSAP384 {
		return hashPoolSHA384.Get().(hash.Hash)
	}
	return hashPoolSHA256.Get().(hash.Hash)
}

func (s *Signer) releaseDigest(h hash.Hash) {
	h.Reset()
	if s.keyType == keyTypeECDSAP384 {
		hashPoolSHA384.Put(h)
		return
	}
	hashPoolSHA256.Put(h)
}

// pendingSignature is a built incremental update whose /Contents placeholder is
// still waiting for its CMS signature.
type pendingSignature struct {
	incr        []byte  // the increment, aliasing buf
	buf         *[]byte // pooled backing buffer; the caller returns it to slicePool
	offsets     incrOffsets
	signingTime time.Time
}

// prepareIncrement parses the PDF and builds its incremental update, with
// /ByteRange already patched to the offsets the finished document will have.
//
// buf is non-nil on every return, error paths included, and the caller must
// hand it back to slicePool.
func (s *Signer) prepareIncrement(pdfData []byte, params SignParams) (pendingSignature, error) {
	reason, contact, location, page, rect, visible := s.resolveParams(params)
	srcSize := int64(len(pdfData))

	p := pendingSignature{
		buf:         slicePool.Get().(*[]byte),
		signingTime: time.Now().UTC(),
	}

	// Parse PDF structure using the custom parser (no pdfcpu).
	pi, err := parsePDF(pdfData, page)
	if err != nil {
		return p, err
	}

	p.incr, p.offsets, err = s.buildIncrement(*p.buf, &pi, srcSize, reason, contact, location, rect, visible, p.signingTime)
	*p.buf = p.incr
	if err != nil {
		return p, err
	}

	// The signed document is pdfData followed by the increment, so
	// increment-relative offsets become absolute by adding srcSize. The two
	// signed ranges straddle the /Contents value, angle brackets included.
	contentValueStart := srcSize + int64(p.offsets.contentsHexInIncr) - 1
	contentValueEnd := srcSize + int64(p.offsets.contentsHexEndIncr) + 1
	totalLen := srcSize + int64(len(p.incr))
	formatByteRange(p.incr, p.offsets.byteRangeInIncr, contentValueStart, contentValueEnd, totalLen-contentValueEnd)

	return p, nil
}

// signInto digests head followed by incr — everything except the /Contents
// value the two enclose — then builds the CMS signature and writes it into that
// placeholder. head and incr must together be the complete signed document, in
// that order.
func (s *Signer) signInto(head, incr []byte, offsets incrOffsets, signingTime time.Time) error {
	h := s.acquireDigest()
	h.Write(head)
	h.Write(incr[:offsets.contentsHexInIncr-1])
	h.Write(incr[offsets.contentsHexEndIncr+1:])
	var contentHashBuf [48]byte // 48 = max for SHA-384
	contentHash := h.Sum(contentHashBuf[:0])
	s.releaseDigest(h)

	cmsSig, err := s.buildCMSSignature(contentHash, signingTime)
	if err != nil {
		return fmt.Errorf("build CMS signature: %w", err)
	}

	sigHexLen := len(cmsSig) * 2
	if sigHexLen > s.contentsPlaceholderLen {
		return fmt.Errorf("CMS signature too large: %d hex chars (max %d)", sigHexLen, s.contentsPlaceholderLen)
	}
	encodeUpperHex(incr[offsets.contentsHexInIncr:offsets.contentsHexInIncr+sigHexLen], cmsSig)
	return nil
}

// SignBytes signs PDF bytes in memory and returns the signed PDF bytes.
func (s *Signer) SignBytes(pdfData []byte, params SignParams) ([]byte, error) {
	p, err := s.prepareIncrement(pdfData, params)
	if err != nil {
		slicePool.Put(p.buf)
		return nil, err
	}

	// Assemble the signed document before digesting it, so the digest is a
	// single linear pass over the finished buffer rather than a second pass
	// over the caller's input.
	result := make([]byte, len(pdfData)+len(p.incr))
	copy(result, pdfData)
	incr := result[len(pdfData):]
	copy(incr, p.incr)
	slicePool.Put(p.buf)

	if err := s.signInto(result[:len(pdfData)], incr, p.offsets, p.signingTime); err != nil {
		return nil, err
	}
	return result, nil
}

// srcBufPool holds buffers used by SignStream to read a whole source PDF.
var srcBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 256*1024)
		return &b
	},
}

// maxPooledSrcBuf caps what goes back into srcBufPool so one outsized PDF does
// not pin its buffer for the life of the process.
const maxPooledSrcBuf = 8 << 20

// SignStream signs a PDF by reading from src and writing the signed PDF to dst.
// Unlike SignBytes it never allocates a buffer holding both the source and the
// signed output; src is read once into a pooled buffer and written straight
// through to dst.
func (s *Signer) SignStream(src io.ReadSeeker, dst io.Writer, params SignParams) error {
	srcSize, err := src.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("seek end: %w", err)
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek start: %w", err)
	}

	sp := srcBufPool.Get().(*[]byte)
	data := *sp
	if int64(cap(data)) >= srcSize {
		data = data[:srcSize]
	} else {
		data = make([]byte, srcSize)
	}
	defer func() {
		if cap(data) <= maxPooledSrcBuf {
			*sp = data[:0]
			srcBufPool.Put(sp)
		}
	}()

	if _, err := io.ReadFull(src, data); err != nil {
		return fmt.Errorf("read source: %w", err)
	}

	p, err := s.prepareIncrement(data, params)
	defer slicePool.Put(p.buf)
	if err != nil {
		return err
	}
	if err := s.signInto(data, p.incr, p.offsets, p.signingTime); err != nil {
		return err
	}

	if _, err := dst.Write(data); err != nil {
		return fmt.Errorf("write src to dst: %w", err)
	}
	if _, err := dst.Write(p.incr); err != nil {
		return fmt.Errorf("write increment to dst: %w", err)
	}
	return nil
}

// Sign signs a PDF file and writes the result to the destination path.
// Output is staged in a temporary file and renamed over the destination, so a
// failure never leaves a truncated or unsigned file behind and readers only
// ever see the old or the new document. The rename is not fsynced, so contents
// are not guaranteed durable across a power loss. Signing in place
// (Dest == Src, or an empty Dest) is supported.
func (s *Signer) Sign(params SignParams) error {
	srcPath := params.Src
	destPath := params.Dest
	if destPath == "" {
		destPath = srcPath
	}

	preparedSrcPath, cleanupPreparedSrc, err := prepareCompatSource(srcPath)
	if err != nil {
		return fmt.Errorf("prepare source PDF: %w", err)
	}
	defer cleanupPreparedSrc()

	srcFile, err := os.Open(preparedSrcPath)
	if err != nil {
		return fmt.Errorf("open input PDF: %w", err)
	}
	defer srcFile.Close()

	// Keep the mode of whatever the output replaces; otherwise use the mode
	// os.Create would have given a fresh file.
	mode := os.FileMode(0o644)
	if st, statErr := os.Stat(destPath); statErr == nil {
		mode = st.Mode()
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(destPath), ".flashsign-*.pdf")
	if err != nil {
		return fmt.Errorf("create temp output PDF: %w", err)
	}
	tmpPath := tmpFile.Name()
	committed := false
	defer func() {
		if !committed {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	if err := s.SignStream(srcFile, tmpFile, params); err != nil {
		return fmt.Errorf("sign PDF: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp output PDF: %w", err)
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return fmt.Errorf("chmod temp output PDF: %w", err)
	}
	if err := os.Rename(tmpPath, destPath); err != nil {
		return fmt.Errorf("replace destination PDF: %w", err)
	}

	committed = true
	return nil
}

func prepareCompatSource(srcPath string) (preparedPath string, cleanup func(), err error) {
	hasXRefStream, err := sourceUsesXRefStream(srcPath)
	if err != nil {
		return "", nil, err
	}
	if !hasXRefStream {
		return srcPath, func() {}, nil
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(srcPath), ".flashsign-srcnorm-*.pdf")
	if err != nil {
		return "", nil, err
	}
	tmpPath := tmpFile.Name()
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", nil, err
	}

	// Rewrite to classic xref sections for better compatibility with strict viewers.
	conf := model.NewDefaultConfiguration()
	conf.ValidationMode = model.ValidationRelaxed
	conf.WriteObjectStream = false
	conf.WriteXRefStream = false
	conf.Optimize = false
	conf.OptimizeBeforeWriting = false
	conf.OptimizeResourceDicts = false
	conf.ValidateLinks = false

	if err := api.OptimizeFile(srcPath, tmpPath, conf); err != nil {
		_ = os.Remove(tmpPath)
		return "", nil, err
	}

	return tmpPath, func() { _ = os.Remove(tmpPath) }, nil
}

// sourceUsesXRefStream reports whether the file's most recent cross-reference
// section is an xref stream rather than a classic "xref" table: startxref
// points at the literal keyword for a classic table and at an object header for
// a stream. Hybrid-reference files keep a classic table and need no rewrite.
//
// Any failure to answer the question reports false, leaving the real diagnosis
// to the parser rather than failing the sign here.
func sourceUsesXRefStream(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return false, err
	}

	var tail [startxrefSearchWindow]byte
	readSize := st.Size()
	if readSize > int64(len(tail)) {
		readSize = int64(len(tail))
	}
	if readSize < int64(len(kwXref)) {
		return false, nil
	}
	if _, err := f.ReadAt(tail[:readSize], st.Size()-readSize); err != nil && err != io.EOF {
		return false, err
	}

	offset, err := findStartxref(tail[:readSize])
	if err != nil || offset <= 0 || offset > st.Size()-int64(len(kwXref)) {
		return false, nil
	}

	var head [4]byte
	if _, err := f.ReadAt(head[:], offset); err != nil && err != io.EOF {
		return false, nil
	}
	return !bytes.Equal(head[:], kwXref), nil
}

// SignAndEncrypt signs a PDF file and then encrypts it with AES.
// Like Sign, the destination is replaced by renaming a fully written temporary
// file over it.
func (s *Signer) SignAndEncrypt(params SignParams, enc EncryptParams) error {
	if enc.Password == "" {
		return fmt.Errorf("EncryptParams.Password is required")
	}

	pdfData, err := os.ReadFile(params.Src)
	if err != nil {
		return fmt.Errorf("read input PDF: %w", err)
	}

	destPath := params.Dest
	if destPath == "" {
		destPath = params.Src
	}

	keyLength := 128
	if enc.AES256 {
		keyLength = 256
	}

	signedData, err := s.SignBytes(pdfData, params)
	if err != nil {
		return fmt.Errorf("sign PDF: %w", err)
	}

	mode := os.FileMode(0o644)
	if st, statErr := os.Stat(destPath); statErr == nil {
		mode = st.Mode()
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(destPath), ".flashsign-enc-*.pdf")
	if err != nil {
		return fmt.Errorf("create temp output PDF: %w", err)
	}
	tmpPath := tmpFile.Name()
	committed := false
	defer func() {
		if !committed {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	if err := encryptPDFStream(bytes.NewReader(signedData), tmpFile, enc.Password, keyLength); err != nil {
		return fmt.Errorf("encrypt PDF: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp output PDF: %w", err)
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return fmt.Errorf("chmod temp output PDF: %w", err)
	}
	if err := os.Rename(tmpPath, destPath); err != nil {
		return fmt.Errorf("replace destination PDF: %w", err)
	}

	committed = true
	return nil
}

// SignBatch signs multiple PDFs concurrently, filling in each item's Result or
// Err. Workers pull from a shared cursor so a slow document cannot stall the
// others.
func (s *Signer) SignBatch(items []BatchItem) {
	workers := runtime.NumCPU()
	if len(items) < workers {
		workers = len(items)
	}
	if workers <= 0 {
		return
	}

	var next atomic.Int64
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= len(items) {
					return
				}
				items[i].Result, items[i].Err = s.SignBytes(items[i].PDFData, items[i].Params)
			}
		}()
	}

	wg.Wait()
}
