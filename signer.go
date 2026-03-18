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

// SignBytes signs PDF bytes in memory and returns the signed PDF bytes.
func (s *Signer) SignBytes(pdfData []byte, params SignParams) ([]byte, error) {
	reason, contact, location, page, rect, visible := s.resolveParams(params)
	signingTime := time.Now().UTC()
	srcSize := int64(len(pdfData))

	// Parse PDF structure using custom parser (no pdfcpu).
	pi, err := parsePDF(pdfData, page)
	if err != nil {
		return nil, err
	}

	// Get pooled buffer for increment.
	bp := slicePool.Get().(*[]byte)

	// Build incremental update.
	incr, offsets, err := s.buildIncrement(*bp, &pi, srcSize, reason, contact, location, rect, visible, signingTime)
	if err != nil {
		*bp = incr
		slicePool.Put(bp)
		return nil, err
	}

	// Combine original + increment into a single contiguous buffer.
	result := make([]byte, len(pdfData)+len(incr))
	copy(result, pdfData)
	copy(result[len(pdfData):], incr)

	// Return increment buffer to pool.
	*bp = incr
	slicePool.Put(bp)

	// Compute absolute positions.
	contentValueStart := srcSize + int64(offsets.contentsHexInIncr) - 1
	contentValueEnd := srcSize + int64(offsets.contentsHexEndIncr) + 1
	totalLen := int64(len(result))

	// Patch ByteRange.
	byteRangePos := int(srcSize) + offsets.byteRangeInIncr
	formatByteRange(result, byteRangePos, contentValueStart, contentValueEnd, totalLen-contentValueEnd)

	// Hash signed ranges.
	h := s.acquireDigest()
	h.Reset()
	h.Write(result[:contentValueStart])
	h.Write(result[contentValueEnd:])
	var contentHashBuf [48]byte // 48 = max for SHA-384
	contentHash := h.Sum(contentHashBuf[:0])
	s.releaseDigest(h)

	// Build CMS signature.
	cmsSig, err := s.buildCMSSignature(contentHash, signingTime)
	if err != nil {
		return nil, fmt.Errorf("build CMS signature: %w", err)
	}

	// Hex-encode and patch Contents.
	sigHexLen := len(cmsSig) * 2
	if sigHexLen > s.contentsPlaceholderLen {
		return nil, fmt.Errorf("CMS signature too large: %d hex chars (max %d)", sigHexLen, s.contentsPlaceholderLen)
	}
	contentsHexStart := int(srcSize) + offsets.contentsHexInIncr
	encodeUpperHex(result[contentsHexStart:contentsHexStart+sigHexLen], cmsSig)

	return result, nil
}

// SignStream signs a PDF by reading from src and writing the signed PDF to dst.
func (s *Signer) SignStream(src io.ReadSeeker, dst io.Writer, params SignParams) error {
	reason, contact, location, page, rect, visible := s.resolveParams(params)
	signingTime := time.Now().UTC()

	srcSize, err := src.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("seek end: %w", err)
	}

	// Parse PDF structure.
	pi, err := parsePDFReader(src, srcSize, page)
	if err != nil {
		return err
	}

	// Get pooled buffer for increment.
	bp := slicePool.Get().(*[]byte)

	// Build incremental update.
	incr, offsets, err := s.buildIncrement(*bp, &pi, srcSize, reason, contact, location, rect, visible, signingTime)
	if err != nil {
		*bp = incr
		slicePool.Put(bp)
		return err
	}

	incrBytes := incr

	// Compute absolute positions.
	contentValueStart := srcSize + int64(offsets.contentsHexInIncr) - 1
	contentValueEnd := srcSize + int64(offsets.contentsHexEndIncr) + 1
	totalLen := srcSize + int64(len(incrBytes))

	// Patch ByteRange.
	formatByteRange(incrBytes, offsets.byteRangeInIncr, contentValueStart, contentValueEnd, totalLen-contentValueEnd)

	// Hash signed ranges.
	contentsIncrStart := offsets.contentsHexInIncr - 1
	contentsIncrEnd := offsets.contentsHexEndIncr + 1

	h := s.acquireDigest()
	h.Reset()

	if _, err := src.Seek(0, io.SeekStart); err != nil {
		s.releaseDigest(h)
		*bp = incr
		slicePool.Put(bp)
		return fmt.Errorf("seek start for hash: %w", err)
	}
	if _, err := io.Copy(h, src); err != nil {
		s.releaseDigest(h)
		*bp = incr
		slicePool.Put(bp)
		return fmt.Errorf("hash src: %w", err)
	}
	h.Write(incrBytes[:contentsIncrStart])
	h.Write(incrBytes[contentsIncrEnd:])

	var contentHashBuf [48]byte
	contentHash := h.Sum(contentHashBuf[:0])
	s.releaseDigest(h)

	// Build CMS signature.
	cmsSig, err := s.buildCMSSignature(contentHash, signingTime)
	if err != nil {
		*bp = incr
		slicePool.Put(bp)
		return fmt.Errorf("build CMS signature: %w", err)
	}

	// Hex-encode into increment buffer.
	sigHexLen := len(cmsSig) * 2
	if sigHexLen > s.contentsPlaceholderLen {
		*bp = incr
		slicePool.Put(bp)
		return fmt.Errorf("CMS signature too large: %d hex chars (max %d)", sigHexLen, s.contentsPlaceholderLen)
	}
	encodeUpperHex(incrBytes[offsets.contentsHexInIncr:offsets.contentsHexInIncr+sigHexLen], cmsSig)

	// Write output.
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		*bp = incr
		slicePool.Put(bp)
		return fmt.Errorf("seek start for write: %w", err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		*bp = incr
		slicePool.Put(bp)
		return fmt.Errorf("write src to dst: %w", err)
	}
	if _, err := dst.Write(incrBytes); err != nil {
		*bp = incr
		slicePool.Put(bp)
		return fmt.Errorf("write increment to dst: %w", err)
	}

	// Return buffer to pool.
	*bp = incr
	slicePool.Put(bp)

	return nil
}

// Sign signs a PDF file and writes the result to the destination path.
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

	if sameFilePath(srcPath, destPath) {
		return s.signInPlace(params, preparedSrcPath, destPath)
	}

	srcFile, err := os.Open(preparedSrcPath)
	if err != nil {
		return fmt.Errorf("open input PDF: %w", err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("create output PDF: %w", err)
	}
	defer dstFile.Close()

	if err := s.SignStream(srcFile, dstFile, params); err != nil {
		return fmt.Errorf("sign PDF: %w", err)
	}
	return nil
}

func (s *Signer) signInPlace(params SignParams, srcPath, destPath string) error {
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("open input PDF: %w", err)
	}
	defer srcFile.Close()

	srcStat, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("stat input PDF: %w", err)
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(destPath), ".flashsign-*.pdf")
	if err != nil {
		return fmt.Errorf("create temp output PDF: %w", err)
	}
	tmpPath := tmpFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	if err := s.SignStream(srcFile, tmpFile, params); err != nil {
		return fmt.Errorf("sign PDF: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("sync temp output PDF: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp output PDF: %w", err)
	}
	if err := os.Chmod(tmpPath, srcStat.Mode()); err != nil {
		return fmt.Errorf("chmod temp output PDF: %w", err)
	}
	if err := os.Rename(tmpPath, destPath); err != nil {
		return fmt.Errorf("replace destination PDF: %w", err)
	}

	cleanup = false
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

	const maxTail = 1 << 20 // 1MB
	readSize := st.Size()
	if readSize > maxTail {
		readSize = maxTail
	}
	start := st.Size() - readSize
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return false, err
	}

	buf := make([]byte, readSize)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return false, err
	}
	buf = buf[:n]

	return bytes.Contains(buf, []byte("/Type/XRef")) ||
		bytes.Contains(buf, []byte("/Type /XRef")), nil
}

// SignAndEncrypt signs a PDF file and then encrypts it with AES.
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

	inPlace := sameFilePath(params.Src, destPath)
	outPath := destPath
	if inPlace {
		tmpFile, err := os.CreateTemp(filepath.Dir(destPath), ".flashsign-enc-*.pdf")
		if err != nil {
			return fmt.Errorf("create temp output PDF: %w", err)
		}
		outPath = tmpFile.Name()
		if err := tmpFile.Close(); err != nil {
			return fmt.Errorf("close temp output PDF: %w", err)
		}
		defer os.Remove(outPath)
	}

	dstFile, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create output PDF: %w", err)
	}

	signedReader := bytes.NewReader(signedData)
	if err := encryptPDFStream(signedReader, dstFile, enc.Password, keyLength); err != nil {
		_ = dstFile.Close()
		return fmt.Errorf("encrypt PDF: %w", err)
	}
	if err := dstFile.Close(); err != nil {
		return fmt.Errorf("close output PDF: %w", err)
	}

	if inPlace {
		srcInfo, err := os.Stat(params.Src)
		if err == nil {
			if chmodErr := os.Chmod(outPath, srcInfo.Mode()); chmodErr != nil {
				return fmt.Errorf("chmod temp encrypted PDF: %w", chmodErr)
			}
		}
		if err := os.Rename(outPath, destPath); err != nil {
			return fmt.Errorf("replace destination PDF: %w", err)
		}
	}

	return nil
}

// SignBatch signs multiple PDFs concurrently.
func (s *Signer) SignBatch(items []BatchItem) {
	workers := runtime.NumCPU()
	if len(items) < workers {
		workers = len(items)
	}

	var wg sync.WaitGroup
	ch := make(chan int, len(items))

	for i := range items {
		ch <- i
	}
	close(ch)

	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for idx := range ch {
				result, err := s.SignBytes(items[idx].PDFData, items[idx].Params)
				items[idx].Result = result
				items[idx].Err = err
			}
		}()
	}

	wg.Wait()
}

func sameFilePath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	if errA == nil && errB == nil {
		return absA == absB
	}
	return filepath.Clean(a) == filepath.Clean(b)
}
