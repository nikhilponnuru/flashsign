package flashsign

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"os"
	"runtime"
	"sync"
	"time"
)

// hashPool provides reusable SHA-256 hash instances.
var hashPool = sync.Pool{
	New: func() any {
		return sha256.New()
	},
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

	// Build incremental update.
	incr, offsets, err := s.buildIncrement(pi, srcSize, reason, contact, location, rect, visible, signingTime)
	if err != nil {
		return nil, err
	}

	// Combine original + increment into a single contiguous buffer.
	result := make([]byte, len(pdfData)+len(incr))
	copy(result, pdfData)
	copy(result[len(pdfData):], incr)

	// Return increment buffer to pool.
	slicePool.Put(incr[:0])

	// Compute absolute positions.
	contentValueStart := srcSize + int64(offsets.contentsHexInIncr) - 1
	contentValueEnd := srcSize + int64(offsets.contentsHexEndIncr) + 1
	totalLen := int64(len(result))

	// Patch ByteRange.
	byteRangePos := int(srcSize) + offsets.byteRangeInIncr
	formatByteRange(result, byteRangePos, contentValueStart, contentValueEnd, totalLen-contentValueEnd)

	// Hash signed ranges.
	h := hashPool.Get().(hash.Hash)
	h.Reset()
	h.Write(result[:contentValueStart])
	h.Write(result[contentValueEnd:])
	contentHash := h.Sum(nil)
	hashPool.Put(h)

	// Build CMS signature.
	cmsSig, err := s.buildCMSSignature(contentHash, signingTime)
	if err != nil {
		return nil, fmt.Errorf("build CMS signature: %w", err)
	}

	// Hex-encode and patch Contents.
	sigHexLen := len(cmsSig) * 2
	if sigHexLen > contentsPlaceholderLen {
		return nil, fmt.Errorf("CMS signature too large: %d hex chars (max %d)", sigHexLen, contentsPlaceholderLen)
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

	// Build incremental update.
	incr, offsets, err := s.buildIncrement(pi, srcSize, reason, contact, location, rect, visible, signingTime)
	if err != nil {
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

	h := hashPool.Get().(hash.Hash)
	h.Reset()

	if _, err := src.Seek(0, io.SeekStart); err != nil {
		hashPool.Put(h)
		return fmt.Errorf("seek start for hash: %w", err)
	}
	if _, err := io.Copy(h, src); err != nil {
		hashPool.Put(h)
		return fmt.Errorf("hash src: %w", err)
	}
	h.Write(incrBytes[:contentsIncrStart])
	h.Write(incrBytes[contentsIncrEnd:])

	contentHash := h.Sum(nil)
	hashPool.Put(h)

	// Build CMS signature.
	cmsSig, err := s.buildCMSSignature(contentHash, signingTime)
	if err != nil {
		return fmt.Errorf("build CMS signature: %w", err)
	}

	// Hex-encode into increment buffer.
	sigHexLen := len(cmsSig) * 2
	if sigHexLen > contentsPlaceholderLen {
		return fmt.Errorf("CMS signature too large: %d hex chars (max %d)", sigHexLen, contentsPlaceholderLen)
	}
	encodeUpperHex(incrBytes[offsets.contentsHexInIncr:offsets.contentsHexInIncr+sigHexLen], cmsSig)

	// Write output.
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek start for write: %w", err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("write src to dst: %w", err)
	}
	if _, err := dst.Write(incrBytes); err != nil {
		return fmt.Errorf("write increment to dst: %w", err)
	}

	// Return buffer to pool.
	slicePool.Put(incr[:0])

	return nil
}

// Sign signs a PDF file and writes the result to the destination path.
func (s *Signer) Sign(params SignParams) error {
	srcFile, err := os.Open(params.Src)
	if err != nil {
		return fmt.Errorf("open input PDF: %w", err)
	}
	defer srcFile.Close()

	destPath := params.Dest
	if destPath == "" {
		destPath = params.Src
	}

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

	dstFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("create output PDF: %w", err)
	}
	defer dstFile.Close()

	signedReader := bytes.NewReader(signedData)
	if err := encryptPDFStream(signedReader, dstFile, enc.Password, keyLength); err != nil {
		return fmt.Errorf("encrypt PDF: %w", err)
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
