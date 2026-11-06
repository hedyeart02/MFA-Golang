package binding

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/hidayat-SE/samlguard/internal/gateway/model"
)

// DefaultRequestDecoder implements the RequestDecoder interface
type DefaultRequestDecoder struct {
	MaxRequestSize   int
	MaxInflatedSize  int
	MaxCompressRatio float64
}

func (d *DefaultRequestDecoder) getMaxRequestSize() int {
	if d.MaxRequestSize > 0 {
		return d.MaxRequestSize
	}
	return 256 * 1024 // 256KB default
}

func (d *DefaultRequestDecoder) getMaxInflatedSize() int {
	if d.MaxInflatedSize > 0 {
		return d.MaxInflatedSize
	}
	return 2 * 1024 * 1024 // 2MB default
}

func (d *DefaultRequestDecoder) getMaxCompressRatio() float64 {
	if d.MaxCompressRatio > 0 {
		return d.MaxCompressRatio
	}
	return 20.0 // 20:1 default
}

// Decode extracts the SAMLRequest parameter, performs base64 decoding, inflation, and limits checks.
func (d *DefaultRequestDecoder) Decode(r *http.Request, binding string) (*model.TransportResult, error) {
	if r == nil {
		return nil, errors.New("http request is nil")
	}

	normBinding := binding
	switch binding {
	case BindingHTTPRedirect, SAMLBindingHTTPRedirect:
		normBinding = BindingHTTPRedirect
	case BindingHTTPPost, SAMLBindingHTTPPost:
		normBinding = BindingHTTPPost
	default:
		return nil, fmt.Errorf("unsupported binding type: %q", binding)
	}

	maxReqSize := d.getMaxRequestSize()
	maxInflatedSize := d.getMaxInflatedSize()
	maxCompressRatio := d.getMaxCompressRatio()

	var rawBase64 string
	var relayState string

	if normBinding == BindingHTTPRedirect {
		if r.URL == nil {
			return nil, errors.New("request URL is nil")
		}
		rawBase64 = r.URL.Query().Get("SAMLRequest")
		relayState = r.URL.Query().Get("RelayState")
	} else {
		_ = r.ParseForm()
		rawBase64 = r.PostFormValue("SAMLRequest")
		relayState = r.PostFormValue("RelayState")
		if relayState == "" && r.URL != nil {
			relayState = r.URL.Query().Get("RelayState")
		}
	}

	cleanBase64 := strings.TrimSpace(rawBase64)
	if cleanBase64 == "" {
		return nil, errors.New("missing SAMLRequest parameter")
	}

	if len(cleanBase64) > maxReqSize {
		return nil, fmt.Errorf("SAMLRequest exceeds maximum allowed size (%d > %d bytes)", len(cleanBase64), maxReqSize)
	}

	// Base64 Decode
	compressedBytes, err := base64.StdEncoding.DecodeString(cleanBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 SAMLRequest: %w", err)
	}
	if len(compressedBytes) == 0 {
		return nil, errors.New("decoded SAMLRequest payload is empty")
	}

	var inflatedBytes []byte

	if normBinding == BindingHTTPRedirect {
		// Inflate: RFC 1951 raw DEFLATE decompression
		inflated, err := d.inflate(compressedBytes, maxInflatedSize)
		if err != nil {
			return nil, err
		}
		inflatedBytes = inflated
	} else {
		// HTTP-POST payload is uncompressed raw XML
		if len(compressedBytes) > maxInflatedSize {
			return nil, fmt.Errorf("payload exceeds maximum allowed size (%d > %d bytes)", len(compressedBytes), maxInflatedSize)
		}
		inflatedBytes = compressedBytes
	}

	if len(inflatedBytes) == 0 {
		return nil, errors.New("payload is empty after decompression")
	}

	// Validate UTF-8
	if !utf8.Valid(inflatedBytes) {
		return nil, errors.New("payload contains invalid UTF-8 characters")
	}

	// Compression Ratio Check for HTTP-Redirect
	var ratio float64
	if normBinding == BindingHTTPRedirect && len(compressedBytes) > 0 {
		ratio = float64(len(inflatedBytes)) / float64(len(compressedBytes))
		if ratio > maxCompressRatio {
			return nil, fmt.Errorf("compression ratio %.2f exceeds maximum allowed limit %.2f (potential zip bomb)", ratio, maxCompressRatio)
		}
	}

	// Compute SHA256 of the processed XML payload
	sha256Sum := sha256.Sum256(inflatedBytes)
	sha256Hex := hex.EncodeToString(sha256Sum[:])

	res := &model.TransportResult{
		RawBase64:        cleanBase64,
		CompressedBytes:  compressedBytes,
		InflatedBytes:    inflatedBytes,
		SHA256:           sha256Hex,
		CompressionRatio: ratio,
		InflatedSize:     len(inflatedBytes),
		RelayState:       relayState,
		BindingType:      normBinding,
	}

	return res, nil
}

// inflate performs RFC 1951 raw DEFLATE decompression with an io.LimitReader to protect against zip bombs
func (d *DefaultRequestDecoder) inflate(compressed []byte, maxSize int) ([]byte, error) {
	reader := flate.NewReader(bytes.NewReader(compressed))
	defer reader.Close()

	limitReader := io.LimitReader(reader, int64(maxSize+1))
	inflated, err := io.ReadAll(limitReader)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress raw DEFLATE payload: %w", err)
	}

	if len(inflated) > maxSize {
		return nil, fmt.Errorf("inflated payload exceeds maximum allowed size (%d bytes)", maxSize)
	}

	return inflated, nil
}
