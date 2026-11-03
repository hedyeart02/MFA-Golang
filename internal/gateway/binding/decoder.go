package binding

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"unicode/utf8"

	"github.com/hidayat-SE/samlguard/internal/gateway/model"
)

// DefaultRequestDecoder implements the RequestDecoder interface
type DefaultRequestDecoder struct {
	MaxRequestSize   int
	MaxInflatedSize  int
	MaxCompressRatio float64
}

// Decode extracts the SAMLRequest parameter, performs base64 decoding, inflation, and limits checks.
func (d *DefaultRequestDecoder) Decode(r *http.Request, binding string) (*model.TransportResult, error) {
	if binding != "HTTP-Redirect" && binding != "HTTP-POST" {
		return nil, errors.New("unsupported binding type")
	}

	res := &model.TransportResult{
		BindingType: binding,
		RelayState:  r.URL.Query().Get("RelayState"),
	}

	var rawBase64 string
	if binding == "HTTP-Redirect" {
		rawBase64 = r.URL.Query().Get("SAMLRequest")
	} else {
		rawBase64 = r.PostFormValue("SAMLRequest")
		if res.RelayState == "" {
			res.RelayState = r.PostFormValue("RelayState")
		}
	}

	if rawBase64 == "" {
		return nil, errors.New("missing SAMLRequest parameter")
	}

	if len(rawBase64) > d.MaxRequestSize {
		return nil, errors.New("SAMLRequest exceeds maximum allowed size")
	}

	res.RawBase64 = rawBase64

	// Base64 Decode
	compressedBytes, err := base64.StdEncoding.DecodeString(rawBase64)
	if err != nil {
		return nil, errors.New("failed to decode base64 SAMLRequest")
	}
	res.CompressedBytes = compressedBytes

	if binding == "HTTP-Redirect" {
		// Inflate (DEFLATE compression is used for HTTP-Redirect)
		inflated, err := d.inflate(compressedBytes)
		if err != nil {
			return nil, err
		}
		res.InflatedBytes = inflated
		res.InflatedSize = len(inflated)
	} else {
		// HTTP-POST is typically not compressed, just base64 encoded
		res.InflatedBytes = compressedBytes
		res.InflatedSize = len(compressedBytes)
	}

	// Validate UTF-8
	if !utf8.Valid(res.InflatedBytes) {
		return nil, errors.New("inflated payload contains invalid UTF-8 characters")
	}

	// Compression Ratio Check
	if binding == "HTTP-Redirect" && len(compressedBytes) > 0 {
		res.CompressionRatio = float64(res.InflatedSize) / float64(len(compressedBytes))
		if res.CompressionRatio > d.MaxCompressRatio {
			return nil, errors.New("compression ratio exceeds maximum allowed limit (potential zip bomb)")
		}
	}

	// Compute SHA256 (stub for now, just placeholder so it compiles)
	res.SHA256 = "TODO_SHA256"

	return res, nil
}

// inflate performs DEFLATE decompression using an io.LimitReader to prevent zip bombs
func (d *DefaultRequestDecoder) inflate(compressed []byte) ([]byte, error) {
	reader := flate.NewReader(bytes.NewReader(compressed))
	defer reader.Close()

	// Use LimitReader to enforce maximum inflated size
	limitReader := io.LimitReader(reader, int64(d.MaxInflatedSize))
	inflated, err := io.ReadAll(limitReader)

	// If we read exactly MaxInflatedSize and haven't hit EOF on the underlying reader, it's too big
	if err == nil && len(inflated) == d.MaxInflatedSize {
		// Check if there is more data left
		b := make([]byte, 1)
		if n, _ := reader.Read(b); n > 0 {
			return nil, errors.New("inflated payload exceeds maximum allowed size")
		}
	} else if err != nil && err != io.EOF {
		return nil, err
	}

	return inflated, nil
}
