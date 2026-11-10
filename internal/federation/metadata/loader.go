package metadata

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// MetadataLoader is responsible for retrieving raw XML bytes from various sources
type MetadataLoader interface {
	Load(ctx context.Context, source string) ([]byte, error)
}

// StaticFileLoader loads XML from the local filesystem
type StaticFileLoader struct{}
func (l *StaticFileLoader) Load(ctx context.Context, source string) ([]byte, error) {
	return os.ReadFile(source)
}

// HTTPMetadataLoader fetches XML from an external IDP URL
type HTTPMetadataLoader struct {
	Client *http.Client
}
func (l *HTTPMetadataLoader) Load(ctx context.Context, source string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", source, nil)
	if err != nil {
		return nil, err
	}
	resp, err := l.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// SmartLoader dynamically dispatches to HTTPMetadataLoader for http/https URLs and StaticFileLoader for file paths.
type SmartLoader struct {
	HTTPClient *http.Client
}

func (l *SmartLoader) Load(ctx context.Context, source string) ([]byte, error) {
	trimmed := strings.TrimSpace(source)
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		client := l.HTTPClient
		if client == nil {
			client = &http.Client{
				Timeout: 10 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}
		}
		loader := &HTTPMetadataLoader{Client: client}
		return loader.Load(ctx, trimmed)
	}
	fileLoader := &StaticFileLoader{}
	return fileLoader.Load(ctx, trimmed)
}

// MemoryLoader is primarily used for testing or direct byte injection
type MemoryLoader struct {
	Store map[string][]byte
}
func (l *MemoryLoader) Load(ctx context.Context, source string) ([]byte, error) {
	data, exists := l.Store[source]
	if !exists {
		return nil, os.ErrNotExist
	}
	return data, nil
}
