package metadata

import (
	"context"
	"io"
	"net/http"
	"os"
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
