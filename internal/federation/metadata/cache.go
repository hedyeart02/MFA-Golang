package metadata

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/hidayat-SE/samlguard/internal/federation/model"
)

// CachedMetadata wraps the descriptor with cache lifecycle metadata
type CachedMetadata struct {
	Descriptor *model.MetadataDescriptor
	CachedAt   time.Time
	ExpiresAt  time.Time
}

// Cache manages the persistence of processed IdP metadata
type Cache struct {
	store map[string]CachedMetadata
	mu    sync.RWMutex
}

func NewCache() *Cache {
	return &Cache{
		store: make(map[string]CachedMetadata),
	}
}

// generateKey creates a SHA-256 hash of the metadata source URI/Filepath
func (c *Cache) generateKey(source string) string {
	hash := sha256.Sum256([]byte(source))
	return hex.EncodeToString(hash[:])
}

func (c *Cache) Get(source string) (*model.MetadataDescriptor, bool) {
	key := c.generateKey(source)
	
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, exists := c.store[key]
	if !exists {
		return nil, false
	}

	if time.Now().After(item.ExpiresAt) {
		return nil, false // Expired
	}

	return item.Descriptor, true
}

func (c *Cache) Set(source string, descriptor *model.MetadataDescriptor, ttl time.Duration) {
	key := c.generateKey(source)
	
	c.mu.Lock()
	defer c.mu.Unlock()

	c.store[key] = CachedMetadata{
		Descriptor: descriptor,
		CachedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(ttl),
	}
}
