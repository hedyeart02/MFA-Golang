package replay

import (
	"context"
	"sync"
	"time"
)

// ReplayDetector ensures an AuthnRequest or Assertion ID isn't processed more than once.
type ReplayDetector interface {
	IsReplay(ctx context.Context, requestID string, expiry time.Duration) (bool, error)
	MarkSeen(ctx context.Context, requestID string, expiry time.Duration) error
}

// MemoryReplayDetector provides thread-safe bounded replay detection with TTL expiration.
type MemoryReplayDetector struct {
	mu         sync.Mutex
	seen       map[string]time.Time
	maxEntries int
}

func NewMemoryReplayDetector() *MemoryReplayDetector {
	return &MemoryReplayDetector{
		seen:       make(map[string]time.Time),
		maxEntries: 20000,
	}
}

func (m *MemoryReplayDetector) IsReplay(ctx context.Context, requestID string, expiry time.Duration) (bool, error) {
	if requestID == "" {
		return false, nil
	}
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.seen == nil {
		return false, nil
	}

	exp, ok := m.seen[requestID]
	if !ok {
		return false, nil
	}
	if !now.Before(exp) {
		delete(m.seen, requestID)
		return false, nil
	}
	return true, nil
}

func (m *MemoryReplayDetector) MarkSeen(ctx context.Context, requestID string, expiry time.Duration) error {
	if requestID == "" {
		return nil
	}
	if expiry <= 0 {
		expiry = 10 * time.Minute
	}
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	m.markLocked(requestID, now, expiry)
	return nil
}

// CheckAndMark atomically tests whether requestID was already seen (and unexpired),
// and records it if not. Returns true if it is a replay.
func (m *MemoryReplayDetector) CheckAndMark(requestID string, expiry time.Duration) bool {
	if requestID == "" {
		return false
	}
	if expiry <= 0 {
		expiry = 10 * time.Minute
	}
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.seen == nil {
		m.seen = make(map[string]time.Time)
	}
	if exp, ok := m.seen[requestID]; ok {
		if now.Before(exp) {
			return true
		}
		delete(m.seen, requestID)
	}

	m.markLocked(requestID, now, expiry)
	return false
}

func (m *MemoryReplayDetector) markLocked(requestID string, now time.Time, expiry time.Duration) {
	if m.seen == nil {
		m.seen = make(map[string]time.Time)
	}
	maxCap := m.maxEntries
	if maxCap <= 0 {
		maxCap = 20000
	}
	if len(m.seen) >= maxCap {
		for k, exp := range m.seen {
			if !now.Before(exp) {
				delete(m.seen, k)
			}
		}
		for len(m.seen) >= maxCap {
			for k := range m.seen {
				delete(m.seen, k)
				break
			}
		}
	}
	m.seen[requestID] = now.Add(expiry)
}

type RedisReplayDetector struct{}

func (r *RedisReplayDetector) IsReplay(ctx context.Context, requestID string, expiry time.Duration) (bool, error) {
	return false, nil // Stub
}

func (r *RedisReplayDetector) MarkSeen(ctx context.Context, requestID string, expiry time.Duration) error {
	return nil // Stub
}
