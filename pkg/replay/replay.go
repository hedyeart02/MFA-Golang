package replay

import (
	"context"
	"time"
)

// ReplayDetector ensures an AuthnRequest ID isn't processed more than once
type ReplayDetector interface {
	IsReplay(ctx context.Context, requestID string, expiry time.Duration) (bool, error)
	MarkSeen(ctx context.Context, requestID string, expiry time.Duration) error
}

type MemoryReplayDetector struct {
	seen map[string]time.Time
}

func NewMemoryReplayDetector() *MemoryReplayDetector {
	return &MemoryReplayDetector{seen: make(map[string]time.Time)}
}

func (m *MemoryReplayDetector) IsReplay(ctx context.Context, requestID string, expiry time.Duration) (bool, error) {
	_, ok := m.seen[requestID]
	return ok, nil
}

func (m *MemoryReplayDetector) MarkSeen(ctx context.Context, requestID string, expiry time.Duration) error {
	m.seen[requestID] = time.Now().Add(expiry)
	return nil
}

type RedisReplayDetector struct{}

func (r *RedisReplayDetector) IsReplay(ctx context.Context, requestID string, expiry time.Duration) (bool, error) {
	return false, nil // Stub
}

func (r *RedisReplayDetector) MarkSeen(ctx context.Context, requestID string, expiry time.Duration) error {
	return nil // Stub
}
