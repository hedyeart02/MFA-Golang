package ratelimiter

import (
	"context"
	"sync"
	"time"
)

type RateLimiter interface {
	Allow(ctx context.Context, key string) (bool, error)
}

// DetailedRateLimiter returns allowance alongside retry wait duration and remaining quota.
type DetailedRateLimiter interface {
	RateLimiter
	AllowDetailed(ctx context.Context, key string) (allowed bool, retryAfter time.Duration, remaining int, err error)
}

type bucket struct {
	count     int
	windowEnd time.Time
}

// MemoryRateLimiter is a thread-safe fixed-window rate limiter with bounded memory capacity.
type MemoryRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]bucket
	Limit   int
	Window  time.Duration
	MaxKeys int
	NowFunc func() time.Time
}

// NewMemoryRateLimiter constructs an in-memory per-key rate limiter.
func NewMemoryRateLimiter(limit int, window time.Duration) *MemoryRateLimiter {
	if window <= 0 {
		window = time.Minute
	}
	return &MemoryRateLimiter{
		buckets: make(map[string]bucket),
		Limit:   limit,
		Window:  window,
		MaxKeys: 10000,
		NowFunc: time.Now,
	}
}

func (m *MemoryRateLimiter) now() time.Time {
	if m.NowFunc != nil {
		return m.NowFunc()
	}
	return time.Now()
}

func (m *MemoryRateLimiter) Allow(ctx context.Context, key string) (bool, error) {
	allowed, _, _, err := m.AllowDetailed(ctx, key)
	return allowed, err
}

func (m *MemoryRateLimiter) AllowDetailed(ctx context.Context, key string) (bool, time.Duration, int, error) {
	if m.Limit <= 0 {
		return true, 0, 0, nil
	}

	window := m.Window
	if window <= 0 {
		window = time.Minute
	}
	maxKeys := m.MaxKeys
	if maxKeys <= 0 {
		maxKeys = 10000
	}

	now := m.now()

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.buckets == nil {
		m.buckets = make(map[string]bucket)
	}

	b, exists := m.buckets[key]
	if !exists || !now.Before(b.windowEnd) {
		// Evict expired keys when approaching cap to keep memory bounded
		if !exists && len(m.buckets) >= maxKeys {
			for k, v := range m.buckets {
				if !now.Before(v.windowEnd) {
					delete(m.buckets, k)
				}
			}
			// If still full under flood, evict oldest/arbitrary entry to stay bounded
			for len(m.buckets) >= maxKeys {
				for k := range m.buckets {
					delete(m.buckets, k)
					break
				}
			}
		}
		m.buckets[key] = bucket{
			count:     1,
			windowEnd: now.Add(window),
		}
		return true, 0, m.Limit - 1, nil
	}

	if b.count >= m.Limit {
		retryAfter := b.windowEnd.Sub(now)
		if retryAfter < time.Second {
			retryAfter = time.Second
		}
		return false, retryAfter, 0, nil
	}

	b.count++
	m.buckets[key] = b
	return true, 0, m.Limit - b.count, nil
}

type RedisRateLimiter struct{}

func (r *RedisRateLimiter) Allow(ctx context.Context, key string) (bool, error) {
	return true, nil // Stub
}
