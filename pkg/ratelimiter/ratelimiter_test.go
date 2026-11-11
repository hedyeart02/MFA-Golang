package ratelimiter

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestMemoryRateLimiter_EnforcesLimitAndResetsWindow(t *testing.T) {
	now := time.Unix(1700000000, 0)
	limiter := NewMemoryRateLimiter(3, time.Minute)
	limiter.NowFunc = func() time.Time { return now }

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		allowed, _, rem, err := limiter.AllowDetailed(ctx, "192.0.2.10")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Fatalf("request %d should be allowed", i+1)
		}
		if rem != 2-i {
			t.Fatalf("expected remaining=%d, got %d", 2-i, rem)
		}
	}

	// 4th request within same window must be denied with Retry-After
	allowed, retryAfter, _, err := limiter.AllowDetailed(ctx, "192.0.2.10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Fatal("expected 4th request to be rate limited")
	}
	if retryAfter <= 0 {
		t.Fatalf("expected positive retryAfter, got %v", retryAfter)
	}

	// Different IP key remains unaffected
	okOther, _ := limiter.Allow(ctx, "192.0.2.11")
	if !okOther {
		t.Fatal("different client key should not share rate limit bucket")
	}

	// Advance past window expiry
	now = now.Add(61 * time.Second)
	okReset, _ := limiter.Allow(ctx, "192.0.2.10")
	if !okReset {
		t.Fatal("expected bucket to reset after window expires")
	}
}

func TestMemoryRateLimiter_BoundedKeysConcurrency(t *testing.T) {
	limiter := NewMemoryRateLimiter(5, time.Minute)
	limiter.MaxKeys = 50

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := time.Now().Format("15:04:05.000000000") + string(rune('a'+(id%26)))
			_, _ = limiter.Allow(context.Background(), key)
		}(i)
	}
	wg.Wait()

	limiter.mu.Lock()
	count := len(limiter.buckets)
	limiter.mu.Unlock()
	if count > 50 {
		t.Fatalf("expected buckets capped at <= 50, got %d", count)
	}
}
