package ratelimiter

import "context"

type RateLimiter interface {
	Allow(ctx context.Context, key string) (bool, error)
}

type MemoryRateLimiter struct {}
func (m *MemoryRateLimiter) Allow(ctx context.Context, key string) (bool, error) {
	return true, nil // Stub
}

type RedisRateLimiter struct {}
func (r *RedisRateLimiter) Allow(ctx context.Context, key string) (bool, error) {
	return true, nil // Stub
}
