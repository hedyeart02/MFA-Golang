package replay

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestMemoryReplayDetector_DetectExpireAndConcurrency(t *testing.T) {
	d := NewMemoryReplayDetector()
	ctx := context.Background()

	// CheckAndMark should permit first occurrence and block duplicate
	if d.CheckAndMark("assertion-1", 50*time.Millisecond) {
		t.Fatal("first CheckAndMark should return false (not a replay)")
	}
	if !d.CheckAndMark("assertion-1", 50*time.Millisecond) {
		t.Fatal("duplicate CheckAndMark within TTL should return true (replay)")
	}

	isRep, err := d.IsReplay(ctx, "assertion-1", 50*time.Millisecond)
	if err != nil || !isRep {
		t.Fatalf("expected IsReplay=true within TTL, got %v, err=%v", isRep, err)
	}

	// Wait past TTL expiration
	time.Sleep(80 * time.Millisecond)
	if d.CheckAndMark("assertion-1", 50*time.Millisecond) {
		t.Fatal("expected expired entry to be cleared and allowed again")
	}

	// Concurrent uniqueness check
	var wg sync.WaitGroup
	wins := 0
	var mu sync.Mutex
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !d.CheckAndMark("concurrent-shared-id", time.Second) {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("expected exactly 1 goroutine to claim unique ID, got %d", wins)
	}
}
