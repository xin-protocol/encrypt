package main

import (
	"sync"
	"testing"
)

func TestObjectRateLimiterBurst(t *testing.T) {
	objectLimiters = sync.Map{}
	allowed := 0
	for i := 0; i < 20; i++ {
		if checkObjectRateLimit("obj-test-abc") {
			allowed++
		}
	}
	// Burst is 5, so no more than 5 should pass immediately
	if allowed > 5 {
		t.Errorf("expected at most 5 requests through burst, got %d", allowed)
	}
	if allowed == 0 {
		t.Error("expected at least 1 request to pass burst")
	}
}
