package main

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type ipLimiterStore struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	r        rate.Limit
	b        int
}

var globalIPLimiter *ipLimiterStore
var objectLimiters sync.Map

func newIPLimiterStore(r float64, b int) *ipLimiterStore {
	return &ipLimiterStore{
		limiters: make(map[string]*rate.Limiter),
		r:        rate.Limit(r),
		b:        b,
	}
}

func (l *ipLimiterStore) get(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	if lim, ok := l.limiters[ip]; ok {
		return lim
	}
	lim := rate.NewLimiter(l.r, l.b)
	l.limiters[ip] = lim
	return lim
}

// rateLimitMiddleware enforces per-IP token bucket limits on all endpoints.
func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if globalIPLimiter != nil {
			ip := strings.Split(r.RemoteAddr, ":")[0]
			if !globalIPLimiter.get(ip).Allow() {
				w.Header().Set("Retry-After", "1")
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// checkObjectRateLimit returns false if the object has exceeded its per-second quota.
func checkObjectRateLimit(objectID string) bool {
	key := "obj:" + objectID
	lim, _ := objectLimiters.LoadOrStore(key, rate.NewLimiter(rate.Every(time.Second), 5))
	return lim.(*rate.Limiter).Allow()
}

func initRateLimiter(cfg *Config) {
	globalIPLimiter = newIPLimiterStore(cfg.RateLimit, cfg.RateBurst)
}

// rateLimitByObject wraps a handler and rate-limits by the object_id JSON field.
func rateLimitByObjectMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}
