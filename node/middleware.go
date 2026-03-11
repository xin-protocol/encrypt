package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// loggingMiddleware records every HTTP request with zerolog structured fields.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(rw, r)
		logger.Info().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Str("remote_addr", r.RemoteAddr).
			Int("status", rw.code).
			Int64("duration_us", time.Since(start).Microseconds()).
			Msg("http_request")
	})
}

// bodySizeLimitMiddleware caps request body at maxBytes to prevent OOM.
func bodySizeLimitMiddleware(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}

// apiKeyMiddleware enforces X-Api-Key header when a key is configured.
func apiKeyMiddleware(expectedKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if expectedKey == "" {
				next.ServeHTTP(w, r)
				return
			}
			if !secureStringEqual(r.Header.Get("X-Api-Key"), expectedKey) {
				logger.Warn().Str("path", r.URL.Path).Str("remote", r.RemoteAddr).Msg("api_key_rejected")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// secureStringEqual compares two strings in constant time to prevent timing attacks.
func secureStringEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// ipAllowlistMiddleware restricts /store to configured IP ranges.
func ipAllowlistMiddleware(allowed []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(allowed) == 0 {
				next.ServeHTTP(w, r)
				return
			}
			ip := strings.Split(r.RemoteAddr, ":")[0]
			if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
				ip = strings.TrimSpace(strings.Split(fwd, ",")[0])
			}
			for _, cidr := range allowed {
				if ip == cidr {
					next.ServeHTTP(w, r)
					return
				}
			}
			logger.Warn().Str("ip", ip).Msg("ip_allowlist_blocked")
			http.Error(w, fmt.Sprintf("IP %s not allowed", ip), http.StatusForbidden)
		})
	}
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.code = code
	sw.ResponseWriter.WriteHeader(code)
}

// maskSensitiveField returns a redacted version of a header value for logging.
func maskSensitiveField(v string) string {
	if len(v) < 8 {
		return "****"
	}
	return v[:4] + "****"
}
