package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
)

// buildTLSConfig creates a tls.Config enforcing TLS 1.3 minimum and HSTS.
func buildTLSConfig(cfg *Config) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS keypair: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}, nil
}

// hstsMiddleware injects Strict-Transport-Security header on all HTTPS responses.
func hstsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

// tlsModeDescription returns a human-readable description of the TLS mode.
func tlsModeDescription(mode string) string {
	switch mode {
	case "auto":
		return "Let's Encrypt automatic certificate"
	case "manual":
		return "manual certificate from file"
	default:
		return "plaintext HTTP (no TLS)"
	}
}

// minTLSVersion returns the minimum TLS version name for logging.
func minTLSVersionName() string { return "TLS 1.3" }

// hstsValue returns the Strict-Transport-Security header value.
func hstsValue() string { return "max-age=63072000; includeSubDomains; preload" }

// TLSConfigSummary returns a loggable string describing the active TLS config.
func TLSConfigSummary(cfg *Config) string {
	return fmt.Sprintf("mode=%s domain=%s cert=%s", cfg.TLSMode, cfg.Domain, cfg.TLSCert)
}
