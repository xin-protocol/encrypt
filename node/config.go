package main

import (
	"fmt"
	"os"
	"strconv"
)

// Config holds all node runtime configuration.
type Config struct {
	Port          string
	DataDir       string
	SorobanRPCURL string
	StoreAPIKey   string
	LogLevel      string
	TLSMode       string
	TLSCert       string
	TLSKey        string
	Domain        string
	ACMECacheDir  string
	RateLimit     float64
	RateBurst     int
	MetricsAPIKey string
	TimeoutSecs   int
	Peers         []string
}

// LoadConfig reads all configuration from environment variables.
func LoadConfig() *Config {
	return &Config{
		Port:          getEnv("PORT", "8080"),
		DataDir:       getEnv("DATA_DIR", "./data"),
		SorobanRPCURL: getEnv("SOROBAN_RPC_URL", "https://soroban-testnet.stellar.org:443"),
		StoreAPIKey:   getEnv("STORE_API_KEY", ""),
		LogLevel:      getEnv("LOG_LEVEL", "info"),
		TLSMode:       getEnv("TLS_MODE", "off"),
		TLSCert:       getEnv("TLS_CERT", ""),
		TLSKey:        getEnv("TLS_KEY", ""),
		Domain:        getEnv("DOMAIN", ""),
		ACMECacheDir:  getEnv("ACME_CACHE_DIR", "./data/acme"),
		RateLimit:     getEnvFloat("RATE_LIMIT", 10.0),
		RateBurst:     getEnvInt("RATE_BURST", 20),
		MetricsAPIKey: getEnv("METRICS_API_KEY", ""),
		TimeoutSecs:   getEnvInt("TIMEOUT_SECONDS", 30),
	}
}

// Validate checks required configuration combinations.
func (c *Config) Validate() error {
	switch c.TLSMode {
	case "off":
		// ok
	case "auto":
		if c.Domain == "" {
			return fmt.Errorf("TLS_MODE=auto requires DOMAIN to be set")
		}
	case "manual":
		if c.TLSCert == "" || c.TLSKey == "" {
			return fmt.Errorf("TLS_MODE=manual requires both TLS_CERT and TLS_KEY to be set")
		}
	default:
		return fmt.Errorf("TLS_MODE must be one of: off, auto, manual (got %q)", c.TLSMode)
	}
	return nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvFloat(key string, fallback float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}
