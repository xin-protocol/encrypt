package main

import (
	"io"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

var logger zerolog.Logger
var auditLogger zerolog.Logger
var loggerOnce sync.Once

// InitLogger sets up the structured JSON logger and a daily audit log file.
func InitLogger(level string) {
	lvl := parseLogLevel(level)
	zerolog.SetGlobalLevel(lvl)

	loggerOnce.Do(func() {
		logger = zerolog.New(os.Stdout).With().Timestamp().Str("service", "soroban-encrypt-node").Logger()

		af, err := openAuditFile()
		var w io.Writer = os.Stdout
		if err == nil {
			w = io.MultiWriter(os.Stdout, af)
		}
		auditLogger = zerolog.New(w).With().Timestamp().Str("component", "audit").Logger()
	})
}

func openAuditFile() (*os.File, error) {
	dir := os.Getenv("DATA_DIR")
	if dir == "" {
		dir = "./data"
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	date := time.Now().Format("2006-01-02")
	return os.OpenFile(dir+"/audit-"+date+".log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
}

// maskBytes redacts sensitive byte slices in log fields.
//nolint:unused
func maskBytes(b []byte) string {
	if len(b) <= 4 {
		return "****"
	}
	return "****[truncated]"
}

// logStartup emits the node startup banner with key config fields. //nolint:unused
//nolint:unused
func logStartup(cfg *Config) {
  logger.Info().Str("port", cfg.Port).Str("tls", cfg.TLSMode).Str("data_dir", cfg.DataDir).Msg("node_startup")
}
 //nolint:unused


// parseLogLevel parses level string or defaults to InfoLevel.
func parseLogLevel(level string) zerolog.Level {
	lvl, err := zerolog.ParseLevel(level)
	if err != nil {
		return zerolog.InfoLevel
	}
	return lvl
}
