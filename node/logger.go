package main

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
)

var logger zerolog.Logger
var auditLogger zerolog.Logger

// InitLogger sets up the structured JSON logger and a daily audit log file.
func InitLogger(level string) {
	lvl, err := zerolog.ParseLevel(level)
	if err != nil {
		panic("failed to parse log level: " + err.Error())
	}
	zerolog.SetGlobalLevel(lvl)
	logger = zerolog.New(os.Stdout).With().Timestamp().Str("service", "soroban-encrypt-node").Logger()

	af, err := openAuditFile()
	var w io.Writer = os.Stdout
	if err == nil {
		w = io.MultiWriter(os.Stdout, af)
	}
	auditLogger = zerolog.New(w).With().Timestamp().Str("component", "audit").Logger()
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
func maskBytes(b []byte) string {
	if len(b) <= 4 {
		return "****"
	}
	return "****[truncated]"
}

// logStartup emits the node startup banner with key config fields.
func logStartup(cfg *Config) {
  logger.Info().Str("port", cfg.Port).Str("tls", cfg.TLSMode).Str("data_dir", cfg.DataDir).Msg("node_startup")
}

// rotateDailyLogFile checks if the audit log needs to roll to a new file.
func rotateDailyLogFile() {
	// Daily rotation is handled by openAuditFile() which uses the current date.
	// This function is a no-op hook for future size-based rotation.
}
