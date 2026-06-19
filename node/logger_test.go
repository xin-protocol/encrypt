package main

import (
	"testing"

	"github.com/rs/zerolog"
)

func TestParseLogLevelFallback(t *testing.T) {
	// Should fallback to InfoLevel on invalid log level
	lvl := parseLogLevel("invalid-log-level")

	if lvl != zerolog.InfoLevel {
		t.Errorf("expected level to fallback to InfoLevel, got %v", lvl)
	}
}
