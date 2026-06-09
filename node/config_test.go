package main

import (
	"os"
	"testing"
)

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr bool
	}{
		{"defaults are valid", nil, false},
		{"auto tls without domain fails", map[string]string{"TLS_MODE": "auto"}, true},
		{"auto tls with domain ok", map[string]string{"TLS_MODE": "auto", "DOMAIN": "example.com"}, false},
		{"manual tls no certs fails", map[string]string{"TLS_MODE": "manual"}, true},
		{"manual tls with certs ok", map[string]string{"TLS_MODE": "manual", "TLS_CERT": "c.pem", "TLS_KEY": "k.pem"}, false},
		{"invalid tls mode fails", map[string]string{"TLS_MODE": "bogus"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				os.Setenv(k, v)
				defer os.Unsetenv(k)
			}
			err := LoadConfig().Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() err=%v wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigMaxBodySize(t *testing.T) {
	os.Setenv("MAX_BODY_SIZE_MB", "25")
	defer os.Unsetenv("MAX_BODY_SIZE_MB")
	cfg := LoadConfig()
	if cfg.MaxBodySizeMB != 25 {
		t.Errorf("expected MaxBodySizeMB to be 25, got %d", cfg.MaxBodySizeMB)
	}
}

func TestConfigHealthCheckPath(t *testing.T) {
	os.Setenv("HEALTH_CHECK_PATH", "/custom-health")
	defer os.Unsetenv("HEALTH_CHECK_PATH")
	cfg := LoadConfig()
	if cfg.HealthCheckPath != "/custom-health" {
		t.Errorf("expected HealthCheckPath to be /custom-health, got %s", cfg.HealthCheckPath)
	}
}
