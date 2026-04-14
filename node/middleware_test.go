package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIKeyMiddlewareRejects(t *testing.T) {
	h := apiKeyMiddleware("secret-key")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	InitLogger("error")

	req := httptest.NewRequest(http.MethodPost, "/store", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
	expected := "{\"error\":\"unauthorized\",\"reason\":\"Invalid API Key\"}\n"
	if rr.Body.String() != expected {
		t.Errorf("expected body %q, got %q", expected, rr.Body.String())
	}
}

func TestAPIKeyMiddlewareAllows(t *testing.T) {
	h := apiKeyMiddleware("secret-key")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	InitLogger("error")

	req := httptest.NewRequest(http.MethodPost, "/store", nil)
	req.Header.Set("X-Api-Key", "secret-key")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestIPAllowlistDirectIP(t *testing.T) {
	InitLogger("error")
	h := ipAllowlistMiddleware([]string{"10.0.0.1"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/store", nil)
	req.RemoteAddr = "10.0.0.1:5555"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("allowed IP: expected 200, got %d", rr.Code)
	}
}

func TestIPAllowlistForwardedFor(t *testing.T) {
	InitLogger("error")
	h := ipAllowlistMiddleware([]string{"10.0.0.5"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/store", nil)
	req.RemoteAddr = "172.16.0.1:80"
	req.Header.Set("X-Forwarded-For", "10.0.0.5, 172.16.0.1")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("X-Forwarded-For: expected 200, got %d", rr.Code)
	}
}

func TestLoggingMiddleware(t *testing.T) {
	InitLogger("info")
	h := loggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/store", bytes.NewBufferString("hello world"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	// Test nil body
	reqNil := httptest.NewRequest(http.MethodGet, "/public-key", nil)
	rrNil := httptest.NewRecorder()
	h.ServeHTTP(rrNil, reqNil)
	if rrNil.Code != http.StatusOK {
		t.Errorf("expected 200 for nil body, got %d", rrNil.Code)
	}
}
