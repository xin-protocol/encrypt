package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func setupTestDB(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	var err error
	db, err = bolt.Open(dir+"/test.db", 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(shareBucket))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	globalStore = &BoltStore{}
	t.Cleanup(func() { db.Close() })
}

func TestHandleHealth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	handleHealth(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var body map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("expected status=ok, got %v", body["status"])
	}
}

func TestHandleReady_NoDB(t *testing.T) {
	origDB := db
	db = nil
	defer func() { db = origDB }()

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rr := httptest.NewRecorder()
	handleReady(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when db nil, got %d", rr.Code)
	}
}

func TestHandleStatus(t *testing.T) {
	setupTestDB(t)
	InitLogger("error")
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	rr := httptest.NewRecorder()
	handleStatus(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestHandlePublicKey(t *testing.T) {
	setupTestDB(t)
	InitLogger("error")
	// Generate a test key pair
	var err error
	nodePrivateKey, err = ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nodePublicKey = nodePrivateKey.PublicKey()

	req := httptest.NewRequest(http.MethodGet, "/public-key", nil)
	rr := httptest.NewRecorder()
	handleGetPublicKey(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}
