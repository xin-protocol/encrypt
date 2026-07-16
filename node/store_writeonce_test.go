package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestWriteOnceConflict(t *testing.T) {
	dir := t.TempDir()
	var err error
	db, err = bolt.Open(dir+"/test.db", 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = db.Update(func(tx *bolt.Tx) error {
		_, _ = tx.CreateBucketIfNotExists([]byte(shareBucket))
		return nil
	})
	globalStore = &BoltStore{}
	InitLogger("error")

	body := StoreRequest{
		ObjectID:        "obj1",
		ContractID:      "contract1",
		EphemeralPubKey: "aabbccdd",
		Ciphertext:      "deadbeef",
		Nonce:           "112233445566778899aabbcc",
	}
	b, _ := json.Marshal(body)

	// First write: should succeed
	req1 := httptest.NewRequest(http.MethodPost, "/store", bytes.NewReader(b))
	req1.Header.Set("Content-Type", "application/json")
	rr1 := httptest.NewRecorder()
	handleStoreShare(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first write: expected 200, got %d: %s", rr1.Code, rr1.Body.String())
	}

	// Second write without X-Overwrite: should 409
	req2 := httptest.NewRequest(http.MethodPost, "/store", bytes.NewReader(b))
	req2.Header.Set("Content-Type", "application/json")
	rr2 := httptest.NewRecorder()
	handleStoreShare(rr2, req2)
	if rr2.Code != http.StatusConflict {
		t.Errorf("duplicate write: expected 409, got %d", rr2.Code)
	}
}
