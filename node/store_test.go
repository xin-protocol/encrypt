package main

import (
	"os"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestBoltShareRoundTrip(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("DATA_DIR", dir)

	var err error
	db, err = bolt.Open(dir+"/shares.db", 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(shareBucket))
		return err
	}); err != nil {
		t.Fatal(err)
	}

	want := StoredShareDB{
		EphemeralPubKey: []byte("pubkey"),
		Ciphertext:      []byte("cipher"),
		Nonce:           []byte("nonce1234567890a"),
	}

	if err := saveShare("contract_obj", want); err != nil {
		t.Fatalf("saveShare: %v", err)
	}

	got, ok, err := loadShare("contract_obj")
	if err != nil || !ok {
		t.Fatalf("loadShare: %v, ok=%v", err, ok)
	}

	if string(got.Ciphertext) != string(want.Ciphertext) {
		t.Errorf("ciphertext mismatch: got %s, want %s", got.Ciphertext, want.Ciphertext)
	}
}
