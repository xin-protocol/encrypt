package main

import (
	"bytes"
	"testing"
)

func TestHKDFDeterminism(t *testing.T) {
	secret := []byte("test-shared-secret-exactly-32byt")
	k1, err := DeriveAESKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := DeriveAESKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, k2) {
		t.Error("HKDF is not deterministic for the same input")
	}
	if len(k1) != 32 {
		t.Errorf("expected 32-byte key, got %d", len(k1))
	}
}
