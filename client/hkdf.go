package main

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// hkdfInfo matches the node constant exactly — do not change without updating both sides.
const hkdfInfo = "soroban-encrypt-share"

// DeriveAESKey derives a 32-byte AES key from an ECDH shared secret using HKDF-SHA256.
func DeriveAESKey(sharedSecret []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, sharedSecret, nil, []byte(hkdfInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}
