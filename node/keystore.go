package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
)

const keyFileName = "node_key.pem"

// LoadOrGenerateKey loads an existing P-256 key from disk or generates and persists a new one.
func LoadOrGenerateKey(dataDir string) (*ecdh.PrivateKey, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}
	keyPath := dataDir + "/" + keyFileName

	// Try to load existing key
	if data, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(data)
		if block != nil && block.Type == "EC PRIVATE KEY" {
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err == nil {
				return key.ECDH()
			}
		}
	}

	// Generate new key
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate P-256 key: %w", err)
	}

	// Persist to disk
	if err := saveKeyToDisk(priv, keyPath); err != nil {
		return nil, fmt.Errorf("failed to persist node key: %w", err)
	}

	return priv, nil
}

func saveKeyToDisk(priv *ecdh.PrivateKey, path string) error {
	ecKey, err := privToEC(priv)
	if err != nil {
		return err
	}
	derBytes, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		return fmt.Errorf("failed to marshal EC key: %w", err)
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: derBytes}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
}

func privToEC(priv *ecdh.PrivateKey) (*ecdsa.PrivateKey, error) {
	raw := priv.Bytes()
	key := new(ecdsa.PrivateKey)
	key.Curve = elliptic.P256()
	key.D = new(big.Int).SetBytes(raw)
	key.PublicKey.Curve = elliptic.P256()
	key.PublicKey.X, key.PublicKey.Y = elliptic.P256().ScalarBaseMult(raw)
	return key, nil
}
