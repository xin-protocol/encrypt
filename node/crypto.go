package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/stellar/go-stellar-sdk/strkey"
)

// GenerateNodeKey makes a static P-256 key pair used for decrypting incoming SSS shares.
func GenerateNodeKey() (*ecdh.PrivateKey, error) {
	priv, err := ecdh.P256().GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate P-256 key: %w", err)
	}
	return priv, nil
}

// DecryptShare derives the ECDH shared secret and decrypts the share with AES-GCM.
func DecryptShare(nodePriv *ecdh.PrivateKey, ephemeralPubKeyBytes []byte, ciphertext []byte, nonce []byte) ([]byte, error) {
	// Parse the remote ephemeral public key
	ephemeralPub, err := ecdh.P256().NewPublicKey(ephemeralPubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key: %w", err)
	}

	// Compute shared secret using ECDH
	sharedSecret, err := nodePriv.ECDH(ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH key agreement failed: %w", err)
	}

	// Initialize AES-256 block cipher using the shared secret
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AES block cipher: %w", err)
	}

	// AES-GCM decryption
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AES-GCM: %w", err)
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (invalid ciphertext/nonce/key): %w", err)
	}

	return plaintext, nil
}

// EncryptShareForTesting is just for testing. Encrypts a share under the node's public key.
func EncryptShareForTesting(nodePub *ecdh.PublicKey, plaintext []byte, nonce []byte) ([]byte, []byte, error) {
	// Generate ephemeral key pair
	ephemeralPriv, err := ecdh.P256().GenerateKey(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}
	ephemeralPubBytes := ephemeralPriv.PublicKey().Bytes()

	// Compute shared secret
	sharedSecret, err := ephemeralPriv.ECDH(nodePub)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH failed: %w", err)
	}

	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
	return ephemeralPubBytes, ciphertext, nil
}

// VerifyStellarSignature validates an Ed25519 signature against a public G-address.
func VerifyStellarSignature(stellarAddress string, message []byte, signature []byte) (bool, error) {
	// Decode Stellar Address to raw Ed25519 public key bytes
	pubKeyBytes, err := strkey.Decode(strkey.VersionByteAccountID, stellarAddress)
	if err != nil {
		return false, fmt.Errorf("invalid Stellar address: %w", err)
	}

	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid public key size: expected %d bytes, got %d", ed25519.PublicKeySize, len(pubKeyBytes))
	}

	publicKey := ed25519.PublicKey(pubKeyBytes)
	isValid := ed25519.Verify(publicKey, message, signature)

	return isValid, nil
}
