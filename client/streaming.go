package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	// v1Magic is the 4-byte prefix for legacy single-chunk .enc files.
	v1Magic = "SE01"
	// v2Magic is the 4-byte prefix for v2 chunked streaming .enc files.
	v2Magic = "SE02"
	// chunkSize is the block size for v2 streaming encryption: 4MB.
	chunkSize = 4 * 1024 * 1024
)

// EncryptFileStreaming encrypts srcPath to dstPath using v2 chunked AES-GCM.
// Files > 64MB are split into 4MB blocks; smaller files use a single block.
func EncryptFileStreaming(srcPath, dstPath string, key []byte, compress bool) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer src.Close()

	dst, err := os.Create(dstPath)
	if err != nil {
		return fmt.Errorf("create dest: %w", err)
	}
	defer dst.Close()

	// Write magic
	if _, err := dst.Write([]byte(v2Magic)); err != nil {
		return err
	}

	// Read all chunks and encrypt
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	var chunks [][]byte
	buf := make([]byte, chunkSize)
	for {
		n, err := io.ReadFull(src, buf)
		if n > 0 {
			nonce := make([]byte, gcm.NonceSize())
			if _, err := rand.Read(nonce); err != nil {
				return err
			}
			ct := gcm.Seal(nil, nonce, buf[:n], nil)
			chunk := append(nonce, ct...)
			chunks = append(chunks, chunk)
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			return err
		}
	}

	// Write chunk count header
	if err := binary.Write(dst, binary.LittleEndian, uint32(len(chunks))); err != nil {
		return err
	}
	// Write chunk sizes
	for _, c := range chunks {
		if err := binary.Write(dst, binary.LittleEndian, uint32(len(c))); err != nil {
			return err
		}
	}
	// Write chunk data
	for _, c := range chunks {
		if _, err := dst.Write(c); err != nil {
			return err
		}
	}

	return nil
}

// DecryptFileStreaming decrypts a v1 or v2 .enc file to dstPath.
func DecryptFileStreaming(srcPath, dstPath string, key []byte) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("open enc file: %w", err)
	}
	defer src.Close()

	magic := make([]byte, 4)
	if _, err := io.ReadFull(src, magic); err != nil {
		return fmt.Errorf("read magic: %w", err)
	}

	switch string(magic) {
	case v1Magic:
		return decryptV1(src, dstPath, key)
	case v2Magic:
		return decryptV2(src, dstPath, key)
	default:
		return fmt.Errorf("unknown .enc file format: %q", magic)
	}
}

func decryptV1(r io.Reader, dstPath string, key []byte) error {
	ct, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	if len(ct) < gcm.NonceSize() {
		return fmt.Errorf("v1 ciphertext too short")
	}
	nonce, ct := ct[:gcm.NonceSize()], ct[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return fmt.Errorf("v1 decryption failed: %w", err)
	}
	return os.WriteFile(dstPath, pt, 0600)
}

func decryptV2(r io.Reader, dstPath string, key []byte) error {
	var chunkCount uint32
	if err := binary.Read(r, binary.LittleEndian, &chunkCount); err != nil {
		return fmt.Errorf("read chunk count: %w", err)
	}
	if chunkCount == 0 || chunkCount > 10000 {
		return fmt.Errorf("invalid chunk count: %d", chunkCount)
	}

	sizes := make([]uint32, chunkCount)
	for i := range sizes {
		if err := binary.Read(r, binary.LittleEndian, &sizes[i]); err != nil {
			return fmt.Errorf("read chunk size %d: %w", i, err)
		}
	}

	dst, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer dst.Close()

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	for i, sz := range sizes {
		ct := make([]byte, sz)
		if _, err := io.ReadFull(r, ct); err != nil {
			return fmt.Errorf("read chunk %d: %w", i, err)
		}
		if len(ct) < gcm.NonceSize() {
			return fmt.Errorf("chunk %d too short", i)
		}
		nonce, ct := ct[:gcm.NonceSize()], ct[gcm.NonceSize():]
		pt, err := gcm.Open(nil, nonce, ct, nil)
		if err != nil {
			return fmt.Errorf("decrypt chunk %d: %w", i, err)
		}
		if _, err := dst.Write(pt); err != nil {
			return err
		}
	}
	return nil
}

// ChecksumFile computes the SHA-256 of a file for integrity verification.
func ChecksumFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
