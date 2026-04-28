package main

import (
	"encoding/json"
	"fmt"
	"os"

	bolt "go.etcd.io/bbolt"
)

const (
	shareBucket = "shares"
	dataDir     = "./data"
)

var db *bolt.DB

// StoredShareDB extends StoredShare with metadata for persistence
type StoredShareDB struct {
	EphemeralPubKey []byte `json:"ephemeral_pubkey"`
	Ciphertext      []byte `json:"ciphertext"`
	Nonce           []byte `json:"nonce"`
}

func initDB() error {
	dir := os.Getenv("DATA_DIR")
	if dir == "" {
		dir = dataDir
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create data directory %s: %w", dir, err)
	}

	var err error
	db, err = bolt.Open(dir+"/shares.db", 0600, nil)
	if err != nil {
		return fmt.Errorf("failed to open BoltDB: %w", err)
	}

	return db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(shareBucket))
		if err != nil {
			return fmt.Errorf("failed to create shares bucket: %w", err)
		}
		return nil
	})
}

func saveShare(key string, share StoredShareDB) error {
	data, err := json.Marshal(share)
	if err != nil {
		return err
	}
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(shareBucket))
		return b.Put([]byte(key), data)
	})
}

func loadShare(key string) (StoredShareDB, bool, error) {
	var share StoredShareDB
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(shareBucket))
		v := b.Get([]byte(key))
		if v == nil {
			return nil
		}
		return json.Unmarshal(v, &share)
	})
	if err != nil {
		return share, false, err
	}
	if share.Ciphertext == nil {
		return share, false, nil
	}
	return share, true, nil
}

func countShares() (int, error) {
	count := 0
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(shareBucket))
		return b.ForEach(func(k, v []byte) error {
			count++
			return nil
		})
	})
	return count, err
}

func deleteShare(key string) error {
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(shareBucket))
		return b.Delete([]byte(key))
	})
}

// closeDB cleanly closes the BoltDB handle — call on shutdown.
func closeDB() {
	if db != nil {
		if err := db.Close(); err != nil {
			fmt.Printf("warning: failed to close BoltDB: %v\n", err)
		}
	}
}

// StoredShareV2 extends StoredShareDB with a key version for rotation support.
type StoredShareV2 struct {
	EphemeralPubKey []byte `json:"ephemeral_pubkey"`
	Ciphertext      []byte `json:"ciphertext"`
	Nonce           []byte `json:"nonce"`
	KeyVersion      uint64 `json:"key_version"`
}

// listShareKeys returns all stored share keys (for debugging and rotation).
func listShareKeys() ([]string, error) {
	var keys []string
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(shareBucket))
		return b.ForEach(func(k, _ []byte) error {
			keys = append(keys, string(k))
			return nil
		})
	})
	return keys, err
}
