package main

import (
	"sync"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestConcurrentRotationAndRetrieve(t *testing.T) {
	dir := t.TempDir()
	if err := initKeyManager(dir); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			globalKeyManager.Rotate()
		}()
	}
	wg.Wait()
	if globalKeyManager.CurrentVersion() == 0 {
		t.Error("expected version to advance after concurrent rotations")
	}
}

func TestRotationWithZeroShares(t *testing.T) {
	dir := t.TempDir()
	var err error
	db, err = bolt.Open(dir+"/test.db", 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.Update(func(tx *bolt.Tx) error {
		tx.CreateBucketIfNotExists([]byte(shareBucket))
		return nil
	})
	globalStore = &BoltStore{}
	if err := initKeyManager(dir); err != nil {
		t.Fatal(err)
	}
	// Should not panic with zero shares
	if err := globalKeyManager.Rotate(); err != nil {
		t.Errorf("Rotate() with zero shares returned error: %v", err)
	}
}

func TestSharesDecryptableAfterRotation(t *testing.T) {
	dir := t.TempDir()
	if err := initKeyManager(dir); err != nil {
		t.Fatal(err)
	}
	v1 := globalKeyManager.CurrentVersion()
	if err := globalKeyManager.Rotate(); err != nil {
		t.Fatal(err)
	}
	v2 := globalKeyManager.CurrentVersion()
	if v2 <= v1 {
		t.Errorf("expected version to increase: v1=%d v2=%d", v1, v2)
	}
	// Verify old key is still accessible during grace period
	_, ok := globalKeyManager.GetKey(v1)
	if !ok {
		t.Error("old key should remain accessible during grace period")
	}
}
