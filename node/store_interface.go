package main

// ShareStore defines the interface for share persistence backends.
type ShareStore interface {
	Save(key string, share StoredShareDB) error
	Load(key string) (StoredShareDB, bool, error)
	Delete(key string) error
	Count() (int, error)
}

// BoltStore is the BoltDB implementation of ShareStore.
type BoltStore struct{}

func (s *BoltStore) Save(key string, share StoredShareDB) error  { return saveShare(key, share) }
func (s *BoltStore) Load(key string) (StoredShareDB, bool, error) { return loadShare(key) }
func (s *BoltStore) Delete(key string) error                      { return deleteShare(key) }
func (s *BoltStore) Count() (int, error)                          { return countShares() }

// globalStore is the active share store — swappable in tests.
var globalStore ShareStore = &BoltStore{}
