package main

import (
	"os"
	"testing"
	"time"
)

func TestObjectDBRoundTrip(t *testing.T) {
	f, err := os.CreateTemp("", "objects-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())

	if err := initObjectDB(f.Name()); err != nil {
		t.Fatal(err)
	}
	defer closeObjectDB()

	rec := ObjectRecord{
		ObjectID:   "abc123",
		ContractID: "CTEST",
		Threshold:  2,
		EncFile:    "test.enc",
		Tags:       map[string]string{"env": "test"},
		CreatedAt:  time.Now(),
	}
	if err := saveObject(rec); err != nil {
		t.Fatal(err)
	}

	got, ok, err := loadObject("abc123")
	if err != nil || !ok {
		t.Fatalf("loadObject: %v ok=%v", err, ok)
	}
	if got.ObjectID != rec.ObjectID {
		t.Errorf("expected %s, got %s", rec.ObjectID, got.ObjectID)
	}

	all, err := listObjects(map[string]string{"env": "test"})
	if err != nil || len(all) != 1 {
		t.Errorf("listObjects: got %d records, want 1, err=%v", len(all), err)
	}

	// Key-only filter
	all2, _ := listObjects(map[string]string{"env": ""})
	if len(all2) != 1 {
		t.Errorf("key-only filter: expected 1, got %d", len(all2))
	}

	if err := deleteObject("abc123"); err != nil {
		t.Fatal(err)
	}
	_, ok2, _ := loadObject("abc123")
	if ok2 {
		t.Error("object should be deleted")
	}
}
