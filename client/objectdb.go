package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	bolt "go.etcd.io/bbolt"
)

const objBucket = "objects"

var objDB *bolt.DB

func initObjectDB(path string) error {
	var err error
	objDB, err = bolt.Open(path, 0600, nil)
	if err != nil {
		return err
	}
	return objDB.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(objBucket))
		return err
	})
}

func saveObject(rec ObjectRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return objDB.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(objBucket)).Put([]byte(rec.ObjectID), data)
	})
}

func loadObject(id string) (ObjectRecord, bool, error) {
	var rec ObjectRecord
	err := objDB.View(func(tx *bolt.Tx) error {
		v := tx.Bucket([]byte(objBucket)).Get([]byte(id))
		if v == nil {
			return nil
		}
		return json.Unmarshal(v, &rec)
	})
	return rec, rec.ObjectID != "", err
}

func listObjects(tagFilter map[string]string) ([]ObjectRecord, error) {
	var records []ObjectRecord
	err := objDB.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(objBucket)).ForEach(func(k, v []byte) error {
			var rec ObjectRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if matchesTags(rec, tagFilter) {
				records = append(records, rec)
			}
			return nil
		})
	})
	return records, err
}

func matchesTags(rec ObjectRecord, filter map[string]string) bool {
	for k, v := range filter {
		if v == "" {
			// key-only match
			if _, ok := rec.Tags[k]; !ok {
				return false
			}
		} else {
			if rec.Tags[k] != v {
				return false
			}
		}
	}
	return true
}

func deleteObject(id string) error {
	return objDB.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(objBucket)).Delete([]byte(id))
	})
}

func printObjects(records []ObjectRecord) {
	if len(records) == 0 {
		fmt.Println("No encrypted objects found.")
		return
	}
	fmt.Printf("%-36s  %-12s  %-3s  %s\n", "OBJECT ID", "CREATED", "THR", "FILE")
	fmt.Println(strings.Repeat("-", 80))
	for _, r := range records {
		fmt.Printf("%-36s  %-12s  %-3d  %s\n",
			r.ObjectID, r.CreatedAt.Format("2006-01-02"), r.Threshold, r.EncFile)
	}
}

func closeObjectDB() {
	if objDB != nil {
		objDB.Close()
	}
}

// homeDir returns the user home directory for default DB path.
func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return "."
}
