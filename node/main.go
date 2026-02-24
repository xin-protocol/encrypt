package main

import (
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
)

type StoredShare struct {
	EphemeralPub []byte `json:"ephemeral_pub"`
	Ciphertext   []byte `json:"ciphertext"`
	Nonce        []byte `json:"nonce"`
}

var (
	store = make(map[string]StoredShare)
	mu    sync.RWMutex
	nodeKey *ecdh.PrivateKey
)

func main() {
	var err error
	nodeKey, err = GenerateNodeKey()
	if err != nil {
		fmt.Printf("Key generation failed: %v\n", err)
		os.Exit(1)
	}

	http.HandleFunc("/public-key", func(w http.ResponseWriter, r *http.Request) {
		pubHex := hex.EncodeToString(nodeKey.PublicKey().Bytes())
		w.Write([]byte(pubHex))
	})

	http.HandleFunc("/store", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ContractID   string `json:"contract_id"`
			ObjectID     string `json:"object_id"`
			EphemeralPub string `json:"ephemeral_pub"`
			Ciphertext   string `json:"ciphertext"`
			Nonce        string `json:"nonce"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		ephemeralBytes, _ := hex.DecodeString(req.EphemeralPub)
		cipherBytes, _ := hex.DecodeString(req.Ciphertext)
		nonceBytes, _ := hex.DecodeString(req.Nonce)

		mu.Lock()
		store[req.ContractID+":"+req.ObjectID] = StoredShare{
			EphemeralPub: ephemeralBytes,
			Ciphertext:   cipherBytes,
			Nonce:        nonceBytes,
		}
		mu.Unlock()

		w.Write([]byte("SUCCESS"))
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Printf("Node listening on :%s...\n", port)
	http.ListenAndServe(":"+port, nil)
}
