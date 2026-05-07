//go:build ignore

package main

import (
	"context"
	"fmt"
	"log"

	se "github.com/teeyml/soroban-encrypt/pkg/sorobanencrypt"
)

func main() {
	client := se.NewClient(
		se.WithNodes("http://node1:8080", "http://node2:8080", "http://node3:8080"),
		se.WithThreshold(2),
		se.WithContractID("CCONTRACT_ID_HERE"),
	)

	meta, err := client.Encrypt(context.Background(), "secret.txt", se.EncryptOptions{
		OutputPath: "secret.txt.enc",
		Tags:       map[string]string{"env": "production", "owner": "alice"},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Encrypted: object_id=%s enc_file=%s\n", meta.ObjectID, meta.EncFile)
}
