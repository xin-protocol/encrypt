//go:build ignore

package main

import (
	"context"
	"log"

	se "github.com/teeyml/soroban-encrypt/pkg/sorobanencrypt"
)

func main() {
	client := se.NewClient(
		se.WithNodes("http://node1:8080", "http://node2:8080", "http://node3:8080"),
		se.WithThreshold(2),
		se.WithContractID("CCONTRACT_ID_HERE"),
	)

	meta := &se.ObjectMetadata{
		ObjectID:   "OBJECT_ID_FROM_ENCRYPT",
		ContractID: "CCONTRACT_ID_HERE",
		Nodes:      []string{"http://node1:8080", "http://node2:8080", "http://node3:8080"},
		Threshold:  2,
		EncFile:    "secret.txt.enc",
	}

	if err := client.Decrypt(context.Background(), meta, se.DecryptOptions{
		OutputPath:    "secret.txt",
		CallerAddress: "GCALLER_ADDRESS",
	}); err != nil {
		log.Fatal(err)
	}
}
