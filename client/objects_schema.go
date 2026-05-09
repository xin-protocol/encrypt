package main

import "time"

// ObjectRecord is a registry entry for a locally tracked encrypted object.
type ObjectRecord struct {
	ObjectID   string            `json:"object_id"`
	ContractID string            `json:"contract_id"`
	Nodes      []string          `json:"nodes"`
	Threshold  int               `json:"threshold"`
	EncFile    string            `json:"enc_file"`
	Tags       map[string]string `json:"tags,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}
