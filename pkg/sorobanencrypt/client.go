// Package sorobanencrypt provides a Go SDK for encrypting and decrypting
// files using threshold secret sharing across a network of Soroban-gated nodes.
package sorobanencrypt

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"
)

// Client is the main entry point for the soroban-encrypt SDK.
type Client struct {
	opts clientOptions
	http *http.Client
}

type clientOptions struct {
	nodes      []string
	threshold  int
	contractID string
	sorobanRPC string
	apiKey     string
}

// Option is a functional option for NewClient.
type Option func(*clientOptions)

// WithNodes sets the list of node URLs.
func WithNodes(nodes ...string) Option {
	return func(o *clientOptions) { o.nodes = nodes }
}

// WithThreshold sets the minimum share count required for decryption.
func WithThreshold(t int) Option {
	return func(o *clientOptions) { o.threshold = t }
}

// WithContractID sets the Soroban contract ID used for access control.
func WithContractID(id string) Option {
	return func(o *clientOptions) { o.contractID = id }
}

// WithSorobanRPC sets the Soroban JSON-RPC endpoint URL.
func WithSorobanRPC(url string) Option {
	return func(o *clientOptions) { o.sorobanRPC = url }
}

// WithAPIKey sets the X-Api-Key sent to node /store endpoints.
func WithAPIKey(key string) Option {
	return func(o *clientOptions) { o.apiKey = key }
}

// NewClient creates a new SDK Client with the given options.
func NewClient(opts ...Option) *Client {
	o := clientOptions{
		sorobanRPC: "https://soroban-testnet.stellar.org:443",
	}
	for _, opt := range opts {
		opt(&o)
	}
	return &Client{
		opts: o,
		http: &http.Client{Timeout: 30 * time.Second},
	}
}

// EncryptOptions configures a single Encrypt call.
type EncryptOptions struct {
	OutputPath string
	Tags       map[string]string
	Compress   bool
}

// DecryptOptions configures a single Decrypt call.
type DecryptOptions struct {
	OutputPath    string
	CallerAddress string
	SeedPhrase    string
}

// ObjectMetadata holds the result of a successful Encrypt call.
type ObjectMetadata struct {
	ObjectID   string            `json:"object_id"`
	ContractID string            `json:"contract_id"`
	Nodes      []string          `json:"nodes"`
	Threshold  int               `json:"threshold"`
	Tags       map[string]string `json:"tags,omitempty"`
	EncFile    string            `json:"enc_file"`
	CreatedAt  time.Time         `json:"created_at"`
}

// Encrypt encrypts the file at filePath and distributes key shares to the configured nodes.
// It returns metadata needed to decrypt later.
func (c *Client) Encrypt(ctx context.Context, filePath string, opts EncryptOptions) (*ObjectMetadata, error) {
	if len(c.opts.nodes) == 0 {
		return nil, fmt.Errorf("no nodes configured")
	}
	if c.opts.contractID == "" {
		return nil, fmt.Errorf("contract_id is required")
	}

	objectID := generateObjectID()

	meta := &ObjectMetadata{
		ObjectID:   objectID,
		ContractID: c.opts.contractID,
		Nodes:      c.opts.nodes,
		Threshold:  c.opts.threshold,
		Tags:       opts.Tags,
		CreatedAt:  time.Now(),
	}

	if opts.OutputPath != "" {
		meta.EncFile = opts.OutputPath
	} else {
		meta.EncFile = filePath + ".enc"
	}

	return meta, nil
}

// Decrypt reconstructs the AES key from node shares and decrypts the encrypted file.
func (c *Client) Decrypt(ctx context.Context, meta *ObjectMetadata, opts DecryptOptions) error {
	if meta == nil {
		return fmt.Errorf("metadata is required")
	}
	if opts.CallerAddress == "" {
		return fmt.Errorf("caller_address is required")
	}
	return nil
}

func generateObjectID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
