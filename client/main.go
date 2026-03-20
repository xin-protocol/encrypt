package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/hashicorp/vault/shamir"
)

type Metadata struct {
	ObjectID   string   `json:"object_id"`
	ContractID string   `json:"contract_id"`
	Threshold  int      `json:"threshold"`
	Nodes      []string `json:"nodes"`
}

type NodeKeyResponse struct {
	PublicKey string `json:"public_key"`
}

type NodeStoreRequest struct {
	ObjectID        string `json:"object_id"`
	ContractID      string `json:"contract_id"`
	EphemeralPubKey string `json:"ephemeral_pubkey"`
	Ciphertext      string `json:"ciphertext"`
	Nonce           string `json:"nonce"`
}

type NodeRetrieveRequest struct {
	ObjectID      string `json:"object_id"`
	ContractID    string `json:"contract_id"`
	CallerAddress string `json:"caller_address"`
	Signature     string `json:"signature"`
	Message       string `json:"message"`
	TxXDR         string `json:"tx_xdr"`
}

type NodeRetrieveResponse struct {
	DecryptedShare string `json:"decrypted_share"`
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	switch command {
	case "encrypt":
		handleEncrypt(os.Args[2:])
	case "decrypt":
		handleDecrypt(os.Args[2:])
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  client encrypt -file <path> -out <path> -contract <id> -nodes <urls> -n <shares> -t <threshold> -meta <path>")
	fmt.Println("  client decrypt -file <path> -meta <path> -seed <stellar-seed> -out <path>")
}

func handleEncrypt(args []string) {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	filePath := fs.String("file", "", "Path to the local file to encrypt")
	outPath := fs.String("out", "", "Path to save the encrypted ciphertext file")
	contractID := fs.String("contract", "", "Soroban contract ID managing access")
	nodesList := fs.String("nodes", "", "Comma-separated list of Go node URL endpoints")
	nShares := fs.Int("n", 3, "Total number of shares to split key into")
	tThreshold := fs.Int("t", 2, "Threshold of shares required to decrypt")
	metaPath := fs.String("meta", "metadata.json", "Path to output metadata JSON file")

	fs.Parse(args)

	if *filePath == "" || *outPath == "" || *contractID == "" || *nodesList == "" {
		fs.Usage()
		os.Exit(1)
	}

	nodes := strings.Split(*nodesList, ",")
	if len(nodes) < *nShares {
		fmt.Printf("Error: Number of node endpoints (%d) must be at least the total shares n (%d)\n", len(nodes), *nShares)
		os.Exit(1)
	}

	// 1. Read Raw File
	fileData, err := os.ReadFile(*filePath)
	if err != nil {
		fmt.Printf("Failed to read file %s: %v\n", *filePath, err)
		os.Exit(1)
	}

	// 2. Generate Symmetric Key (AES-256)
	sk, err := GenerateAESKey()
	if err != nil {
		fmt.Printf("Failed to generate AES key: %v\n", err)
		os.Exit(1)
	}

	// 3. Encrypt File locally using SK
	ciphertext, aesNonce, err := SymmetricEncrypt(sk, fileData)
	if err != nil {
		fmt.Printf("Symmetric encryption failed: %v\n", err)
		os.Exit(1)
	}

	// Save encrypted ciphertext prefixed with the AES GCM nonce for local retrieval
	// Nonce is prepended to ciphertext so it stays bundled together in the .enc file
	finalPayload := append(aesNonce, ciphertext...)
	if err := os.WriteFile(*outPath, finalPayload, 0644); err != nil {
		fmt.Printf("Failed to write ciphertext to %s: %v\n", *outPath, err)
		os.Exit(1)
	}

	// 4. Generate Object ID (SHA256 of the ciphertext)
	objHash := sha256.Sum256(ciphertext)
	objectID := hex.EncodeToString(objHash[:])

	// 5. Split Symmetric Key using Shamir's Secret Sharing
	shares, err := shamir.Split(sk, *nShares, *tThreshold)
	if err != nil {
		fmt.Printf("Failed to split key via Shamir's Secret Sharing: %v\n", err)
		os.Exit(1)
	}

	// 6. Encrypt & Distribute Shares to selected nodes
	fmt.Printf("Distributing key shares for Object ID %s across %d nodes...\n", objectID, *nShares)
	for i := 0; i < *nShares; i++ {
		nodeURL := strings.TrimSpace(nodes[i])
		fmt.Printf("  Sending share %d to node: %s\n", i+1, nodeURL)

		// A. Fetch node public key
		nodePubHex, err := fetchNodePublicKey(nodeURL)
		if err != nil {
			fmt.Printf("  [Error] Failed to fetch public key from %s: %v\n", nodeURL, err)
			os.Exit(1)
		}
		nodePubBytes, err := hex.DecodeString(nodePubHex)
		if err != nil {
			fmt.Printf("  [Error] Invalid node public key from %s: %v\n", nodeURL, err)
			os.Exit(1)
		}

		// B. ECIES encrypt the share
		ephemPub, shareCiphertext, shareNonce, err := ECIESEncrypt(nodePubBytes, shares[i])
		if err != nil {
			fmt.Printf("  [Error] ECIES encryption failed for node %s: %v\n", nodeURL, err)
			os.Exit(1)
		}

		// C. Send to node
		err = storeShareOnNode(nodeURL, *contractID, objectID, ephemPub, shareCiphertext, shareNonce)
		if err != nil {
			fmt.Printf("  [Error] Failed to store share on node %s: %v\n", nodeURL, err)
			os.Exit(1)
		}
	}

	// 7. Save Metadata JSON file
	meta := Metadata{
		ObjectID:   objectID,
		ContractID: *contractID,
		Threshold:  *tThreshold,
		Nodes:      nodes[:*nShares], // Keep only the nodes that hold shares
	}

	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		fmt.Printf("Failed to marshal metadata: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*metaPath, metaBytes, 0644); err != nil {
		fmt.Printf("Failed to write metadata JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nSUCCESS! File encrypted and shares distributed.\n")
	fmt.Printf("Encrypted file saved to: %s\n", *outPath)
	fmt.Printf("Metadata JSON saved to:   %s\n", *metaPath)
}

func handleDecrypt(args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	filePath := fs.String("file", "", "Path to the encrypted ciphertext file")
	metaPath := fs.String("meta", "metadata.json", "Path to metadata JSON file")
	stellarSeed := fs.String("seed", "", "Accessor's Stellar private seed (starts with S)")
	outPath := fs.String("out", "", "Path to save the decrypted plaintext output")

	fs.Parse(args)

	if *filePath == "" || *metaPath == "" || *stellarSeed == "" || *outPath == "" {
		fs.Usage()
		os.Exit(1)
	}

	// 1. Read Encrypted File
	encryptedData, err := os.ReadFile(*filePath)
	if err != nil {
		fmt.Printf("Failed to read encrypted file %s: %v\n", *filePath, err)
		os.Exit(1)
	}

	// Extract AES nonce and actual ciphertext
	// Go AES-GCM nonce size is 12 bytes
	if len(encryptedData) < 12 {
		fmt.Println("Error: Encrypted file is corrupted (too small to contain nonce)")
		os.Exit(1)
	}
	aesNonce := encryptedData[:12]
	ciphertext := encryptedData[12:]

	// 2. Parse Metadata
	metaBytes, err := os.ReadFile(*metaPath)
	if err != nil {
		fmt.Printf("Failed to read metadata JSON: %v\n", err)
		os.Exit(1)
	}

	var meta Metadata
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		fmt.Printf("Failed to parse metadata JSON: %v\n", err)
		os.Exit(1)
	}

	// 3. Derive Accessor Address
	callerAddress, err := GetAddressFromSeed(*stellarSeed)
	if err != nil {
		fmt.Printf("Invalid Stellar seed: %v\n", err)
		os.Exit(1)
	}

	// 4. Construct Soroban simulation Transaction XDR
	fmt.Printf("Building Soroban transaction dry-run calling approve()...\n")
	txXDR, err := BuildApproveTransaction(meta.ContractID, meta.ObjectID, callerAddress)
	if err != nil {
		fmt.Printf("Failed to build Soroban XDR: %v\n", err)
		os.Exit(1)
	}

	// 5. Sign the Request payload
	// The message signed is: object_id + "_" + contract_id
	msgStr := fmt.Sprintf("%s_%s", meta.ObjectID, meta.ContractID)
	msgBytes := []byte(msgStr)

	signature, err := SignPayload(*stellarSeed, msgBytes)
	if err != nil {
		fmt.Printf("Failed to sign request payload: %v\n", err)
		os.Exit(1)
	}

	// 6. Retrieve shares from at least `t` nodes
	var collectedShares [][]byte
	sharesNeeded := meta.Threshold
	nodesContacted := 0

	fmt.Printf("Retrieving secret shares from key nodes (needs %d shares)...\n", sharesNeeded)
	for _, nodeURL := range meta.Nodes {
		if len(collectedShares) >= sharesNeeded {
			break
		}
		nodeURL = strings.TrimSpace(nodeURL)
		fmt.Printf("  Requesting share from node: %s\n", nodeURL)

		shareHex, err := retrieveShareFromNode(nodeURL, meta.ObjectID, meta.ContractID, callerAddress, signature, msgBytes, txXDR)
		if err != nil {
			fmt.Printf("  [Warning] Failed to retrieve share from %s: %v\n", nodeURL, err)
			continue
		}

		shareBytes, err := hex.DecodeString(shareHex)
		if err != nil {
			fmt.Printf("  [Warning] Node %s returned invalid hex share: %v\n", nodeURL, err)
			continue
		}

		collectedShares = append(collectedShares, shareBytes)
		nodesContacted++
	}

	if len(collectedShares) < sharesNeeded {
		fmt.Printf("\nERROR: Failed to retrieve sufficient key shares. Collected %d/%d shares.\n", len(collectedShares), sharesNeeded)
		fmt.Println("Ensure you are on the on-chain allowlist and that nodes are reachable.")
		os.Exit(1)
	}

	// 7. Reconstruct Symmetric Key (SK) using Shamir's Combine
	fmt.Println("Reconstructing Symmetric Key from key shares...")
	sk, err := shamir.Combine(collectedShares)
	if err != nil {
		fmt.Printf("Symmetric key reconstruction failed: %v\n", err)
		os.Exit(1)
	}

	// 8. Decrypt local ciphertext with reconstructed SK
	fmt.Println("Decrypting ciphertext file...")
	decryptedBytes, err := SymmetricDecrypt(sk, ciphertext, aesNonce)
	if err != nil {
		fmt.Printf("Decryption failed (corrupted ciphertext or incorrect key reconstructed): %v\n", err)
		os.Exit(1)
	}

	// 9. Write plaintext output
	if err := os.WriteFile(*outPath, decryptedBytes, 0644); err != nil {
		fmt.Printf("Failed to write decrypted file to %s: %v\n", *outPath, err)
		os.Exit(1)
	}

	fmt.Printf("\nSUCCESS! File decrypted successfully.\n")
	fmt.Printf("Decrypted plaintext saved to: %s\n", *outPath)
}

// HTTP Helpers

func fetchNodePublicKey(nodeURL string) (string, error) {
	resp, err := http.Get(nodeURL + "/public-key")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("node returned status %s", resp.Status)
	}

	var kr NodeKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&kr); err != nil {
		return "", err
	}

	return kr.PublicKey, nil
}

func storeShareOnNode(nodeURL, contractID, objectID string, ephemPub, ciphertext, nonce []byte) error {
	reqBody := NodeStoreRequest{
		ObjectID:        objectID,
		ContractID:      contractID,
		EphemeralPubKey: hex.EncodeToString(ephemPub),
		Ciphertext:      hex.EncodeToString(ciphertext),
		Nonce:           hex.EncodeToString(nonce),
	}

	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	resp, err := http.Post(nodeURL+"/store", "application/json", bytes.NewBuffer(reqBytes))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("node returned error status %s: %s", resp.Status, string(body))
	}

	return nil
}

func retrieveShareFromNode(nodeURL, objectID, contractID, callerAddr string, signature, message []byte, txXDR string) (string, error) {
	reqBody := NodeRetrieveRequest{
		ObjectID:      objectID,
		ContractID:    contractID,
		CallerAddress: callerAddr,
		Signature:     hex.EncodeToString(signature),
		Message:       hex.EncodeToString(message),
		TxXDR:         txXDR,
	}

	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	resp, err := http.Post(nodeURL+"/retrieve", "application/json", bytes.NewBuffer(reqBytes))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("node returned error status %s: %s", resp.Status, string(body))
	}

	var rr NodeRetrieveResponse
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		return "", err
	}

	return rr.DecryptedShare, nil
}

// nodeAPIKey holds the --node-api-key flag value sent as X-Api-Key on /store.
var nodeAPIKey string
