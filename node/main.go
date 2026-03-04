package main

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// StoredShare holds the ECIES-encrypted secret share
type StoredShare struct {
	EphemeralPubKey []byte
	Ciphertext      []byte
	Nonce           []byte
}

type StoreRequest struct {
	ObjectID        string `json:"object_id"`
	ContractID      string `json:"contract_id"`
	EphemeralPubKey string `json:"ephemeral_pubkey"`
	Ciphertext      string `json:"ciphertext"`
	Nonce           string `json:"nonce"`
}

type RetrieveRequest struct {
	ObjectID      string `json:"object_id"`
	ContractID    string `json:"contract_id"`
	CallerAddress string `json:"caller_address"`
	Signature     string `json:"signature"`
	Message       string `json:"message"`
	TxXDR         string `json:"tx_xdr"`
}

type RetrieveResponse struct {
	DecryptedShare string `json:"decrypted_share"`
}

type JSONRPCRequest struct {
	JsonRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

type SimulateResponse struct {
	Result struct {
		Error   string `json:"error,omitempty"`
		Results []struct {
			Error string `json:"error,omitempty"`
			XDR   string `json:"xdr,omitempty"`
		} `json:"results,omitempty"`
	} `json:"result"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

var (
	// In-memory registry of stored shares (bare-bones implementation)
	sharesMu sync.RWMutex
	sharesMap = make(map[string]StoredShare) // key: contractID_objectID

	// Node P-256 ECIES Key Pair
	nodePrivateKey *ecdh.PrivateKey
	nodePublicKey  *ecdh.PublicKey

	// Configurable Soroban RPC URL
	sorobanRPCURL = "https://soroban-testnet.stellar.org:443"
)

func init() {
	if envRPC := os.Getenv("SOROBAN_RPC_URL"); envRPC != "" {
		sorobanRPCURL = envRPC
	}

	// Load or generate node key pair — persists across restarts
	dir := os.Getenv("DATA_DIR"); if dir == "" { dir = dataDir }; priv, err := LoadOrGenerateKey(dir)
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize Node P-256 key pair: %v", err))
	}
	nodePrivateKey = priv
	nodePublicKey = priv.PublicKey()
}

func main() {
	fmt.Printf("Soroban-Encrypt Go Node public key: %s\n", hex.EncodeToString(nodePublicKey.Bytes()))

	http.HandleFunc("/public-key", handleGetPublicKey)
	http.HandleFunc("/store", handleStoreShare)
	http.HandleFunc("/retrieve", handleRetrieveShare)

	port := "8080"
	if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}
	fmt.Printf("Node listening on :%s...\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Printf("HTTP Server failed: %v\n", err)
	}
}

// GET /public-key
func handleGetPublicKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"public_key": hex.EncodeToString(nodePublicKey.Bytes()),
	})
}

// POST /store
func handleStoreShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req StoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	if req.ObjectID == "" || req.ContractID == "" || req.EphemeralPubKey == "" || req.Ciphertext == "" || req.Nonce == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	ephemBytes, err := hex.DecodeString(req.EphemeralPubKey)
	if err != nil {
		http.Error(w, "Invalid ephemeral public key hex", http.StatusBadRequest)
		return
	}

	cipherBytes, err := hex.DecodeString(req.Ciphertext)
	if err != nil {
		http.Error(w, "Invalid ciphertext hex", http.StatusBadRequest)
		return
	}

	nonceBytes, err := hex.DecodeString(req.Nonce)
	if err != nil {
		http.Error(w, "Invalid nonce hex", http.StatusBadRequest)
		return
	}

	// Store key share in memory
	key := fmt.Sprintf("%s_%s", req.ContractID, req.ObjectID)
	sharesMu.Lock()
	sharesMap[key] = StoredShare{
		EphemeralPubKey: ephemBytes,
		Ciphertext:      cipherBytes,
		Nonce:           nonceBytes,
	}
	sharesMu.Unlock()

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "stored"})
}

// POST /retrieve
func handleRetrieveShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RetrieveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	if req.ObjectID == "" || req.ContractID == "" || req.CallerAddress == "" || req.Signature == "" || req.Message == "" || req.TxXDR == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// 1. Verify Client Ed25519 Signature
	msgBytes, err := hex.DecodeString(req.Message)
	if err != nil {
		http.Error(w, "Invalid message hex", http.StatusBadRequest)
		return
	}

	sigBytes, err := hex.DecodeString(req.Signature)
	if err != nil {
		http.Error(w, "Invalid signature hex", http.StatusBadRequest)
		return
	}

	sigValid, err := VerifyStellarSignature(req.CallerAddress, msgBytes, sigBytes)
	if err != nil || !sigValid {
		http.Error(w, "Invalid Stellar signature", http.StatusUnauthorized)
		return
	}

	// 2. Decode & Inspect the Transaction XDR
	if err := verifySorobanTx(req.TxXDR, req.ContractID, "approve", req.CallerAddress); err != nil {
		http.Error(w, fmt.Sprintf("Transaction verification failed: %v", err), http.StatusBadRequest)
		return
	}

	// 3. Simulate Transaction on Soroban RPC
	rpcValid, err := simulateSorobanTx(req.TxXDR)
	if err != nil {
		http.Error(w, fmt.Sprintf("Soroban simulation communication error: %v", err), http.StatusInternalServerError)
		return
	}
	if !rpcValid {
		http.Error(w, "Access Denied: Soroban simulation rejected the authorization request (approve failed)", http.StatusForbidden)
		return
	}

	// 4. Retrieve & Decrypt Share
	key := fmt.Sprintf("%s_%s", req.ContractID, req.ObjectID)
	sharesMu.RLock()
	stored, exists := sharesMap[key]
	sharesMu.RUnlock()

	if !exists {
		http.Error(w, "Key share not found", http.StatusNotFound)
		return
	}

	decryptedShare, err := DecryptShare(nodePrivateKey, stored.EphemeralPubKey, stored.Ciphertext, stored.Nonce)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to decrypt share: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RetrieveResponse{
		DecryptedShare: hex.EncodeToString(decryptedShare),
	})
}

// verifySorobanTx parses base64 transaction XDR and ensures it represents a call to contractID:approve for sourceAccount
func verifySorobanTx(txXdr string, contractID string, expectedFunc string, sourceAccount string) error {
	var env xdr.TransactionEnvelope
	err := xdr.SafeUnmarshalBase64(txXdr, &env)
	if err != nil {
		return fmt.Errorf("failed to unmarshal transaction XDR: %v", err)
	}

	sourceMuxed, operations, err := getTxSourceAndOps(env)
	if err != nil {
		return fmt.Errorf("failed to extract transaction details: %v", err)
	}

	// Verify source account matches the expected caller
	sourceAddr, err := sourceMuxed.GetAddress()
	if err != nil {
		return fmt.Errorf("failed to get source address: %v", err)
	}
	if sourceAddr != sourceAccount {
		return fmt.Errorf("transaction source account %s does not match expected caller %s", sourceAddr, sourceAccount)
	}

	if len(operations) != 1 {
		return fmt.Errorf("transaction must contain exactly one operation")
	}

	op := operations[0]
	sorobanOp, ok := op.Body.GetInvokeHostFunctionOp()
	if !ok {
		return fmt.Errorf("operation is not a Soroban InvokeHostFunction operation")
	}

	fn := sorobanOp.HostFunction
	if fn.Type != xdr.HostFunctionTypeHostFunctionTypeInvokeContract {
		return fmt.Errorf("host function is not an InvokeContract type")
	}

	invokeArgs := fn.InvokeContract
	if invokeArgs == nil {
		return fmt.Errorf("invoke contract arguments are nil")
	}

	// Verify Contract Address
	var contractAddr string
	switch invokeArgs.ContractAddress.Type {
	case xdr.ScAddressTypeScAddressTypeContract:
		if invokeArgs.ContractAddress.ContractId == nil {
			return fmt.Errorf("contract ID is nil")
		}
		cId := *invokeArgs.ContractAddress.ContractId
		var err error
		contractAddr, err = strkey.Encode(strkey.VersionByteContract, cId[:])
		if err != nil {
			return fmt.Errorf("failed to encode contract address: %v", err)
		}
	case xdr.ScAddressTypeScAddressTypeAccount:
		if invokeArgs.ContractAddress.AccountId == nil {
			return fmt.Errorf("account ID is nil")
		}
		accId := *invokeArgs.ContractAddress.AccountId
		var err error
		contractAddr, err = accId.GetAddress()
		if err != nil {
			return fmt.Errorf("failed to get account address: %v", err)
		}
	default:
		return fmt.Errorf("unknown ScAddress type: %v", invokeArgs.ContractAddress.Type)
	}

	if contractAddr != contractID {
		return fmt.Errorf("contract address %s does not match expected contract %s", contractAddr, contractID)
	}

	// Verify Function Name
	if string(invokeArgs.FunctionName) != expectedFunc {
		return fmt.Errorf("function %s does not match expected function %s", string(invokeArgs.FunctionName), expectedFunc)
	}

	return nil
}

func getTxSourceAndOps(env xdr.TransactionEnvelope) (xdr.MuxedAccount, []xdr.Operation, error) {
	switch env.Type {
	case xdr.EnvelopeTypeEnvelopeTypeTx:
		if env.V1 == nil {
			return xdr.MuxedAccount{}, nil, fmt.Errorf("V1 envelope is nil")
		}
		return env.V1.Tx.SourceAccount, env.V1.Tx.Operations, nil
	default:
		return xdr.MuxedAccount{}, nil, fmt.Errorf("unsupported transaction envelope type (only V1 Tx is supported for Soroban): %v", env.Type)
	}
}

// simulateSorobanTx sends the Transaction XDR to the Soroban RPC simulateTransaction endpoint
func simulateSorobanTx(txXdr string) (bool, error) {
	rpcReq := JSONRPCRequest{
		JsonRPC: "2.0",
		ID:      1,
		Method:  "simulateTransaction",
		Params: map[string]string{
			"transaction": txXdr,
		},
	}

	reqBody, err := json.Marshal(rpcReq)
	if err != nil {
		return false, err
	}

	resp, err := http.Post(sorobanRPCURL, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return false, fmt.Errorf("Soroban RPC call failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	var rpcResp SimulateResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return false, fmt.Errorf("failed to parse RPC response: %w", err)
	}

	// If there is a JSON-RPC level error
	if rpcResp.Error != nil {
		return false, fmt.Errorf("Soroban RPC returned error: %s (code %d)", rpcResp.Error.Message, rpcResp.Error.Code)
	}

	// If the simulation failed at execution level
	if rpcResp.Result.Error != "" {
		return false, nil // Invalidation (fail)
	}

	// Inspect operation result failures
	if len(rpcResp.Result.Results) > 0 {
		for _, res := range rpcResp.Result.Results {
			if res.Error != "" {
				return false, nil // Invalidation (fail)
			}
		}
	} else {
		// No results means it didn't even run
		return false, fmt.Errorf("simulation returned no results")
	}

	return true, nil
}
