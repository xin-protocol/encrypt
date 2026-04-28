package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

var nodeStartTime = time.Now()

// GET /health — liveness probe
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"uptime":  time.Since(nodeStartTime).String(),
		"started": nodeStartTime.Format(time.RFC3339),
	})
}

// GET /ready — readiness probe; 503 if BoltDB is not open
func handleReady(w http.ResponseWriter, r *http.Request) {
	if db == nil {
		http.Error(w, "not ready: database not initialised", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
}

// GET /status — node summary
func handleStatus(w http.ResponseWriter, r *http.Request) {
	count, err := countShares()
	if err != nil {
		http.Error(w, "failed to count shares: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"version":     nodeVersion,
		"public_key":  hex.EncodeToString(nodePublicKey.Bytes()),
		"share_count": count,
		"uptime":      time.Since(nodeStartTime).String(),
	})
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

	key := fmt.Sprintf("%s_%s", req.ContractID, req.ObjectID)

	// Write-once: reject duplicate unless X-Overwrite: true
	if r.Header.Get("X-Overwrite") != "true" {
		if _, exists, _ := globalStore.Load(key); exists {
			http.Error(w, "conflict: share already exists for this object (use X-Overwrite: true to replace)", http.StatusConflict)
			return
		}
	}

	share := StoredShareDB{
		EphemeralPubKey: ephemBytes,
		Ciphertext:      cipherBytes,
		Nonce:           nonceBytes,
	}
	if err := globalStore.Save(key, share); err != nil {
		logger.Error().Err(err).Str("key", key).Msg("store_failed")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	logger.Info().
		Str("object_id", req.ObjectID).
		Str("contract_id", req.ContractID).
		Str("remote", r.RemoteAddr).
		Str("outcome", "stored").
		Msg("share_stored")

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
	if req.ObjectID == "" || req.ContractID == "" || req.CallerAddress == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Object-level rate limit
	if !checkObjectRateLimit(req.ObjectID) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	// Verify signature
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
	if valid, err := VerifyStellarSignature(req.CallerAddress, msgBytes, sigBytes); err != nil || !valid {
		http.Error(w, "Invalid Stellar signature", http.StatusUnauthorized)
		return
	}

	// Verify Soroban transaction
	if err := verifySorobanTx(req.TxXDR, req.ContractID, "approve", req.CallerAddress); err != nil {
		http.Error(w, "Transaction verification failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Simulate on Soroban RPC
	rpcValid, err := simulateSorobanTx(req.TxXDR)
	if err != nil {
		http.Error(w, "Soroban simulation error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !rpcValid {
		auditLogger.Warn().
			Str("caller", req.CallerAddress).
			Str("object_id", req.ObjectID).
			Str("outcome", "denied").
			Msg("access_denied")
		http.Error(w, "Access Denied: on-chain approve() rejected", http.StatusForbidden)
		return
	}

	// Load and decrypt share
	key := fmt.Sprintf("%s_%s", req.ContractID, req.ObjectID)
	stored, exists, err := globalStore.Load(key)
	if err != nil || !exists {
		http.Error(w, "Share not found", http.StatusNotFound)
		return
	}

	decrypted, err := DecryptShare(nodePrivateKey, stored.EphemeralPubKey, stored.Ciphertext, stored.Nonce)
	if err != nil {
		http.Error(w, "Decryption failed", http.StatusInternalServerError)
		return
	}

	auditLogger.Info().
		Str("caller", req.CallerAddress).
		Str("object_id", req.ObjectID).
		Str("outcome", "granted").
		Msg("access_granted")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RetrieveResponse{
		DecryptedShare: hex.EncodeToString(decrypted),
	})
}

// logStoreOutcome writes a structured audit log entry for /store requests.
func logStoreOutcome(objectID, contractID, remoteAddr, outcome string) {
	auditLogger.Info().
		Str("object_id", objectID).
		Str("contract_id", contractID).
		Str("remote", remoteAddr).
		Str("outcome", outcome).
		Msg("store_audit")
}

// logRetrieveOutcome writes a structured audit log for /retrieve requests.
func logRetrieveOutcome(caller, objectID, contractID, outcome string) {
	auditLogger.Info().
		Str("caller_address", caller).
		Str("object_id", objectID).
		Str("contract_id", contractID).
		Str("outcome", outcome).
		Msg("retrieve_audit")
}

// fixedShareCount wraps countShares with an error log on failure.
func fixedShareCount() int {
	n, err := countShares()
	if err != nil {
		logger.Error().Err(err).Msg("share_count_failed")
		return -1
	}
	return n
}
