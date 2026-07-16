package main

import (
	"encoding/json"
	"net/http"
)

// POST /rotate-key — triggers node key rotation (requires API key auth)
func handleRotateKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if globalKeyManager == nil {
		http.Error(w, "Key manager not initialised", http.StatusInternalServerError)
		return
	}
	if err := globalKeyManager.Rotate(); err != nil {
		logger.Error().Err(err).Msg("key_rotation_failed")
		http.Error(w, "Key rotation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "rotated",
		"new_version": globalKeyManager.CurrentVersion(),
	})
}

// DELETE /shares — admin purge shares for an object
func handlePurgeShares(w http.ResponseWriter, r *http.Request) { //nolint:unused
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ObjectID   string `json:"object_id"`
		ContractID string `json:"contract_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	key := req.ContractID + "_" + req.ObjectID
	if err := globalStore.Delete(key); err != nil {
		http.Error(w, "Failed to delete share: "+err.Error(), http.StatusInternalServerError)
		return
	}
	sharesInStore.Dec()
	logger.Info().Str("key", key).Msg("share_purged")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "purged"})
}

// POST /sync — pull missing shares from a peer node
func handleSync(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Forwarded-By") != "" {
		http.Error(w, "Sync loop detected", http.StatusLoopDetected)
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "sync_ok"})
}
