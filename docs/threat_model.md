# Threat Model

## Assets

- **Plaintext files**: Must remain confidential. Encrypted at rest with AES-256-GCM.
- **AES symmetric key**: Sharded via Shamir. No single node holds the full key.
- **Node private keys**: P-256 ECIES keys persist in `$DATA_DIR/node_key.pem`. Must be protected.

## Attacker Scenarios

### Node Compromise
An attacker who controls fewer than `threshold` nodes cannot reconstruct the AES key.
Mitigations: restrict `STORE_API_KEY`, enable TLS, rotate keys periodically.

### Transport Attack (MITM)
TLS 1.3 with HSTS prevents interception of share traffic in transit.
HTTP-only deployments (`TLS_MODE=off`) are vulnerable to MITM — not recommended for production.

### Share Replay
AEAD additional data (`contractID|objectID`) prevents a share from being replayed for a different object.

### Soroban RPC Manipulation
Access control relies on honest Soroban RPC nodes. Use a trusted private RPC endpoint for production.

### Brute Force / Enumeration
Per-IP and per-object rate limiting (429 responses) throttles enumeration attempts.
