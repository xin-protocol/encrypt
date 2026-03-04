## soroban-encrypt

A decentralized secrets management framework for off-chain access control on Stellar, powered by Shamir's Secret Sharing, ECIES and Soroban smart contracts. 

It allows you to encrypt files locally, split the encryption key using Shamir's Secret Sharing (SSS) and store the encrypted key shares across $N$ self-hosted nodes. When someone wants to decrypt the file, they must present a valid access token showing they are on the contract's allowlist. If they are, nodes release their key shares allowing the client to reconstruct the key and decrypt.

No global contracts, no centralized storage provider needed, you can encrypt your files and allow programmable onchain access controls without risk of key compromise

---

## How it works under the hood

1. **Encryption**: 
   - A file is encrypted locally using AES-256-GCM.
   - The symmetric key is split into $N$ shares with a threshold of $T$ (using Vault's SSS).
   - Each share is encrypted using ECIES (P-256 + AES-GCM) with the target node's static public key and dispatched to the node's `/store` endpoint.
2. **Decryption**:
   - The client constructs an unsigned Soroban transaction envelope calling the allowlist contract's `approve(object_id, caller)` method.
   - The client signs a request challenge using their Stellar Ed25519 seed.
   - The client queries at least $T$ nodes with the XDR and signature.
   - Each node simulates the transaction envelope via Soroban RPC. If the transaction executes successfully (i.e. the caller is allowed), the node decrypts and returns the key share.
   - The client combines the $T$ shares to rebuild the AES key and decrypts the file.

---

## Quick Start

### 1. Build Node & Client

```bash
# Build the self-hostable Go Node
cd node
go build -o node-bin

# Build the Go Client CLI
cd ../client
go build -o client-bin
```

### 2. Run Storage Nodes

Nodes require a connection to a Soroban RPC node (like Futurenet/Testnet) to simulate access check transactions.

```bash
# Run Node 1 on port 8080
PORT=8080 SOROBAN_RPC_URL="https://soroban-testnet.stellar.org:443" ./node-bin

# Run Node 2 on port 8081
PORT=8081 SOROBAN_RPC_URL="https://soroban-testnet.stellar.org:443" ./node-bin
```

### 3. Client Usage

#### Encrypt a local file
Encrypt a file, split the key into 3 shares (need 2 to decrypt), and store them on local nodes:
```bash
./client-bin encrypt \
  -file contract.pdf \
  -out contract.enc \
  -contract "C..." \
  -nodes "http://localhost:8080,http://localhost:8081,http://localhost:8082" \
  -n 3 \
  -t 2 \
  -meta metadata.json
```

#### Decrypt the file
Use your Stellar private key seed (starts with `S`) to authenticate yourself and fetch key shares to decrypt:
```bash
./client-bin decrypt \
  -file contract.enc \
  -meta metadata.json \
  -seed "S..." \
  -out contract_restored.pdf
```

---

## Contract Interface

Deploy your own contract implementing the simple allowlist interface. The only requirement is an entrypoint function called `approve` that panics if the caller doesn't have access.

Example contract in Rust:

```rust
#[contractimpl]
impl AllowlistContract {
    pub fn approve(env: Env, object_id: Bytes, caller: Address) {
        caller.require_auth();
        
        let has_access = env.storage().persistent().has(&caller);
        if !has_access {
            panic!("ENoAccess");
        }
    }
}
```

## Node Configuration

| Env Var | Default | Description |
|---------|---------|-------------|
| `DATA_DIR` | `./data` | Directory for BoltDB share store and node key PEM |
| `PORT` | `8080` | HTTP listen port |
| `SOROBAN_RPC_URL` | testnet | Soroban JSON-RPC endpoint |
