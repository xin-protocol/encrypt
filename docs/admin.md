# Admin CLI Reference

## Commands

### `admin deploy`
Compiles the contract WASM and uploads it to the Soroban network.

```bash
./client-bin admin deploy --wasm contract.wasm --secret SXXX
```

### `admin init`
Initialises the deployed contract with an admin keypair.

```bash
./client-bin admin init --contract CXXX --admin GXXX --secret SXXX
```

### `admin add`
Adds an address to the on-chain allowlist.

```bash
./client-bin admin add --contract CXXX --address GXXX --secret SXXX
```

### `admin remove`
Removes an address from the on-chain allowlist.

```bash
./client-bin admin remove --contract CXXX --address GXXX --secret SXXX
```

### `admin info`
Displays contract metadata.

```bash
./client-bin admin info --contract CXXX --rpc https://soroban-testnet.stellar.org
```

### `admin rotate-key`
Triggers key rotation on a node.

```bash
./client-bin admin rotate-key --node http://node1:8080 --api-key KEY
```

### `admin purge-shares`
Removes shares for an object from all nodes.

```bash
./client-bin admin purge-shares --object OBJ_ID --contract CXXX --nodes http://n1,http://n2 --api-key KEY
```
