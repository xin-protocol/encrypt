# sorobanencrypt Go SDK

## Install

```bash
go get github.com/teeyml/soroban-encrypt/pkg/sorobanencrypt
```

## Usage

```go
client := sorobanencrypt.NewClient(
    sorobanencrypt.WithNodes("http://node1:8080", "http://node2:8080", "http://node3:8080"),
    sorobanencrypt.WithThreshold(2),
    sorobanencrypt.WithContractID("CCONTRACT_ID"),
)

meta, err := client.Encrypt(ctx, "file.txt", sorobanencrypt.EncryptOptions{})
```

See [examples/](../../examples/) for full encrypt and decrypt usage.

## godoc

https://pkg.go.dev/github.com/teeyml/soroban-encrypt/pkg/sorobanencrypt
