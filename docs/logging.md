# Logging & Audit Log

## Structured Log Fields

The node emits JSON logs on stdout via zerolog.

| Field | Description |
|-------|-------------|
| `time` | RFC3339Nano timestamp |
| `level` | debug / info / warn / error |
| `service` | `soroban-encrypt-node` |
| `method` | HTTP method |
| `path` | Endpoint path |
| `remote_addr` | Caller IP:port |
| `status` | HTTP response code |
| `duration_us` | Latency in microseconds |
| `object_id` | Share object identifier |
| `caller_address` | Stellar address on /retrieve |
| `outcome` | granted / denied / error |

## Audit Log

Written to `$DATA_DIR/audit-YYYY-MM-DD.log` (append-only).
Sensitive key material is masked with `****`.

## Log Level

`LOG_LEVEL=debug|info|warn|error` (default: `info`)

## 12-Factor Config

Every `node.yaml` field has a matching `UPPER_SNAKE_CASE` env var that takes precedence.
