# Operations Guide

## Production Deployment Checklist

### Node Hardening

- [ ] Set `TLS_MODE=auto` or `TLS_MODE=manual` — never deploy with `TLS_MODE=off` on public networks
- [ ] Set a strong `STORE_API_KEY` (min 32 random characters)
- [ ] Set `METRICS_API_KEY` if exposing `/metrics` publicly
- [ ] Set `STORE_ALLOWED_IPS` to restrict /store to known client IPs
- [ ] Mount `DATA_DIR` on a persistent volume with encrypted-at-rest storage
- [ ] Enable log aggregation: pipe stdout to your SIEM
- [ ] Schedule periodic `admin rotate-key` (recommended: monthly)

### Firewall Rules

| Port | Purpose | Restrict to |
|------|---------|-------------|
| 443 | HTTPS API | Public (client nodes + browsers) |
| 80 | HTTP redirect | Public |
| 9090 | Metrics (optional) | Prometheus scraper IP |

### Key Rotation

Rotate node keys monthly or after any suspected compromise:

```bash
./client-bin admin rotate-key \
  --node https://node1.example.com \
  --api-key "$STORE_API_KEY"
```

Old key versions are retained for a grace period (default: 24h) to allow
in-flight retrieval requests to complete before the old key is purged.

### Backup

Back up `$DATA_DIR` daily. The directory contains:
- `shares.db` — BoltDB share store
- `node_key.pem` — Node P-256 private key (treat as secret)
- `audit-*.log` — Audit log files

### Monitoring

See [docs/monitoring.md](monitoring.md) for Prometheus and Grafana setup.
