# Monitoring

## Prometheus Scrape Config

```yaml
scrape_configs:
  - job_name: soroban-encrypt-node
    static_configs:
      - targets: ['node1:8080', 'node2:8080', 'node3:8080']
    bearer_token: "${METRICS_API_KEY}"
```

## Key Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `soroban_encrypt_requests_total` | Counter | Total requests by endpoint + status |
| `soroban_encrypt_request_duration_seconds` | Histogram | Request latency |
| `soroban_encrypt_shares_in_store` | Gauge | Live share count |
| `soroban_encrypt_access_denied_total` | Counter | Denied retrieve attempts |
| `soroban_encrypt_simulation_duration_seconds` | Histogram | Soroban RPC latency |

## Alerting Rules

```yaml
groups:
  - name: soroban-encrypt
    rules:
      - alert: HighAccessDeniedRate
        expr: rate(soroban_encrypt_access_denied_total[5m]) > 1
        annotations:
          summary: "High rate of access denials — possible brute force attempt"
      - alert: SlowSorobanRPC
        expr: histogram_quantile(0.99, rate(soroban_encrypt_simulation_duration_seconds_bucket[5m])) > 5
        annotations:
          summary: "Soroban RPC p99 latency above 5s"
