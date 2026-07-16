package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	serverUptime = promauto.NewCounter(prometheus.CounterOpts{
		Name: "soroban_encrypt_server_uptime_seconds_total",
		Help: "Uptime of the server in seconds.",
	})

//nolint:unused
	requestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{ //nolint:unused
		Name: "soroban_encrypt_requests_total",
		Help: "Total HTTP requests by endpoint and status code.",
	}, []string{"endpoint", "status"})

//nolint:unused
	requestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{ //nolint:unused
		Name:    "soroban_encrypt_request_duration_seconds",
		Help:    "HTTP request latency by endpoint.",
		Buckets: prometheus.DefBuckets,
	}, []string{"endpoint"})

//nolint:unused
	sharesStored = promauto.NewCounter(prometheus.CounterOpts{ //nolint:unused
		Name: "soroban_encrypt_shares_stored_total",
		Help: "Cumulative shares written to this node.",
	})

//nolint:unused
	sharesInStore = promauto.NewGauge(prometheus.GaugeOpts{ //nolint:unused
		Name: "soroban_encrypt_shares_in_store",
		Help: "Current number of shares in the BoltDB store.",
	})

//nolint:unused
	simulationDuration = promauto.NewHistogram(prometheus.HistogramOpts{ //nolint:unused
		Name:    "soroban_encrypt_simulation_duration_seconds",
		Help:    "Soroban RPC simulateTransaction round-trip latency.",
		Buckets: prometheus.DefBuckets,
	})

//nolint:unused
	accessGranted = promauto.NewCounter(prometheus.CounterOpts{ //nolint:unused
		Name: "soroban_encrypt_access_granted_total",
		Help: "Total successful /retrieve access grants.",
	})

//nolint:unused
	accessDenied = promauto.NewCounter(prometheus.CounterOpts{ //nolint:unused
		Name: "soroban_encrypt_access_denied_total",
		Help: "Total denied /retrieve access attempts.",
	})
)

// metricsHandler returns the Prometheus /metrics endpoint, optionally protected by API key.
//nolint:unused
func metricsHandler(apiKey string) http.Handler { //nolint:unused
	h := promhttp.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if apiKey != "" && !secureStringEqual(r.Header.Get("X-Api-Key"), apiKey) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// StartUptimeTicker starts background ticks to increment the uptime counter.
func StartUptimeTicker() {
	go func() {
		ticker := time.NewTicker(time.Second)
		for range ticker.C {
			serverUptime.Inc()
		}
	}()
}

// prometheusMiddleware wraps a handler to record request metrics.
//nolint:unused
func prometheusMiddleware(endpoint string) func(http.Handler) http.Handler { //nolint:unused
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			timer := prometheus.NewTimer(requestDuration.WithLabelValues(endpoint))
			defer timer.ObserveDuration()
			sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
			next.ServeHTTP(sw, r)
			requestsTotal.WithLabelValues(endpoint, fmt.Sprintf("%d", sw.code)).Inc()
		})
	}
}

// observeSimulationDuration records the duration of a Soroban RPC simulation call.
//nolint:unused
func observeSimulationDuration(d float64) { simulationDuration.Observe(d) } //nolint:unused

// updateSharesInStore refreshes the shares_in_store gauge from the BoltDB count.
//nolint:unused
func updateSharesInStore() { //nolint:unused
	if n, err := countShares(); err == nil {
		sharesInStore.Set(float64(n))
	}
}

// observeSimulationRPC records a completed simulation round-trip.
//nolint:unused
func observeSimulationRPC(durationSecs float64) { //nolint:unused
	simulationDuration.Observe(durationSecs)
}

// recordAccessDecision increments either the granted or denied counter.
//nolint:unused
func recordAccessDecision(granted bool) { //nolint:unused
	if granted {
		accessGranted.Inc()
	} else {
		accessDenied.Inc()
	}
}

// requireMetricsKey is a middleware that enforces the METRICS_API_KEY.
//nolint:unused
func requireMetricsKey(key string, next http.Handler) http.Handler { //nolint:unused
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if key != "" && !secureStringEqual(r.Header.Get("X-Api-Key"), key) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
