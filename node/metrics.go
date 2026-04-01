package main

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	requestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "soroban_encrypt_requests_total",
		Help: "Total HTTP requests by endpoint and status code.",
	}, []string{"endpoint", "status"})

	requestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "soroban_encrypt_request_duration_seconds",
		Help:    "HTTP request latency by endpoint.",
		Buckets: prometheus.DefBuckets,
	}, []string{"endpoint"})

	sharesStored = promauto.NewCounter(prometheus.CounterOpts{
		Name: "soroban_encrypt_shares_stored_total",
		Help: "Cumulative shares written to this node.",
	})

	sharesInStore = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "soroban_encrypt_shares_in_store",
		Help: "Current number of shares in the BoltDB store.",
	})

	simulationDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "soroban_encrypt_simulation_duration_seconds",
		Help:    "Soroban RPC simulateTransaction round-trip latency.",
		Buckets: prometheus.DefBuckets,
	})

	accessGranted = promauto.NewCounter(prometheus.CounterOpts{
		Name: "soroban_encrypt_access_granted_total",
		Help: "Total successful /retrieve access grants.",
	})

	accessDenied = promauto.NewCounter(prometheus.CounterOpts{
		Name: "soroban_encrypt_access_denied_total",
		Help: "Total denied /retrieve access attempts.",
	})
)

// metricsHandler returns the Prometheus /metrics endpoint, optionally protected by API key.
func metricsHandler(apiKey string) http.Handler {
	h := promhttp.Handler()
	if apiKey == "" {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !secureStringEqual(r.Header.Get("X-Api-Key"), apiKey) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// prometheusMiddleware wraps a handler to record request metrics.
func prometheusMiddleware(endpoint string) func(http.Handler) http.Handler {
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
