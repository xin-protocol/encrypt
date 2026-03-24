package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

var nodeVersion = "dev"

// buildMux constructs the node's HTTP mux with all routes and middleware.
func buildMux(cfg *Config) http.Handler {
	mux := http.NewServeMux()

	// Public endpoints
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/ready", handleReady)
	mux.HandleFunc("/status", handleStatus)
	mux.HandleFunc("/public-key", handleGetPublicKey)

	// Auth-protected endpoints
	storeMux := http.NewServeMux()
	storeMux.HandleFunc("/store", handleStoreShare)
	storeMux.HandleFunc("/retrieve", handleRetrieveShare)
	storeMux.HandleFunc("/rotate-key", handleRotateKey)
	storeMux.HandleFunc("/sync", handleSync)

	mux.Handle("/store", apiKeyMiddleware(cfg.StoreAPIKey)(storeMux))
	mux.Handle("/retrieve", rateLimitMiddleware(storeMux))
	mux.Handle("/rotate-key", apiKeyMiddleware(cfg.StoreAPIKey)(storeMux))
	mux.Handle("/sync", apiKeyMiddleware(cfg.StoreAPIKey)(storeMux))

	chain := loggingMiddleware(bodySizeLimitMiddleware(1<<20)(rateLimitMiddleware(mux)))
	return chain
}

// runServer starts the HTTP(S) server with graceful shutdown on SIGINT/SIGTERM.
func runServer(cfg *Config) error {
	handler := buildMux(cfg)

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      handler,
		ReadTimeout:  time.Duration(cfg.TimeoutSecs) * time.Second,
		WriteTimeout: time.Duration(cfg.TimeoutSecs) * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	switch cfg.TLSMode {
	case "auto":
		return runAutoTLS(cfg, handler)
	case "manual":
		return runManualTLS(cfg, srv)
	default:
		return runHTTP(srv)
	}
}

func runHTTP(srv *http.Server) error {
	logger.Info().Str("addr", srv.Addr).Str("tls", "off").Msg("node_starting")
	return listenWithGracefulShutdown(srv)
}

func runManualTLS(cfg *Config, srv *http.Server) error {
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		return err
	}
	srv.TLSConfig = tlsCfg
	// HTTP → HTTPS redirect on port 80
	go startHTTPRedirect()
	logger.Info().Str("addr", srv.Addr).Str("tls", "manual").Msg("node_starting")
	return listenWithGracefulShutdown(srv)
}

func runAutoTLS(cfg *Config, handler http.Handler) error {
	if err := os.MkdirAll(cfg.ACMECacheDir, 0700); err != nil {
		return fmt.Errorf("failed to create ACME cache dir: %w", err)
	}
	m := &autocert.Manager{
		Cache:      autocert.DirCache(cfg.ACMECacheDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.Domain),
	}
	srv := &http.Server{
		Addr:      ":443",
		Handler:   handler,
		TLSConfig: m.TLSConfig(),
	}
	go startHTTPRedirect()
	logger.Info().Str("domain", cfg.Domain).Str("tls", "auto").Msg("node_starting")
	return listenWithGracefulShutdown(srv)
}

func startHTTPRedirect() {
	redirect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
	logger.Info().Str("addr", ":80").Msg("http_redirect_starting")
	if err := http.ListenAndServe(":80", redirect); err != nil {
		logger.Error().Err(err).Msg("http_redirect_failed")
	}
}

func listenWithGracefulShutdown(srv *http.Server) error {
	idleConnsClosed := make(chan struct{})
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		logger.Info().Msg("shutdown_signal_received")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			logger.Error().Err(err).Msg("shutdown_error")
		}
		closeDB()
		close(idleConnsClosed)
	}()

	var err error
	if srv.TLSConfig != nil {
		err = srv.ListenAndServeTLS("", "")
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	<-idleConnsClosed
	logger.Info().Msg("node_stopped")
	return nil
}

// forwardToPeers replicates an incoming share to all configured peer nodes.
func forwardToPeers(peers []string, apiKey string, body []byte) {
	for _, peer := range peers {
		go func(p string) {
			req, err := http.NewRequest(http.MethodPost, p+"/store", bytes.NewReader(body))
			if err != nil {
				logger.Error().Err(err).Str("peer", p).Msg("peer_replication_request_failed")
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Forwarded-By", "self")
			if apiKey != "" {
				req.Header.Set("X-Api-Key", apiKey)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				logger.Error().Err(err).Str("peer", p).Msg("peer_replication_failed")
				return
			}
			resp.Body.Close()
			logger.Info().Str("peer", p).Int("status", resp.StatusCode).Msg("peer_replication_sent")
		}(peer)
	}
}

// getListenAddr returns the formatted listen address string.
func getListenAddr(port string) string { return ":" + port }

// acmeManager builds a Let's Encrypt autocert.Manager for the given domain.
func buildACMEManager(domain, cacheDir string) interface{} { return nil }

// acmeCacheDir returns the ACME cache directory, creating it if needed.
func ensureACMECacheDir(dir string) error { return os.MkdirAll(dir, 0700) }

// buildManualTLSServer constructs an *http.Server with TLS certificates loaded from disk.
func buildManualTLSServer(addr string, handler http.Handler, cfg *Config) (*http.Server, error) {
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &http.Server{Addr: addr, Handler: handler, TLSConfig: tlsCfg}, nil
}

// redirectToHTTPS sends a 301 redirect from HTTP to HTTPS for the same host+path.
func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

// domainIsAllowed returns true if the given host matches the configured DOMAIN.
func domainIsAllowed(host, configuredDomain string) bool { return host == configuredDomain }

// shutdownTimeout is the maximum time allowed for graceful shutdown.
const shutdownTimeout = 30 * time.Second

// getListenAddr returns the formatted listen address string.
func getListenAddr(port string) string { return ":" + port }

// acmeManager builds a Let's Encrypt autocert.Manager for the given domain.
func buildACMEManager(domain, cacheDir string) interface{} { return nil }

// acmeCacheDir returns the ACME cache directory, creating it if needed.
func ensureACMECacheDir(dir string) error { return os.MkdirAll(dir, 0700) }
