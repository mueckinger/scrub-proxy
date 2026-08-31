// Command scrub-proxy is a transparent reverse proxy for OpenAI-compatible
// LLM APIs. It scrubs secrets and PII out of requests, forwards the sanitized
// request upstream, and restores placeholders back to plaintext in responses.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"scrub-proxy/language"
	"scrub-proxy/presidio"
	proxy "scrub-proxy/proxy"
	"scrub-proxy/secrets"
)

func main() {
	cfg := LoadConfig()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLogLevel(cfg.LogLevel),
	}))

	pc := presidio.NewClient(cfg.PresidioAnalyzerURL)
	uc := proxy.NewUpstreamClient(cfg.UpstreamBaseURL, logger, cfg.UpstreamLog)

	detector, err := language.NewDetector(cfg.AnalyzerLanguages)
	if err != nil {
		logger.Error("failed to build language detector", "error", err)
		os.Exit(1)
	}

	// Build the gitleaks secret scanner. It is optional: when disabled, the
	// secret redaction stage is skipped.
	var scanner proxy.SecretScanner
	if cfg.SecretScanEnabled {
		gs, err := secrets.NewGitleaksScanner(cfg.GitleaksConfig)
		if err != nil {
			logger.Error("failed to build gitleaks scanner", "error", err)
			os.Exit(1)
		}
		scanner = gs
	}

	handler := proxy.NewProxyHandler(proxy.HandlerConfig{
		Presidio:     pc,
		Upstream:     uc,
		Logger:       logger,
		Detector:     detector,
		Scanner:      scanner,
		HTTPLog:      cfg.HTTPLog,
		MaxBodyBytes: cfg.MaxRequestBodyBytes,
	})
	server := proxy.NewServer(handler, cfg.Port, logger)

	// Shut down gracefully on SIGINT/SIGTERM so in-flight requests drain
	// instead of being cut off (e.g. on k8s pod termination).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := server.ListenAndServe(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server failed", "error", err)
		os.Exit(1)
	}
	logger.Info("server stopped")
}
