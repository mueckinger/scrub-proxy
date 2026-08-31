package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// Server wraps the HTTP server for the proxy.
type Server struct {
	handler http.Handler
	port    int
	logger  *slog.Logger
}

// NewServer creates an HTTP server with the given handler.
func NewServer(handler http.Handler, port int, logger *slog.Logger) *Server {
	return &Server{handler: handler, port: port, logger: logger}
}

// ListenAndServe starts the HTTP server and blocks until ctx is cancelled or
// the listener fails. On ctx cancellation (e.g. SIGTERM) the server drains
// in-flight requests gracefully before returning.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.port < 1 || s.port > 65535 {
		return fmt.Errorf("invalid port %d", s.port)
	}
	addr := fmt.Sprintf(":%d", s.port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.handler,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
		// WriteTimeout is intentionally zero: streaming LLM responses can be
		// long-lived and must not be cut off mid-stream.
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	s.logger.Info("proxy listening", "addr", addr)

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		return nil
	}
}
