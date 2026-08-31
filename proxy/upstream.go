package proxy

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

// UpstreamClient forwards requests to the upstream LLM API.
type UpstreamClient struct {
	baseURL     string
	httpClient  *http.Client
	logger      *slog.Logger
	upstreamLog bool
}

// NewUpstreamClient creates an upstream client. Trailing slashes are trimmed
// from the base URL so forwarded paths join cleanly.
func NewUpstreamClient(baseURL string, logger *slog.Logger, upstreamLog bool) *UpstreamClient {
	return &UpstreamClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: 0, // no timeout — streaming responses can be long-lived
		},
		logger:      logger,
		upstreamLog: upstreamLog,
	}
}

// Forward sends the request body to the upstream path using the given HTTP
// method, passing through the client's Authorization header. It returns the
// upstream response (which the caller must close).
//
// logBody controls whether the request body is written to the log when
// UPSTREAM_LOG is enabled. It should only be true for bodies that went
// through the anonymization pipeline; passthrough bodies bypass it and may
// contain sensitive data, so they are never logged.
func (c *UpstreamClient) Forward(ctx context.Context, method, pathWithQuery string, body []byte, authHeader string, logBody bool) (*http.Response, error) {
	url := c.baseURL + pathWithQuery
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create upstream request: %w", err)
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	if c.upstreamLog {
		fields := []any{"method", method, "url", url}
		if logBody {
			fields = append(fields, "body", string(body))
		}
		c.logger.Info("upstream_request", fields...)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upstream request: %w", err)
	}

	if c.upstreamLog {
		c.logger.Info("upstream_response",
			"url", url,
			"status", resp.StatusCode,
		)
	}
	return resp, nil
}
