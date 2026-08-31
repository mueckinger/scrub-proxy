package presidio

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is a thin HTTP client for the presidio-analyzer service.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a presidio analyzer client. Trailing slashes are trimmed
// from the base URL so the /analyze path joins cleanly.
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Analyze sends a single text to POST /analyze and returns the detections.
// It requests the decision process (analysis_explanation) from presidio.
func (c *Client) Analyze(ctx context.Context, text, language string) ([]RecognizerResult, error) {
	req := AnalyzeRequest{
		Text:                  text,
		Language:              language,
		ReturnDecisionProcess: true,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal analyze request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/analyze", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create analyze request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("presidio analyze request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("presidio analyze returned %d: %s", resp.StatusCode, string(respBody))
	}

	var results []RecognizerResult
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, fmt.Errorf("decode presidio analyze response: %w", err)
	}
	return results, nil
}
