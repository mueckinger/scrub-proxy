package proxy

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"path"
	"strconv"
	"strings"

	"scrub-proxy/anonymize"
	"scrub-proxy/language"
	"scrub-proxy/presidio"
	"scrub-proxy/restore"
	"scrub-proxy/secrets"
)

// healthPath is served locally for liveness probes and never forwarded.
const healthPath = "/healthz"

// SecretScanner scans text for secrets. It is satisfied by
// *secrets.GitleaksScanner and can be mocked in tests.
type SecretScanner interface {
	Scan(text string) []secrets.Finding
}

// HandlerConfig holds the dependencies and options for ProxyHandler.
type HandlerConfig struct {
	// Presidio detects PII spans in text.
	Presidio *presidio.Client
	// Upstream forwards requests to the LLM API.
	Upstream *UpstreamClient
	// Logger receives structured logs.
	Logger *slog.Logger
	// Detector picks the language of each text before analysis.
	Detector *language.Detector
	// Scanner redacts secrets one-way. Optional: when nil, the secret
	// redaction stage is skipped.
	Scanner SecretScanner
	// HTTPLog enables logging of incoming HTTP traffic.
	HTTPLog bool
	// MaxBodyBytes caps the size of buffered request bodies. Zero or
	// negative disables the limit (not recommended).
	MaxBodyBytes int64
}

// ProxyHandler is the main HTTP handler for the scrub proxy.
type ProxyHandler struct {
	presidio     *presidio.Client
	upstream     *UpstreamClient
	logger       *slog.Logger
	detector     *language.Detector
	scanner      SecretScanner
	httpLog      bool
	maxBodyBytes int64
}

// NewProxyHandler creates the proxy handler from its configuration.
func NewProxyHandler(cfg HandlerConfig) *ProxyHandler {
	return &ProxyHandler{
		presidio:     cfg.Presidio,
		upstream:     cfg.Upstream,
		logger:       cfg.Logger,
		detector:     cfg.Detector,
		scanner:      cfg.Scanner,
		httpLog:      cfg.HTTPLog,
		maxBodyBytes: cfg.MaxBodyBytes,
	}
}

// ServeHTTP handles incoming requests.
func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqPath := r.URL.Path

	// Log incoming HTTP traffic if enabled.
	if h.httpLog {
		h.logger.Info("http_request",
			"method", r.Method,
			"path", reqPath,
			"query", r.URL.RawQuery,
			"remote", r.RemoteAddr,
			"user_agent", r.Header.Get("User-Agent"),
			"content_type", r.Header.Get("Content-Type"),
			"content_length", r.Header.Get("Content-Length"),
			"accept", r.Header.Get("Accept"),
		)
	}

	if reqPath == healthPath {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
		return
	}

	// Only handle POST to the LLM endpoints; everything else passes through.
	if r.Method != http.MethodPost || !isLLMEndpoint(reqPath) {
		h.passthrough(w, r)
		return
	}

	body, err := io.ReadAll(limitedBody(r, h.maxBodyBytes))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	// Decode the request body into a generic structure.
	var reqBody any
	if err := json.Unmarshal(body, &reqBody); err != nil {
		http.Error(w, "invalid request json", http.StatusBadRequest)
		return
	}

	// Per-request placeholder mapping: identical plaintext values share one
	// placeholder across the whole request. It is safe for concurrent use so
	// it can be read while a response streams back.
	gen := anonymize.NewPlaceholderGenerator()
	pipeline := anonymize.NewPipeline(h.presidio, h.logger, h.detector)

	// Extract and anonymize all user textual inputs.
	locations, err := anonymize.ExtractUserTexts(reqBody)
	if err != nil {
		http.Error(w, "failed to extract user text", http.StatusBadRequest)
		return
	}
	for _, loc := range locations {
		text := loc.Text

		// Stage 1: one-way secret redaction via gitleaks. Secrets are never
		// restored, so this runs before PII anonymization.
		if h.scanner != nil {
			findings := h.scanner.Scan(text)
			if len(findings) > 0 {
				text = secrets.Redact(text, findings)
				// Log each detection for audit purposes. The secret value is
				// intentionally not logged — only the rule, offsets, and entropy.
				for _, f := range findings {
					h.logger.Info("secret_redacted",
						"path", loc.Path,
						"rule_id", f.RuleID,
						"start", f.Start,
						"end", f.End,
						"entropy", f.Entropy,
					)
				}
			}
		}

		// Stage 2: PII anonymization (presidio) with placeholder restoration.
		anonymized, _, err := pipeline.AnonymizeText(r.Context(), text, gen)
		if err != nil {
			h.logger.Error("anonymization failed", "path", loc.Path, "error", err)
			http.Error(w, "anonymization failed", http.StatusInternalServerError)
			return
		}
		if err := anonymize.SetTextAtPath(reqBody, loc.Path, anonymized); err != nil {
			h.logger.Error("failed to write anonymized text", "path", loc.Path, "error", err)
			http.Error(w, "anonymization failed", http.StatusInternalServerError)
			return
		}
	}

	// Re-encode the anonymized request body.
	anonymizedBody, err := json.Marshal(reqBody)
	if err != nil {
		http.Error(w, "failed to encode request", http.StatusInternalServerError)
		return
	}

	// Forward to upstream, passing through the client's Authorization header.
	// The upstream base URL already includes /api/v1, so strip the leading
	// /v1 from the downstream path to avoid duplication.
	authHeader := r.Header.Get("Authorization")
	target := upstreamPath(reqPath) + forwardQuery(r.URL.RawQuery)
	resp, err := h.upstream.Forward(r.Context(), http.MethodPost, target, anonymizedBody, authHeader, true)
	if err != nil {
		h.logger.Error("upstream request failed", "error", err)
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Decide whether the response is streaming before touching headers:
	// streaming and non-streaming responses need different header handling.
	contentType := resp.Header.Get("Content-Type")
	streaming := strings.Contains(contentType, "text/event-stream") || isStreamRequest(reqBody)

	if streaming {
		h.copyResponseHeaders(w.Header(), resp)
		w.WriteHeader(resp.StatusCode)
		h.handleStreaming(w, resp, gen.Lookup, reqPath)
	} else {
		h.handleNonStreaming(w, resp, gen.Lookup)
	}

	// Log the downstream response status if enabled.
	if h.httpLog {
		h.logger.Info("http_response",
			"method", r.Method,
			"path", reqPath,
			"status", resp.StatusCode,
			"content_type", contentType,
		)
	}
}

// handleNonStreaming reads the full JSON response, restores placeholders, and
// writes it to the client. Content-Length is recomputed because restoration
// changes the body length.
func (h *ProxyHandler) handleNonStreaming(w http.ResponseWriter, resp *http.Response, lookup func(string) (string, bool)) {
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		h.logger.Error("failed to read upstream response", "error", err)
		http.Error(w, "failed to read upstream response", http.StatusBadGateway)
		return
	}

	out := data
	if restored, err := restore.RestoreJSONBytes(data, lookup); err == nil {
		out = restored
	} else {
		// If we can't parse as JSON, pass the raw body through unchanged.
		h.logger.Debug("response is not json; passing through unmodified", "error", err)
	}

	h.copyResponseHeaders(w.Header(), resp)
	w.Header().Set("Content-Length", strconv.Itoa(len(out)))
	w.WriteHeader(resp.StatusCode)
	if _, err := w.Write(out); err != nil {
		h.logger.Error("failed to write response", "error", err)
	}
}

// handleStreaming routes to the appropriate stream restorer based on the path.
func (h *ProxyHandler) handleStreaming(w http.ResponseWriter, resp *http.Response, lookup func(string) (string, bool), endpoint string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		h.logger.Error("streaming not supported by response writer")
		return
	}

	fw := &flushWriter{w: w, flusher: flusher}
	if endpoint == "/v1/responses" {
		// streamableHttp: JSON array of events.
		restorer := restore.NewStreamableRestorer(lookup).WithLogger(h.logger)
		if err := restorer.Copy(fw, resp.Body); err != nil {
			h.logger.Error("streamable restore failed", "error", err)
		}
	} else {
		// SSE: text/event-stream.
		restorer := restore.NewSSEStreamRestorer(lookup).WithLogger(h.logger)
		if err := restorer.Copy(fw, resp.Body); err != nil {
			h.logger.Error("sse restore failed", "error", err)
		}
	}
	flusher.Flush()
}

// passthrough forwards the request to the upstream unchanged. Its body is not
// logged even when UPSTREAM_LOG is enabled: passthrough bodies bypass the
// anonymization pipeline and could contain sensitive data.
func (h *ProxyHandler) passthrough(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(limitedBody(r, h.maxBodyBytes))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	authHeader := r.Header.Get("Authorization")
	target := upstreamPath(r.URL.Path) + forwardQuery(r.URL.RawQuery)
	resp, err := h.upstream.Forward(r.Context(), r.Method, target, body, authHeader, false)
	if err != nil {
		h.logger.Error("upstream request failed", "path", r.URL.Path, "error", err)
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	h.copyResponseHeaders(w.Header(), resp)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		h.logger.Error("failed to copy passthrough response", "error", err)
	}
}

// limitedBody wraps the request body in a size limiter so that oversized
// bodies fail fast instead of exhausting proxy memory.
func limitedBody(r *http.Request, maxBytes int64) io.Reader {
	if maxBytes <= 0 {
		return r.Body
	}
	return http.MaxBytesReader(nil, r.Body, maxBytes)
}

// hopByHopHeaders are per-connection headers that must not be forwarded
// between hops (RFC 9110 §7.6.1).
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// copyResponseHeaders copies upstream response headers to the client, dropping
// hop-by-hop headers and Content-Length. Content-Length is dropped because
// placeholder restoration can change the body length; callers either set the
// correct value explicitly or let Go compute it.
func (h *ProxyHandler) copyResponseHeaders(dst http.Header, resp *http.Response) {
	for k, vv := range resp.Header {
		if isHopByHop(k) || strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func isHopByHop(header string) bool {
	for _, h := range hopByHopHeaders {
		if strings.EqualFold(header, h) {
			return true
		}
	}
	return false
}

// flushWriter flushes after every successful write so streamed events reach
// the client immediately instead of being buffered until the handler returns.
type flushWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
}

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if err == nil {
		fw.flusher.Flush()
	}
	return n, err
}

// upstreamPath maps a downstream path to the upstream path. The upstream base
// URL already includes /api/v1, so /v1/chat/completions becomes
// /chat/completions when forwarded. The result is normalized with path.Clean
// so that dot segments cannot escape the intended upstream prefix.
func upstreamPath(p string) string {
	if p == "" {
		p = "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	// Strip exactly one leading "/v1" segment.
	if rest, ok := strings.CutPrefix(p, "/v1"); ok && (rest == "" || rest[0] == '/') {
		if rest == "" {
			rest = "/"
		}
		p = rest
	}
	cleaned := path.Clean(p)
	if !strings.HasPrefix(cleaned, "/") { // defensive: Clean of a rooted path stays rooted
		cleaned = "/" + cleaned
	}
	return cleaned
}

// forwardQuery reattaches the downstream query string to the forwarded path.
func forwardQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	return "?" + rawQuery
}

// isLLMEndpoint reports whether the path is a supported LLM endpoint.
func isLLMEndpoint(p string) bool {
	switch p {
	case "/v1/chat/completions", "/v1/responses", "/v1/completions":
		return true
	}
	return false
}

// isStreamRequest reports whether the request body requests streaming.
func isStreamRequest(body any) bool {
	m, ok := body.(map[string]any)
	if !ok {
		return false
	}
	stream, ok := m["stream"].(bool)
	return ok && stream
}
