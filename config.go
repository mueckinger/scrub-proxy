package main

import (
	"log/slog"
	"os"
	"strconv"
	"strings"
)

// DefaultMaxRequestBodyBytes caps how large an incoming request body may be
// (10 MiB). Bodies are fully buffered for anonymization, so an explicit limit
// protects the proxy from memory-exhaustion denial of service.
const DefaultMaxRequestBodyBytes = 10 << 20

// Config holds all runtime configuration, sourced from environment variables.
type Config struct {
	// PresidioAnalyzerURL is the base URL of the presidio-analyzer service.
	PresidioAnalyzerURL string
	// UpstreamBaseURL is the base URL of the upstream LLM API.
	UpstreamBaseURL string
	// Port is the port the proxy listens on.
	Port int
	// HTTPLog enables logging of incoming HTTP traffic.
	HTTPLog bool
	// UpstreamLog enables logging of outgoing upstream HTTP traffic.
	UpstreamLog bool
	// LogLevel is the slog log level ("debug", "info", "warn", "error").
	LogLevel string
	// AnalyzerLanguages is a comma-separated list of ISO 639-1 codes that the
	// language detector may choose from when analyzing text (default "en,de").
	AnalyzerLanguages string
	// SecretScanEnabled enables the gitleaks secret redaction stage.
	SecretScanEnabled bool
	// GitleaksConfig is the path to a custom gitleaks TOML config. When empty,
	// the gitleaks default config is used.
	GitleaksConfig string
	// MaxRequestBodyBytes caps the size of buffered request bodies. Zero or
	// negative disables the limit (not recommended).
	MaxRequestBodyBytes int64
}

// LoadConfig reads configuration from environment variables, applying defaults.
func LoadConfig() Config {
	return Config{
		PresidioAnalyzerURL: getEnv("PRESIDIO_ANALYZER_URL", "http://presidio-analyzer"),
		UpstreamBaseURL:     getEnv("UPSTREAM_BASE_URL", "https://openrouter.ai/api/v1"),
		Port:                getEnvInt("PORT", 8080),
		HTTPLog:             getEnvBool("HTTP_LOG", false),
		UpstreamLog:         getEnvBool("UPSTREAM_LOG", false),
		LogLevel:            getEnv("LOG_LEVEL", "info"),
		AnalyzerLanguages:   getEnv("ANALYZER_LANGUAGES", "en,de"),
		SecretScanEnabled:   getEnvBool("SECRET_SCAN_ENABLED", true),
		GitleaksConfig:      getEnv("GITLEAKS_CONFIG", ""),
		MaxRequestBodyBytes: getEnvInt64("MAX_REQUEST_BODY_BYTES", DefaultMaxRequestBodyBytes),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		switch strings.ToLower(v) {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		}
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func getEnvInt64(key string, fallback int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return fallback
}

// parseLogLevel maps a string log level to a slog.Level.
func parseLogLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
