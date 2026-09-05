package secrets

import (
	"testing"
)

// testConfig is a minimal gitleaks TOML config exercising the scanner's
// feature set: capture-group extraction, entropy gating, keyword prefilter,
// and the global allowlist.
const testConfig = `
title = "test config"

[allowlist]
regexes = [
    '''^EXAMPLE[-0-9A-Z]+$''',
]
stopwords = ["changeme"]

[[rules]]
id = "openai-key"
regex = '''\bsk-[A-Za-z0-9]{20,}\b'''
keywords = ["sk-"]

[[rules]]
id = "assigned-token"
regex = '''token[=:]\s*([a-z0-9]+)'''
secretGroup = 1
keywords = ["token"]

[[rules]]
id = "entropy-gated"
regex = '''\bsecret[=:]\s*([A-Za-z0-9]{16,})\b'''
secretGroup = 1
entropy = 3.5
keywords = ["secret"]
`

func newTestScanner(t *testing.T) *RuleScanner {
	t.Helper()
	s, err := NewScanner("", []byte(testConfig))
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	return s
}

// TestScanFindsSecret verifies a basic match with correct byte offsets.
func TestScanFindsSecret(t *testing.T) {
	s := newTestScanner(t)
	text := "the key is sk-abcdefghij0123456789 ok"
	findings := s.Scan(text)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.RuleID != "openai-key" {
		t.Errorf("rule ID = %q, want openai-key", f.RuleID)
	}
	if text[f.Start:f.End] != "sk-abcdefghij0123456789" {
		t.Errorf("offsets [%d,%d) slice %q, want the key", f.Start, f.End, text[f.Start:f.End])
	}
	if f.Secret != "sk-abcdefghij0123456789" {
		t.Errorf("secret = %q", f.Secret)
	}
}

// TestScanSecretGroup verifies that secretGroup extracts the capture group,
// not the whole match.
func TestScanSecretGroup(t *testing.T) {
	s := newTestScanner(t)
	text := "token=abc123def"
	findings := s.Scan(text)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.RuleID != "assigned-token" {
		t.Errorf("rule ID = %q, want assigned-token", f.RuleID)
	}
	if text[f.Start:f.End] != "abc123def" {
		t.Errorf("offsets [%d,%d) slice %q, want 'abc123def'", f.Start, f.End, text[f.Start:f.End])
	}
}

// TestScanEntropyGate verifies that low-entropy matches are discarded.
func TestScanEntropyGate(t *testing.T) {
	s := newTestScanner(t)
	// "aaaaaaaaaaaaaaaa" has ~0 entropy and must be filtered.
	if got := s.Scan("secret=aaaaaaaaaaaaaaaa"); len(got) != 0 {
		t.Errorf("low-entropy match not filtered: %+v", got)
	}
	// High-entropy 16+ char match passes the 3.5 threshold.
	high := "secret=xK9mQ2vL8pR4wZ7j"
	if got := s.Scan(high); len(got) != 1 {
		t.Errorf("expected high-entropy match to pass, got %+v", got)
	}
}

// TestScanKeywordPrefilter verifies that rules whose keywords are absent from
// the text are skipped even if the regex would match.
func TestScanKeywordPrefilter(t *testing.T) {
	s, err := NewScanner("", []byte(`
[[rules]]
id = "kw-rule"
regex = '''key[=]\s*([a-z0-9]+)'''
secretGroup = 1
keywords = ["stripe"]
`))
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	if got := s.Scan("key=abc123def"); len(got) != 0 {
		t.Errorf("keyword prefilter failed: %+v", got)
	}
	if got := s.Scan("stripe key=abc123def"); len(got) != 1 {
		t.Errorf("expected match when keyword present, got %+v", got)
	}
}

// TestScanGlobalAllowlist verifies allowlist regexes and stopwords filter
// findings.
func TestScanGlobalAllowlist(t *testing.T) {
	s := newTestScanner(t)
	// "EXAMPLE1234567890" (captured group) matches allowlist ^EXAMPLE[-0-9A-Z]+$.
	if got := s.Scan("token=EXAMPLE1234567890"); len(got) != 0 {
		t.Errorf("allowlist regex not applied: %+v", got)
	}
	// Stopword "changeme" inside the secret.
	if got := s.Scan("token=changeme1"); len(got) != 0 {
		t.Errorf("stopword not applied: %+v", got)
	}
}

// TestScanPathRulesSkipped verifies path-gated rules never match on plain
// text (there is no path context in request bodies).
func TestScanPathRulesSkipped(t *testing.T) {
	s, err := NewScanner("", []byte(`
[[rules]]
id = "php-only"
regex = '''key[=]\s*([a-z0-9]+)'''
secretGroup = 1
path = '''(?i)\.php$'''
keywords = ["key"]

[[rules]]
id = "text-rule"
regex = '''key[=]\s*([a-z0-9]+)'''
secretGroup = 1
keywords = ["key"]
`))
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	findings := s.Scan("key=abc123def")
	if len(findings) != 1 || findings[0].RuleID != "text-rule" {
		t.Errorf("expected only text-rule finding, got %+v", findings)
	}
}

// TestNewScannerNoRules verifies an error when the config has no usable rules.
func TestNewScannerNoRules(t *testing.T) {
	if _, err := NewScanner("", []byte("title = \"empty\"\n")); err == nil {
		t.Fatal("expected error for config without rules")
	}
}

// TestNewScannerSkipsUncompilable verifies that rules using regex syntax
// beyond RE2 (e.g. lookaheads) are skipped without failing the whole scan.
func TestNewScannerSkipsUncompilable(t *testing.T) {
	s, err := NewScanner("", []byte(`
[[rules]]
id = "unsupported"
regex = '''(?<=x)key'''
keywords = ["key"]

[[rules]]
id = "supported"
regex = '''\bsk-[A-Za-z0-9]{20,}\b'''
keywords = ["sk-"]
`))
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	if len(s.rules) != 1 || s.rules[0].id != "supported" {
		t.Fatalf("expected only the supported rule, got %+v", s.rules)
	}
}

// TestShannonEntropy verifies known entropy values.
func TestShannonEntropy(t *testing.T) {
	if got := ShannonEntropy(""); got != 0 {
		t.Errorf("empty string entropy = %v, want 0", got)
	}
	if got := ShannonEntropy("aaaaaaaa"); got != 0 {
		t.Errorf("single-symbol entropy = %v, want 0", got)
	}
	// Two equally likely symbols: exactly 1 bit per byte.
	if got := ShannonEntropy("aabb"); got != 1 {
		t.Errorf("aabb entropy = %v, want 1", got)
	}
	if ShannonEntropy("xK9mQ2vL8pR4wZ7j") <= ShannonEntropy("aaaaaaaaaaaaaaaa") {
		t.Error("random-looking string should have higher entropy than repeats")
	}
}

// TestRedactReplacesSecrets verifies that secrets are replaced with the fixed
// redaction token.
func TestRedactReplacesSecrets(t *testing.T) {
	text := "api_key=sk-1234567890abcdef"
	findings := []Finding{
		{RuleID: "generic-api-key", Start: 8, End: 27, Secret: "sk-1234567890abcdef"},
	}
	out := Redact(text, findings)
	expected := "api_key=[REDACTED]"
	if out != expected {
		t.Fatalf("expected %q, got %q", expected, out)
	}
}

// TestRedactMultipleSecrets verifies that multiple non-overlapping secrets are
// each redacted.
func TestRedactMultipleSecrets(t *testing.T) {
	text := "token=abc123 and key=xyz789"
	findings := []Finding{
		{RuleID: "generic-api-key", Start: 6, End: 12, Secret: "abc123"},
		{RuleID: "generic-api-key", Start: 21, End: 27, Secret: "xyz789"},
	}
	out := Redact(text, findings)
	expected := "token=[REDACTED] and key=[REDACTED]"
	if out != expected {
		t.Fatalf("expected %q, got %q", expected, out)
	}
}

// TestRedactOverlappingSpans verifies that overlapping spans do not corrupt
// the output: the first span is redacted and the overlapping one is skipped.
func TestRedactOverlappingSpans(t *testing.T) {
	text := "abcdefghij"
	findings := []Finding{
		{RuleID: "a", Start: 2, End: 8, Secret: "cdefgh"},
		{RuleID: "b", Start: 4, End: 6, Secret: "ef"},
	}
	out := Redact(text, findings)
	expected := "ab[REDACTED]ij"
	if out != expected {
		t.Fatalf("expected %q, got %q", expected, out)
	}
}

// TestRedactNoFindings verifies that text is returned unchanged when there are
// no findings.
func TestRedactNoFindings(t *testing.T) {
	text := "no secrets here"
	out := Redact(text, nil)
	if out != text {
		t.Fatalf("expected unchanged text %q, got %q", text, out)
	}
}

// mockScanner returns a fixed set of findings for testing the pipeline stage.
type mockScanner struct {
	findings []Finding
}

func (m *mockScanner) Scan(text string) []Finding {
	return m.findings
}

// TestScannerInterface verifies that a mock scanner satisfies the Scanner
// interface and that its findings flow through redaction.
func TestScannerInterface(t *testing.T) {
	scanner := &mockScanner{findings: []Finding{
		{RuleID: "generic-api-key", Start: 0, End: 11, Secret: "sk-abcdefgh"},
	}}
	text := "sk-abcdefgh rest"
	out := Redact(text, scanner.Scan(text))
	expected := "[REDACTED] rest"
	if out != expected {
		t.Fatalf("expected %q, got %q", expected, out)
	}
}
