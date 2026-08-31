package secrets

import (
	"testing"
)

// TestConvertLineColumnToOffsets verifies that gitleaks line/column positions
// are converted to byte offsets correctly, including multi-line text.
func TestConvertLineColumnToOffsets(t *testing.T) {
	text := "line one\nline two\nline three"

	// "line two" starts at byte 9 (after "line one\n"). Start column is 1-based
	// (1), end column is 0-based exclusive (4) for the 4-char word "line".
	start, end := ConvertLineColumnToOffsets(text, 2, 1, 2, 4)
	if start != 9 || end != 13 {
		t.Fatalf("expected [9,13), got [%d,%d)", start, end)
	}
	if text[start:end] != "line" {
		t.Fatalf("expected slice 'line', got %q", text[start:end])
	}

	// A single-line text: line 1, start column 1, end column 5 (exclusive).
	start, end = ConvertLineColumnToOffsets("hello", 1, 1, 1, 5)
	if start != 0 || end != 5 {
		t.Fatalf("expected [0,5), got [%d,%d)", start, end)
	}
	if "hello"[start:end] != "hello" {
		t.Fatalf("expected slice 'hello', got %q", "hello"[start:end])
	}
}

// TestConvertLineColumnToOffsetsClamps verifies that out-of-range positions
// are clamped to the text bounds.
func TestConvertLineColumnToOffsetsClamps(t *testing.T) {
	text := "abc"
	start, end := ConvertLineColumnToOffsets(text, 1, 1, 5, 10)
	if start != 0 || end != 3 {
		t.Fatalf("expected clamped [0,3), got [%d,%d)", start, end)
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
