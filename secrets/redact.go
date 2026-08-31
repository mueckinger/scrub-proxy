package secrets

import (
	"sort"
	"strings"
)

// RedactionToken is the fixed token that replaces every detected secret.
// Secrets are redacted one-way: the original value is never recoverable.
const RedactionToken = "[REDACTED]"

// Redact replaces each secret span in text with the fixed redaction token.
// Findings are sorted by start offset and applied left-to-right so that
// overlapping spans do not corrupt the output. The original secret is
// intentionally discarded.
func Redact(text string, findings []Finding) string {
	if len(findings) == 0 {
		return text
	}

	// Sort by start ascending, then by end descending so that, for equal
	// starts, the longer span is applied first.
	sorted := make([]Finding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Start != sorted[j].Start {
			return sorted[i].Start < sorted[j].Start
		}
		return sorted[i].End > sorted[j].End
	})

	var out strings.Builder
	cursor := 0
	for _, f := range sorted {
		start, end := f.Start, f.End
		if start < cursor {
			// This span overlaps an already-redacted region; skip it.
			continue
		}
		if start < 0 {
			start = 0
		}
		if end > len(text) {
			end = len(text)
		}
		if start >= end {
			continue
		}
		out.WriteString(text[cursor:start])
		out.WriteString(RedactionToken)
		cursor = end
	}
	out.WriteString(text[cursor:])
	return out.String()
}
