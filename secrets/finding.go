package secrets

// Finding is a single secret detection with byte offsets into the scanned
// text. Gitleaks reports line/column positions; we convert them to byte
// offsets so findings can be redacted by span.
type Finding struct {
	// RuleID is the gitleaks rule that matched (e.g. "generic-api-key").
	RuleID string
	// Start is the byte offset of the start of the secret.
	Start int
	// End is the byte offset just past the end of the secret.
	End int
	// Secret is the captured secret value.
	Secret string
	// Entropy is the shannon entropy of the secret, if computed.
	Entropy float32
}

// ConvertLineColumnToOffsets converts a gitleaks finding's line/column
// positions into byte offsets into the original text.
//
// Gitleaks reports 1-based lines. The start column is 1-based (the first
// character of the match is column 1); the end column is 0-based and exclusive
// (it points just past the last character of the match). We walk the text line
// by line, tracking byte offsets, and resolve both positions.
func ConvertLineColumnToOffsets(text string, startLine, startColumn, endLine, endColumn int) (int, int) {
	// Build the byte offset of each line's first character. A trailing newline
	// produces a final empty line, which is harmless for position resolution.
	var lineStarts []int
	lineStarts = append(lineStarts, 0)
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			lineStarts = append(lineStarts, i+1)
		}
	}

	// Start column is 1-based; end column is 0-based exclusive.
	start := lineOffset(lineStarts, startLine) + (startColumn - 1)
	end := lineOffset(lineStarts, endLine) + endColumn

	// Clamp to the text bounds.
	if start < 0 {
		start = 0
	}
	if end > len(text) {
		end = len(text)
	}
	if start > end {
		start = end
	}
	return start, end
}

// lineOffset returns the byte offset of the first character of the given
// 1-based line, clamped to the text bounds.
func lineOffset(lineStarts []int, line int) int {
	if line < 1 {
		line = 1
	}
	if line > len(lineStarts) {
		return lineStarts[len(lineStarts)-1]
	}
	return lineStarts[line-1]
}
