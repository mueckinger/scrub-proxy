package restore

import (
	"strings"

	"scrub-proxy/anonymize"
)

// HoldBackRestorer incrementally restores placeholders in a streaming
// response. It holds back a bounded suffix that could still grow into a
// placeholder, and only emits text that is provably not part of a placeholder.
//
// Because placeholders have a bounded, well-defined format, the restorer can
// reliably detect partial placeholders and hold them back until they complete
// (or the stream ends).
type HoldBackRestorer struct {
	pending string
	lookup  func(string) (string, bool)
}

// NewHoldBackRestorer creates a restorer that resolves placeholders via the
// provided lookup function (typically the per-request mapping).
func NewHoldBackRestorer(lookup func(string) (string, bool)) *HoldBackRestorer {
	return &HoldBackRestorer{lookup: lookup}
}

// Push feeds a chunk of streamed text and returns the portion that is now
// safe to emit (with placeholders restored). Any suffix that could still grow
// into a placeholder is held back.
func (r *HoldBackRestorer) Push(chunk string) string {
	r.pending += chunk
	holdStart := findHoldStart(r.pending)
	if holdStart >= len(r.pending) {
		safe := r.pending
		r.pending = ""
		return RestoreString(safe, r.lookup)
	}
	safe := r.pending[:holdStart]
	r.pending = r.pending[holdStart:]
	return RestoreString(safe, r.lookup)
}

// Flush emits whatever is still buffered. Partial placeholders come out as-is
// (they cannot be resolved).
func (r *HoldBackRestorer) Flush() string {
	out := RestoreString(r.pending, r.lookup)
	r.pending = ""
	return out
}

// RestoreString replaces every complete placeholder in s with its plaintext
// using the provided lookup function. Tokens that don't resolve are left
// unchanged.
func RestoreString(s string, lookup func(string) (string, bool)) string {
	if lookup == nil || !strings.Contains(s, "<") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for {
		start := strings.IndexByte(s, '<')
		if start < 0 {
			b.WriteString(s)
			break
		}
		b.WriteString(s[:start])
		// Find the closing '>'.
		end := strings.IndexByte(s[start:], '>')
		if end < 0 {
			// No closing bracket — not a complete placeholder.
			b.WriteString(s[start:])
			break
		}
		end += start + 1
		token := s[start:end]
		if plain, ok := lookup(token); ok {
			b.WriteString(plain)
		} else {
			b.WriteString(token)
		}
		s = s[end:]
	}
	return b.String()
}

// findHoldStart scans backward from the end of the buffer for the last '<'
// that could begin a placeholder. It returns the index at which the safe
// prefix ends (i.e. the start of the held-back suffix). If nothing could be a
// placeholder prefix, it returns len(buffer).
func findHoldStart(buffer string) int {
	for i := len(buffer) - 1; i >= 0; i-- {
		if buffer[i] != '<' {
			continue
		}
		tail := buffer[i:]
		if len(tail) > anonymize.MaxPlaceholderLen {
			continue
		}
		if anonymize.CompletePlaceholder.MatchString(tail) {
			continue
		}
		if anonymize.ViablePrefix.MatchString(tail) {
			return i
		}
	}
	return len(buffer)
}
