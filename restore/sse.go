package restore

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
)

// SSEStreamRestorer reads an SSE stream from the upstream, restores
// placeholders in the content deltas, and writes the restored SSE stream to
// the destination. It preserves the SSE framing (data: lines, [DONE] marker).
//
// A placeholder may be split across multiple SSE events, so content deltas
// are fed through a HoldBackRestorer which holds back a bounded suffix that
// could still grow into a placeholder.
type SSEStreamRestorer struct {
	lookup func(string) (string, bool)
	logger *slog.Logger
}

// NewSSEStreamRestorer creates an SSE restorer.
func NewSSEStreamRestorer(lookup func(string) (string, bool)) *SSEStreamRestorer {
	return &SSEStreamRestorer{lookup: lookup, logger: slog.Default()}
}

// WithLogger sets the logger used for debug logging.
func (r *SSEStreamRestorer) WithLogger(l *slog.Logger) *SSEStreamRestorer {
	r.logger = l
	return r
}

// Copy reads SSE events from src and writes restored events to dst.
func (r *SSEStreamRestorer) Copy(dst io.Writer, src io.Reader) error {
	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	hb := NewHoldBackRestorer(r.lookup)

	// A single SSE event may span multiple data: lines. We buffer the current
	// event's data lines and emit them when a blank line terminates the event.
	var eventData []string
	flushEvent := func() error {
		if len(eventData) == 0 {
			return nil
		}
		restored := r.restoreEvent([]byte(strings.Join(eventData, "\n")), hb)
		if _, err := dst.Write(restored); err != nil {
			return err
		}
		eventData = eventData[:0]
		return nil
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if err := flushEvent(); err != nil {
				return err
			}
			if _, err := dst.Write([]byte("\n")); err != nil {
				return err
			}
			continue
		}
		if len(line) > 0 && line[0] == ':' {
			if _, err := dst.Write([]byte(line + "\n")); err != nil {
				return err
			}
			continue
		}
		if len(line) >= 6 && line[:6] == "data: " {
			eventData = append(eventData, line[6:])
			continue
		}
		if _, err := dst.Write([]byte(line + "\n")); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if err := flushEvent(); err != nil {
		return err
	}
	// Flush any remaining held-back partial placeholder.
	if _, err := dst.Write([]byte(hb.Flush())); err != nil {
		return err
	}
	return nil
}

// restoreEvent parses a single SSE data payload (JSON), restores placeholders
// in the content deltas via the hold-back restorer, and re-encodes it as a
// "data: " line.
func (r *SSEStreamRestorer) restoreEvent(payload []byte, hb *HoldBackRestorer) []byte {
	trimmed := bytes.TrimSpace(payload)
	if bytes.Equal(trimmed, []byte("[DONE]")) {
		return []byte("data: [DONE]\n")
	}

	var chunk map[string]any
	if err := json.Unmarshal(trimmed, &chunk); err != nil {
		return append([]byte("data: "), append(trimmed, '\n')...)
	}

	// Restore placeholders in choices[].delta.content and
	// choices[].delta.tool_calls[].function.arguments.
	if choices, ok := chunk["choices"].([]any); ok {
		for _, c := range choices {
			if cm, ok := c.(map[string]any); ok {
				if delta, ok := cm["delta"].(map[string]any); ok {
					if content, ok := delta["content"].(string); ok {
						// Feed through hold-back restorer; only the safe
						// portion is emitted now.
						delta["content"] = hb.Push(content)
					}
					// Tool call arguments may contain placeholders too.
					if toolCalls, ok := delta["tool_calls"].([]any); ok {
						for _, tc := range toolCalls {
							if tcm, ok := tc.(map[string]any); ok {
								if fn, ok := tcm["function"].(map[string]any); ok {
									if args, ok := fn["arguments"].(string); ok {
										restored := hb.Push(args)
										r.logger.Debug("sse_tool_call_arguments",
											"raw", args,
											"restored", restored,
										)
										fn["arguments"] = restored
									}
								}
							}
						}
					}
				}
			}
		}
	}

	out, err := json.Marshal(chunk)
	if err != nil {
		return append([]byte("data: "), append(trimmed, '\n')...)
	}
	return append([]byte("data: "), append(out, '\n')...)
}
