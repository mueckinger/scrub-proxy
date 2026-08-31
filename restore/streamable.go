package restore

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
)

// StreamableRestorer reads a streamableHttp response (a JSON array of event
// objects) from the upstream, restores placeholders in text deltas, and
// writes the restored stream to the destination.
//
// In the Responses API, text arrives in events of type
// "response.output_text.delta" with a "delta" field. A placeholder may be
// split across multiple deltas, so deltas are fed through a HoldBackRestorer.
type StreamableRestorer struct {
	lookup func(string) (string, bool)
	logger *slog.Logger
}

// NewStreamableRestorer creates a streamableHttp restorer.
func NewStreamableRestorer(lookup func(string) (string, bool)) *StreamableRestorer {
	return &StreamableRestorer{lookup: lookup, logger: slog.Default()}
}

// WithLogger sets the logger used for debug logging.
func (r *StreamableRestorer) WithLogger(l *slog.Logger) *StreamableRestorer {
	r.logger = l
	return r
}

// Copy reads events from src and writes restored events to dst.
func (r *StreamableRestorer) Copy(dst io.Writer, src io.Reader) error {
	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	hb := NewHoldBackRestorer(r.lookup)

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		restored, err := r.restoreLine(line, hb)
		if err != nil {
			// Pass through lines we can't parse.
			if _, werr := dst.Write(append(line, '\n')); werr != nil {
				return werr
			}
			continue
		}
		if _, err := dst.Write(append(restored, '\n')); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	// Flush any remaining held-back partial placeholder.
	if _, err := dst.Write([]byte(hb.Flush())); err != nil {
		return err
	}
	return nil
}

// restoreLine parses a single JSON event line and restores placeholders in
// text deltas.
func (r *StreamableRestorer) restoreLine(line []byte, hb *HoldBackRestorer) ([]byte, error) {
	var event map[string]any
	if err := json.Unmarshal(line, &event); err != nil {
		return nil, err
	}

	typ, _ := event["type"].(string)

	// Handle response.output_text.delta events: {"type":"response.output_text.delta","delta":"..."}
	if typ == "response.output_text.delta" {
		if delta, ok := event["delta"].(string); ok {
			event["delta"] = hb.Push(delta)
		}
	}

	// Also handle response.output_text.done which may carry the full text.
	if typ == "response.output_text.done" {
		if text, ok := event["text"].(string); ok {
			event["text"] = hb.Push(text)
		}
	}

	// Tool call arguments arrive in response.function_call_arguments.delta and
	// response.function_call_arguments.done events, in the "arguments" field.
	if typ == "response.function_call_arguments.delta" || typ == "response.function_call_arguments.done" {
		if args, ok := event["arguments"].(string); ok {
			restored := hb.Push(args)
			r.logger.Debug("streamable_tool_call_arguments",
				"type", typ,
				"raw", args,
				"restored", restored,
			)
			event["arguments"] = restored
		}
	}

	return json.Marshal(event)
}
