package anonymize

import (
	"fmt"
	"strconv"
)

// TextLocation identifies a user textual input within a request body.
// It stores the JSON path so the anonymized text can be written back.
type TextLocation struct {
	// Path is the JSON path to the text value, e.g. "messages.0.content".
	Path string
	// Text is the current text value at that path.
	Text string
}

// ExtractUserTexts walks a decoded JSON request body and returns all user
// textual inputs along with their JSON paths. It handles:
//   - messages[].content (string or array of content parts)
//   - input (string or array of strings) — Responses API
//   - prompt (string) — legacy completions
//
// The returned locations can be used to write anonymized text back.
func ExtractUserTexts(body any) ([]TextLocation, error) {
	var locations []TextLocation
	if err := extract(body, "", &locations); err != nil {
		return nil, err
	}
	return locations, nil
}

func extract(v any, path string, out *[]TextLocation) error {
	switch t := v.(type) {
	case map[string]any:
		// messages[].content
		if path == "" || isMessagesArray(path) {
			if content, ok := t["content"]; ok {
				if err := extractContent(content, joinPath(path, "content"), out); err != nil {
					return err
				}
			}
		}
		// input (Responses API)
		if input, ok := t["input"]; ok {
			if err := extractInput(input, joinPath(path, "input"), out); err != nil {
				return err
			}
		}
		// prompt (legacy completions)
		if prompt, ok := t["prompt"]; ok {
			if s, ok := prompt.(string); ok {
				*out = append(*out, TextLocation{Path: joinPath(path, "prompt"), Text: s})
			}
		}
		// Recurse into nested objects.
		for k, child := range t {
			if k == "content" || k == "input" || k == "prompt" {
				continue
			}
			if err := extract(child, joinPath(path, k), out); err != nil {
				return err
			}
		}
	case []any:
		for i, child := range t {
			if err := extract(child, joinPath(path, strconv.Itoa(i)), out); err != nil {
				return err
			}
		}
	}
	return nil
}

// extractContent handles messages[].content which can be a string or an array
// of content parts (e.g. {"type":"text","text":"..."}).
func extractContent(v any, path string, out *[]TextLocation) error {
	switch t := v.(type) {
	case string:
		*out = append(*out, TextLocation{Path: path, Text: t})
	case []any:
		for i, part := range t {
			if m, ok := part.(map[string]any); ok {
				if typ, _ := m["type"].(string); typ == "text" {
					if text, ok := m["text"].(string); ok {
						*out = append(*out, TextLocation{Path: joinPath(path, strconv.Itoa(i), "text"), Text: text})
					}
				}
			}
		}
	}
	return nil
}

// extractInput handles the Responses API "input" field: string or array of
// strings (or array of message objects with content).
func extractInput(v any, path string, out *[]TextLocation) error {
	switch t := v.(type) {
	case string:
		*out = append(*out, TextLocation{Path: path, Text: t})
	case []any:
		for i, item := range t {
			switch it := item.(type) {
			case string:
				*out = append(*out, TextLocation{Path: joinPath(path, strconv.Itoa(i)), Text: it})
			case map[string]any:
				if content, ok := it["content"]; ok {
					if err := extractContent(content, joinPath(path, strconv.Itoa(i), "content"), out); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func isMessagesArray(path string) bool {
	// Path like "messages.0" or "messages.0.content" — check if it contains
	// "messages." followed by a digit.
	for i := 0; i+len("messages.") <= len(path); i++ {
		if path[i:i+len("messages.")] == "messages." {
			rest := path[i+len("messages."):]
			if len(rest) > 0 && rest[0] >= '0' && rest[0] <= '9' {
				return true
			}
		}
	}
	return false
}

func joinPath(parts ...string) string {
	out := ""
	for _, p := range parts {
		if p == "" {
			continue
		}
		if out == "" {
			out = p
		} else {
			out = out + "." + p
		}
	}
	return out
}

// SetTextAtPath writes a string value at the given JSON path within the body.
// The path is a dot-separated sequence of keys and array indices.
func SetTextAtPath(body any, path string, value string) error {
	parts := splitPath(path)
	if len(parts) == 0 {
		return fmt.Errorf("empty path")
	}
	cur := body
	for i, part := range parts {
		last := i == len(parts)-1
		switch node := cur.(type) {
		case map[string]any:
			if last {
				node[part] = value
				return nil
			}
			next, ok := node[part]
			if !ok {
				return fmt.Errorf("path %q not found", path)
			}
			cur = next
		case []any:
			idx, err := strconv.Atoi(part)
			if err != nil {
				return fmt.Errorf("invalid array index %q: %w", part, err)
			}
			if idx < 0 || idx >= len(node) {
				return fmt.Errorf("array index %d out of range", idx)
			}
			if last {
				node[idx] = value
				return nil
			}
			cur = node[idx]
		default:
			return fmt.Errorf("cannot traverse into %T at %q", cur, part)
		}
	}
	return fmt.Errorf("path %q not found", path)
}

func splitPath(path string) []string {
	var parts []string
	start := 0
	for i := 0; i <= len(path); i++ {
		if i == len(path) || path[i] == '.' {
			if i > start {
				parts = append(parts, path[start:i])
			}
			start = i + 1
		}
	}
	return parts
}
