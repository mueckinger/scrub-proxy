package restore

import (
	"encoding/json"
	"fmt"
)

// RestoreJSON walks a decoded JSON value and replaces every placeholder in
// every string with its plaintext, using the provided lookup function.
// It returns a new value with placeholders restored.
func RestoreJSON(v any, lookup func(string) (string, bool)) any {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			t[k] = RestoreJSON(child, lookup)
		}
		return t
	case []any:
		for i, child := range t {
			t[i] = RestoreJSON(child, lookup)
		}
		return t
	case string:
		return RestoreString(t, lookup)
	default:
		return v
	}
}

// RestoreJSONBytes decodes JSON, restores placeholders, and re-encodes it.
func RestoreJSONBytes(data []byte, lookup func(string) (string, bool)) ([]byte, error) {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("decode response json: %w", err)
	}
	restored := RestoreJSON(v, lookup)
	out, err := json.Marshal(restored)
	if err != nil {
		return nil, fmt.Errorf("encode restored json: %w", err)
	}
	return out, nil
}
