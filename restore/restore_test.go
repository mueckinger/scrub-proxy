package restore

import (
	"bytes"
	"strings"
	"testing"
)

func lookup() func(string) (string, bool) {
	m := map[string]string{
		"<Name_1>":  "John Smith",
		"<Phone_1>": "555-1234",
	}
	return func(s string) (string, bool) {
		v, ok := m[s]
		return v, ok
	}
}

func TestRestoreJSON(t *testing.T) {
	input := `{"choices":[{"message":{"content":"Hello <Name_1>, call <Phone_1> now"}}]}`
	out, err := RestoreJSONBytes([]byte(input), lookup())
	if err != nil {
		t.Fatalf("RestoreJSONBytes error: %v", err)
	}
	expected := `{"choices":[{"message":{"content":"Hello John Smith, call 555-1234 now"}}]}`
	if string(out) != expected {
		t.Fatalf("expected %q, got %q", expected, string(out))
	}
}

func TestHoldBackRestorerSingleChunk(t *testing.T) {
	hb := NewHoldBackRestorer(lookup())
	out := hb.Push("Hello <Name_1>!")
	if out != "Hello John Smith!" {
		t.Fatalf("expected %q, got %q", "Hello John Smith!", out)
	}
}

func TestHoldBackRestorerSplitPlaceholder(t *testing.T) {
	hb := NewHoldBackRestorer(lookup())

	// Feed the placeholder in pieces.
	out1 := hb.Push("Hello <Na")
	if out1 != "Hello " {
		t.Fatalf("expected %q, got %q", "Hello ", out1)
	}
	out2 := hb.Push("me_1>!")
	if out2 != "John Smith!" {
		t.Fatalf("expected %q, got %q", "John Smith!", out2)
	}
}

func TestHoldBackRestorerFlushPartial(t *testing.T) {
	hb := NewHoldBackRestorer(lookup())
	out1 := hb.Push("Hello <Na")
	if out1 != "Hello " {
		t.Fatalf("expected %q, got %q", "Hello ", out1)
	}
	// Stream ends with a partial placeholder — flush emits it as-is.
	out2 := hb.Flush()
	if out2 != "<Na" {
		t.Fatalf("expected %q, got %q", "<Na", out2)
	}
}

func TestSSERestorer(t *testing.T) {
	input := "data: {\"choices\":[{\"delta\":{\"content\":\"Hello <Na\"}}]}\n\n" +
		"data: {\"choices\":[{\"delta\":{\"content\":\"me_1>!\"}}]}\n\n" +
		"data: [DONE]\n\n"

	var out bytes.Buffer
	r := NewSSEStreamRestorer(lookup())
	if err := r.Copy(&out, strings.NewReader(input)); err != nil {
		t.Fatalf("SSE Copy error: %v", err)
	}

	result := out.String()
	if !strings.Contains(result, "John Smith") {
		t.Fatalf("expected restored content to contain John Smith, got: %q", result)
	}
	if strings.Contains(result, "<Name_1>") {
		t.Fatalf("expected placeholder to be restored, got: %q", result)
	}
	if !strings.Contains(result, "[DONE]") {
		t.Fatalf("expected [DONE] marker preserved, got: %q", result)
	}
}

func TestStreamableRestorer(t *testing.T) {
	input := "{\"type\":\"response.output_text.delta\",\"delta\":\"Hello <Na\"}\n" +
		"{\"type\":\"response.output_text.delta\",\"delta\":\"me_1>!\"}\n"

	var out bytes.Buffer
	r := NewStreamableRestorer(lookup())
	if err := r.Copy(&out, strings.NewReader(input)); err != nil {
		t.Fatalf("Streamable Copy error: %v", err)
	}

	result := out.String()
	if !strings.Contains(result, "John Smith") {
		t.Fatalf("expected restored content to contain John Smith, got: %q", result)
	}
	if strings.Contains(result, "<Name_1>") {
		t.Fatalf("expected placeholder to be restored, got: %q", result)
	}
}

func TestSSERestorerToolCalls(t *testing.T) {
	// Tool call arguments split across SSE events.
	input := "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"arguments\":\"{\\\"name\\\":\\\"<Na\"}}]}}]}\n\n" +
		"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"arguments\":\"me_1>\\\"}\"}}]}}]}\n\n" +
		"data: [DONE]\n\n"

	var out bytes.Buffer
	r := NewSSEStreamRestorer(lookup())
	if err := r.Copy(&out, strings.NewReader(input)); err != nil {
		t.Fatalf("SSE Copy error: %v", err)
	}

	result := out.String()
	if !strings.Contains(result, "John Smith") {
		t.Fatalf("expected restored tool args to contain John Smith, got: %q", result)
	}
	if strings.Contains(result, "<Name_1>") {
		t.Fatalf("expected placeholder in tool args to be restored, got: %q", result)
	}
}

func TestStreamableRestorerToolCalls(t *testing.T) {
	// Tool call arguments split across function_call_arguments.delta events.
	input := "{\"type\":\"response.function_call_arguments.delta\",\"arguments\":\"{\\\"name\\\":\\\"<Na\"}\n" +
		"{\"type\":\"response.function_call_arguments.delta\",\"arguments\":\"me_1>\\\"}\"}\n"

	var out bytes.Buffer
	r := NewStreamableRestorer(lookup())
	if err := r.Copy(&out, strings.NewReader(input)); err != nil {
		t.Fatalf("Streamable Copy error: %v", err)
	}

	result := out.String()
	if !strings.Contains(result, "John Smith") {
		t.Fatalf("expected restored tool args to contain John Smith, got: %q", result)
	}
	if strings.Contains(result, "<Name_1>") {
		t.Fatalf("expected placeholder in tool args to be restored, got: %q", result)
	}
}
