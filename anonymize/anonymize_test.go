package anonymize

import (
	"context"
	"log/slog"
	"testing"

	"scrub-proxy/language"
	"scrub-proxy/presidio"
)

// mockAnalyzer returns a fixed set of detections.
type mockAnalyzer struct {
	results []presidio.RecognizerResult
}

func (m *mockAnalyzer) Analyze(ctx context.Context, text, language string) ([]presidio.RecognizerResult, error) {
	return m.results, nil
}

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// testDetector builds a language detector restricted to English and German.
func testDetector() *language.Detector {
	d, err := language.NewDetector("en,de")
	if err != nil {
		panic(err)
	}
	return d
}

func TestAnonymizeText(t *testing.T) {
	// "John Smith" at bytes 11-20, "555-1234" at bytes 38-45.
	text := "My name is John Smith and my phone is 555-1234."
	analyzer := &mockAnalyzer{results: []presidio.RecognizerResult{
		{Start: 11, End: 21, Score: 0.9, EntityType: "PERSON"},
		{Start: 38, End: 46, Score: 0.95, EntityType: "PHONE_NUMBER"},
	}}
	p := NewPipeline(analyzer, discardLogger(), testDetector())
	gen := NewPlaceholderGenerator()

	out, repls, err := p.AnonymizeText(context.Background(), text, gen)
	if err != nil {
		t.Fatalf("AnonymizeText error: %v", err)
	}

	if len(repls) != 2 {
		t.Fatalf("expected 2 replacements, got %d", len(repls))
	}

	expected := "My name is <Name_1> and my phone is <Phone_1>."
	if out != expected {
		t.Fatalf("expected %q, got %q", expected, out)
	}

	// Verify the mapping restores the original.
	if v, ok := gen.Lookup("<Name_1>"); !ok || v != "John Smith" {
		t.Fatalf("expected lookup <Name_1> -> John Smith, got %q (ok=%v)", v, ok)
	}
	if v, ok := gen.Lookup("<Phone_1>"); !ok || v != "555-1234" {
		t.Fatalf("expected lookup <Phone_1> -> 555-1234, got %q (ok=%v)", v, ok)
	}
}

func TestAnonymizeTextDedup(t *testing.T) {
	// Same name appears twice.
	text := "John Smith and John Smith"
	analyzer := &mockAnalyzer{results: []presidio.RecognizerResult{
		{Start: 0, End: 10, Score: 0.9, EntityType: "PERSON"},
		{Start: 15, End: 25, Score: 0.9, EntityType: "PERSON"},
	}}
	p := NewPipeline(analyzer, discardLogger(), testDetector())
	gen := NewPlaceholderGenerator()

	out, _, err := p.AnonymizeText(context.Background(), text, gen)
	if err != nil {
		t.Fatalf("AnonymizeText error: %v", err)
	}

	// Both should map to the same placeholder.
	expected := "<Name_1> and <Name_1>"
	if out != expected {
		t.Fatalf("expected %q, got %q", expected, out)
	}
}

func TestAnonymizeTextNoPII(t *testing.T) {
	text := "This is a clean sentence."
	analyzer := &mockAnalyzer{results: nil}
	p := NewPipeline(analyzer, discardLogger(), testDetector())
	gen := NewPlaceholderGenerator()

	out, repls, err := p.AnonymizeText(context.Background(), text, gen)
	if err != nil {
		t.Fatalf("AnonymizeText error: %v", err)
	}
	if out != text {
		t.Fatalf("expected unchanged text %q, got %q", text, out)
	}
	if len(repls) != 0 {
		t.Fatalf("expected 0 replacements, got %d", len(repls))
	}
}
