package presidio

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
)

// decodeResults decodes a presidio /analyze response body into results.
func decodeResults(t *testing.T, body string) []RecognizerResult {
	var results []RecognizerResult
	if err := json.NewDecoder(bytes.NewReader([]byte(body))).Decode(&results); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return results
}

// TestDecodeSpacyRecognizer verifies that a SpacyRecognizer response is parsed
// with textual_explanation populated and pattern fields legitimately null.
func TestDecodeSpacyRecognizer(t *testing.T) {
	body := `[
		{
			"entity_type": "PERSON", "start": 0, "end": 10, "score": 0.85,
			"analysis_explanation": {
				"recognizer": "SpacyRecognizer", "pattern_name": null, "pattern": null,
				"original_score": 0.85, "score": 0.85,
				"textual_explanation": "Identified as PERSON by Spacy's Named Entity Recognition",
				"score_context_improvement": 0, "supportive_context_word": "",
				"validation_result": null
			}
		}
	]`
	results := decodeResults(t, body)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	exp := results[0].AnalysisExplanation
	if exp == nil {
		t.Fatal("expected analysis_explanation to be present")
	}
	if exp.Recognizer != "SpacyRecognizer" {
		t.Fatalf("expected recognizer SpacyRecognizer, got %q", exp.Recognizer)
	}
	// textual_explanation is populated by the API for SpacyRecognizer.
	if exp.TextualExplanation == nil {
		t.Fatal("expected textual_explanation to be populated")
	}
	if *exp.TextualExplanation != "Identified as PERSON by Spacy's Named Entity Recognition" {
		t.Fatalf("unexpected textual_explanation: %q", *exp.TextualExplanation)
	}
	// pattern_name/pattern/validation_result are legitimately null for Spacy.
	if exp.PatternName != nil {
		t.Fatalf("expected pattern_name to be null, got %q", *exp.PatternName)
	}
	if exp.Pattern != nil {
		t.Fatalf("expected pattern to be null, got %q", *exp.Pattern)
	}
	if exp.ValidationResult != nil {
		t.Fatalf("expected validation_result to be null, got %v", *exp.ValidationResult)
	}
}

// TestDecodePatternRecognizer verifies that a PatternRecognizer response is
// parsed with pattern_name/pattern populated and textual_explanation null.
func TestDecodePatternRecognizer(t *testing.T) {
	body := `[
		{
			"entity_type": "US_DRIVER_LICENSE", "start": 30, "end": 38, "score": 0.6499999999999999,
			"analysis_explanation": {
				"recognizer": "UsLicenseRecognizer",
				"pattern_name": "Driver License - Alphanumeric (weak)",
				"pattern": "\\\\b([A-Z][0-9]{3,6})\\\\b",
				"original_score": 0.3, "score": 0.6499999999999999,
				"textual_explanation": null,
				"score_context_improvement": 0.3499999999999999,
				"supportive_context_word": "driver",
				"validation_result": null
			}
		}
	]`
	results := decodeResults(t, body)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	exp := results[0].AnalysisExplanation
	if exp == nil {
		t.Fatal("expected analysis_explanation to be present")
	}
	if exp.PatternName == nil || *exp.PatternName != "Driver License - Alphanumeric (weak)" {
		t.Fatalf("expected pattern_name to be populated, got %v", exp.PatternName)
	}
	if exp.Pattern == nil || *exp.Pattern != "\\\\b([A-Z][0-9]{3,6})\\\\b" {
		t.Fatalf("expected pattern to be populated, got %v", exp.Pattern)
	}
	// textual_explanation is legitimately null for a PatternRecognizer.
	if exp.TextualExplanation != nil {
		t.Fatalf("expected textual_explanation to be null, got %q", *exp.TextualExplanation)
	}
	if exp.SupportiveContextWord != "driver" {
		t.Fatalf("expected supportive_context_word driver, got %q", exp.SupportiveContextWord)
	}
}

// TestLogValueRendering verifies that slog renders an AnalysisExplanation as a
// readable group (no raw pointer addresses) and that populated fields show
// their values rather than <nil>.
func TestLogValueRendering(t *testing.T) {
	textual := "Identified as PERSON by Spacy's Named Entity Recognition"
	exp := AnalysisExplanation{
		Recognizer:              "SpacyRecognizer",
		PatternName:             nil,
		Pattern:                 nil,
		OriginalScore:           0.85,
		Score:                   0.85,
		TextualExplanation:      &textual,
		ScoreContextImprovement: 0,
		SupportiveContextWord:   "",
		ValidationResult:        nil,
	}

	// Render through slog to a string and assert the populated value appears.
	var buf bytes.Buffer
	handler := slog.New(slog.NewTextHandler(&buf, nil))
	handler.Info("pii_replaced", "analysis_explanation", &exp)
	out := buf.String()

	if !contains(out, "Identified as PERSON by Spacy's Named Entity Recognition") {
		t.Fatalf("expected textual_explanation value in log output, got: %s", out)
	}
	if contains(out, "0x") {
		t.Fatalf("log output should not contain raw pointer addresses, got: %s", out)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || stringContains(haystack, needle)
}

func stringContains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
