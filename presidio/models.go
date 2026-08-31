package presidio

import (
	"log/slog"
)

// AnalyzeRequest is the request body for POST /analyze.
type AnalyzeRequest struct {
	Text                  string   `json:"text"`
	Language              string   `json:"language"`
	ReturnDecisionProcess bool     `json:"return_decision_process,omitempty"`
	ScoreThreshold        *float64 `json:"score_threshold,omitempty"`
}

// RecognizerResult is a single PII detection from presidio.
type RecognizerResult struct {
	Start               int                  `json:"start"`
	End                 int                  `json:"end"`
	Score               float64              `json:"score"`
	EntityType          string               `json:"entity_type"`
	AnalysisExplanation *AnalysisExplanation `json:"analysis_explanation"`
}

// AnalysisExplanation describes why presidio made a detection decision.
type AnalysisExplanation struct {
	Recognizer              string  `json:"recognizer"`
	PatternName             *string `json:"pattern_name"`
	Pattern                 *string `json:"pattern"`
	OriginalScore           float64 `json:"original_score"`
	Score                   float64 `json:"score"`
	TextualExplanation      *string `json:"textual_explanation"`
	ScoreContextImprovement float64 `json:"score_context_improvement"`
	SupportiveContextWord   string  `json:"supportive_context_word"`
	ValidationResult        *bool   `json:"validation_result"`
}

// LogValue implements slog.LogValuer so that logging an *AnalysisExplanation
// renders a readable group of key/value pairs instead of raw pointer addresses
// for the pointer-typed fields.
func (e *AnalysisExplanation) LogValue() slog.Value {
	if e == nil {
		return slog.GroupValue()
	}
	return slog.GroupValue(
		slog.String("recognizer", e.Recognizer),
		slog.Any("pattern_name", derefString(e.PatternName)),
		slog.Any("pattern", derefString(e.Pattern)),
		slog.Float64("original_score", e.OriginalScore),
		slog.Float64("score", e.Score),
		slog.Any("textual_explanation", derefString(e.TextualExplanation)),
		slog.Float64("score_context_improvement", e.ScoreContextImprovement),
		slog.String("supportive_context_word", e.SupportiveContextWord),
		slog.Any("validation_result", derefBool(e.ValidationResult)),
	)
}

func derefString(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func derefBool(p *bool) any {
	if p == nil {
		return nil
	}
	return *p
}
