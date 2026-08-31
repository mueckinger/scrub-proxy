package anonymize

import (
	"context"
	"fmt"
	"log/slog"
	"sort"

	"scrub-proxy/language"
	"scrub-proxy/presidio"
)

// Analyzer is the interface the pipeline uses to detect PII. It is satisfied
// by *presidio.Client and can be mocked in tests.
type Analyzer interface {
	Analyze(ctx context.Context, text, language string) ([]presidio.RecognizerResult, error)
}

// Replacement is a single PII replacement, logged for audit purposes.
type Replacement struct {
	EntityType          string
	Start               int
	End                 int
	Score               float64
	Placeholder         string
	AnalysisExplanation *presidio.AnalysisExplanation
}

// Pipeline anonymizes user text by detecting PII via presidio and replacing
// each span with a bounded placeholder.
type Pipeline struct {
	analyzer Analyzer
	logger   *slog.Logger
	detector *language.Detector
}

// NewPipeline creates an anonymization pipeline. The detector is used to
// determine the language of each text before it is sent to presidio.
func NewPipeline(analyzer Analyzer, logger *slog.Logger, detector *language.Detector) *Pipeline {
	return &Pipeline{analyzer: analyzer, logger: logger, detector: detector}
}

// AnonymizeText analyzes a single text and returns the anonymized text plus
// the list of replacements made. The generator is used to deduplicate values
// across the whole request.
func (p *Pipeline) AnonymizeText(ctx context.Context, text string, gen *PlaceholderGenerator) (string, []Replacement, error) {
	if text == "" {
		return text, nil, nil
	}

	// Detect the language of this specific text and pass it to presidio.
	language := p.detector.DetectLanguageOf(text)
	results, err := p.analyzer.Analyze(ctx, text, language)
	if err != nil {
		return "", nil, fmt.Errorf("analyze text: %w", err)
	}

	// Presidio returns byte offsets into the original text. We operate on
	// byte indices throughout.
	spans := normalizeDetections(results, len(text))
	if len(spans) == 0 {
		return text, nil, nil
	}

	out := text
	replacements := make([]Replacement, 0, len(spans))
	// Apply replacements right-to-left so earlier byte offsets stay valid.
	for i := len(spans) - 1; i >= 0; i-- {
		s := spans[i]
		value := out[s.start:s.end]
		ph := gen.PlaceholderFor(value, s.result.EntityType)

		out = out[:s.start] + ph + out[s.end:]

		replacements = append(replacements, Replacement{
			EntityType:          s.result.EntityType,
			Start:               s.start,
			End:                 s.end,
			Score:               s.result.Score,
			Placeholder:         ph,
			AnalysisExplanation: s.result.AnalysisExplanation,
		})
		p.logger.Info("pii_replaced",
			"entity_type", s.result.EntityType,
			"start", s.start,
			"end", s.end,
			"score", s.result.Score,
			"placeholder", ph,
			"language", language,
			"analysis_explanation", s.result.AnalysisExplanation,
		)
	}

	return out, replacements, nil
}

// piiSpan is a validated detection span with clamped byte offsets.
type piiSpan struct {
	result presidio.RecognizerResult
	start  int
	end    int
}

// normalizeDetections converts raw detections into clamped, non-overlapping
// spans ordered by start position. Overlapping detections are dropped so that
// applying two replacements to the same byte range cannot corrupt the output;
// for equal starts the longer span wins.
func normalizeDetections(results []presidio.RecognizerResult, textLen int) []piiSpan {
	sorted := make([]presidio.RecognizerResult, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Start != sorted[j].Start {
			return sorted[i].Start < sorted[j].Start
		}
		return sorted[i].End > sorted[j].End
	})

	spans := make([]piiSpan, 0, len(sorted))
	keptEnd := 0
	for _, r := range sorted {
		start, end := max(r.Start, 0), min(r.End, textLen)
		if start >= end || start < keptEnd {
			continue
		}
		keptEnd = end
		spans = append(spans, piiSpan{result: r, start: start, end: end})
	}
	return spans
}
