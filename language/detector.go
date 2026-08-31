package language

import (
	"fmt"
	"strings"

	"github.com/pemistahl/lingua-go"
)

// Detector wraps a lingua LanguageDetector to detect the language of a text
// and return its ISO 639-1 code (e.g. "en", "de").
type Detector struct {
	detector lingua.LanguageDetector
}

// NewDetector builds a language detector restricted to the given ISO 639-1
// codes (comma-separated, e.g. "en,de"). Unknown or unsupported codes are
// ignored. It returns an error if fewer than two valid languages remain,
// since lingua requires at least two languages to choose from.
func NewDetector(isoCodes string) (*Detector, error) {
	codes := parseIsoCodes(isoCodes)
	if len(codes) < 2 {
		return nil, fmt.Errorf("at least 2 valid ISO 639-1 language codes are required, got %d", len(codes))
	}

	detector := lingua.NewLanguageDetectorBuilder().
		FromIsoCodes639_1(codes...).
		Build()

	return &Detector{detector: detector}, nil
}

// DetectLanguageOf detects the language of the given text and returns its
// ISO 639-1 code in lowercase (e.g. "en", "de"), which is what presidio
// expects. If detection is not reliable, it returns the first configured
// language as a fallback.
func (d *Detector) DetectLanguageOf(text string) string {
	language, exists := d.detector.DetectLanguageOf(text)
	if !exists {
		return d.fallback()
	}
	return strings.ToLower(language.IsoCode639_1().String())
}

// fallback returns the ISO code of the first configured language in lowercase.
// It is used when language detection is not reliable (e.g. very short or empty
// text).
func (d *Detector) fallback() string {
	// The detector always has at least two languages (enforced in NewDetector).
	// We return the first one as a stable fallback.
	return strings.ToLower(d.detector.ComputeLanguageConfidenceValues("")[0].Language().IsoCode639_1().String())
}

// parseIsoCodes splits a comma-separated string into valid ISO 639-1 codes,
// preserving order and dropping invalid or duplicate entries.
func parseIsoCodes(s string) []lingua.IsoCode639_1 {
	var codes []lingua.IsoCode639_1
	seen := make(map[lingua.IsoCode639_1]struct{})
	for _, part := range strings.Split(s, ",") {
		code := lingua.GetIsoCode639_1FromValue(strings.TrimSpace(part))
		if code == lingua.UnknownIsoCode639_1 {
			continue
		}
		if _, exists := seen[code]; exists {
			continue
		}
		seen[code] = struct{}{}
		codes = append(codes, code)
	}
	return codes
}
