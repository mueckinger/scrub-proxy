package anonymize

import (
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Placeholder format: <Label_Index>
// - Label: a short, sanitized label derived from the entity type.
// - Index: a per-request counter so identical values share one label.
//
// The format is bounded and well-defined so that streaming restoration can
// reliably detect partial placeholders (see restore/holdback.go).

// MaxPlaceholderLen is the maximum length of a complete placeholder.
// Format: '<' + label(<=32) + '_' + index(<=6) + '>'  => max 41 chars.
const MaxPlaceholderLen = 41

// CompletePlaceholder matches a fully-formed placeholder.
var CompletePlaceholder = regexp.MustCompile(`^<[A-Za-z0-9_]{1,32}_\d{1,6}>$`)

// ViablePrefix matches a string that could still grow into a complete
// placeholder (i.e. an incomplete placeholder prefix).
var ViablePrefix = regexp.MustCompile(`^<[A-Za-z0-9_]{0,32}(?:_\d{0,6})?>?$`)

// maxLabelLen caps the sanitized entity-type label length.
const maxLabelLen = 32

// labelForEntity maps a presidio entity type to a short, human-readable label.
// Unknown entity types fall back to a sanitized version of the type itself.
func labelForEntity(entityType string) string {
	upper := strings.ToUpper(strings.TrimSpace(entityType))
	switch upper {
	case "PERSON":
		return "Name"
	case "EMAIL_ADDRESS":
		return "Email"
	case "PHONE_NUMBER":
		return "Phone"
	case "LOCATION":
		return "Location"
	case "CREDIT_CARD":
		return "Card"
	case "US_SSN":
		return "SSN"
	case "IP_ADDRESS":
		return "IP"
	case "DATE_TIME":
		return "Date"
	case "URL":
		return "URL"
	case "IBAN_CODE":
		return "IBAN"
	case "CRYPTO":
		return "Crypto"
	case "US_DRIVER_LICENSE":
		return "License"
	case "US_PASSPORT":
		return "Passport"
	case "US_BANK_NUMBER":
		return "Bank"
	case "US_ITIN":
		return "ITIN"
	case "UK_NHS":
		return "NHS"
	case "NRP":
		return "NRP"
	case "MEDICAL_LICENSE":
		return "MedLicense"
	default:
		// Sanitize: keep only alphanumerics and underscores, cap length.
		var b strings.Builder
		for _, r := range upper {
			if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
				b.WriteRune(r)
			}
		}
		s := b.String()
		if s == "" {
			s = "PII"
		}
		if len(s) > maxLabelLen {
			s = s[:maxLabelLen]
		}
		return s
	}
}

// PlaceholderGenerator creates unique, deduplicated placeholders for a single
// request. Identical plaintext values map to the same placeholder. It is safe
// for concurrent use: placeholders are generated while the request is
// anonymized and looked up while the response streams back.
type PlaceholderGenerator struct {
	mu sync.RWMutex
	// labelCounts tracks the next index per label.
	labelCounts map[string]int
	// valueToPlaceholder deduplicates identical plaintext values.
	valueToPlaceholder map[string]string
	// placeholderToValue is the reverse mapping for restoration.
	placeholderToValue map[string]string
}

// NewPlaceholderGenerator creates an empty generator.
func NewPlaceholderGenerator() *PlaceholderGenerator {
	return &PlaceholderGenerator{
		labelCounts:        make(map[string]int),
		valueToPlaceholder: make(map[string]string),
		placeholderToValue: make(map[string]string),
	}
}

// PlaceholderFor returns the placeholder for a given plaintext value and
// entity type, creating a new one if the value hasn't been seen before.
func (g *PlaceholderGenerator) PlaceholderFor(value, entityType string) string {
	g.mu.Lock()
	defer g.mu.Unlock()

	if ph, ok := g.valueToPlaceholder[value]; ok {
		return ph
	}
	label := labelForEntity(entityType)
	g.labelCounts[label]++
	ph := "<" + label + "_" + strconv.Itoa(g.labelCounts[label]) + ">"
	g.valueToPlaceholder[value] = ph
	g.placeholderToValue[ph] = value
	return ph
}

// Lookup returns the plaintext for a placeholder, or "" if unknown. Its
// signature matches the lookup function expected by the restore package.
func (g *PlaceholderGenerator) Lookup(placeholder string) (string, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	v, ok := g.placeholderToValue[placeholder]
	return v, ok
}
