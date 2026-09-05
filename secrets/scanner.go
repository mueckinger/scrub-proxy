package secrets

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// Scanner detects secrets in a text and returns findings with byte offsets.
// It is satisfied by *RuleScanner and can be mocked in tests.
type Scanner interface {
	Scan(text string) []Finding
}

// gkRule is the subset of a gitleaks TOML rule that this scanner uses.
type gkRule struct {
	ID          string   `toml:"id"`
	Regex       string   `toml:"regex"`
	SecretGroup int      `toml:"secretGroup"`
	Entropy     float64  `toml:"entropy"`
	Keywords    []string `toml:"keywords"`
	Path        string   `toml:"path"`
}

// gkAllowlist is the subset of a gitleaks TOML allowlist that this scanner
// uses.
type gkAllowlist struct {
	Regexes   []string `toml:"regexes"`
	Stopwords []string `toml:"stopwords"`
}

// gkConfig is the subset of a gitleaks TOML config that this scanner uses.
type gkConfig struct {
	Allowlist gkAllowlist `toml:"allowlist"`
	Rules     []gkRule    `toml:"rules"`
}

// compiledRule is a gitleaks rule with its regex pre-compiled.
type compiledRule struct {
	id       string
	re       *regexp.Regexp
	group    int // capture group holding the secret; 0 = whole match
	entropy  float64
	keywords []string
}

// RuleScanner scans text for secrets using gitleaks TOML rules compiled with
// the standard library regexp package (gitleaks rules are RE2-compatible).
type RuleScanner struct {
	rules     []compiledRule
	allowRe   []*regexp.Regexp
	stopwords []string
}

// NewScanner builds a scanner from a gitleaks TOML config file. If configPath
// is empty, defaultConfig (the embedded default rule set) is used. It returns
// an error if the config cannot be read or parsed.
func NewScanner(configPath string, defaultConfig []byte) (*RuleScanner, error) {
	raw := defaultConfig
	if configPath != "" {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("read gitleaks config %q: %w", configPath, err)
		}
		raw = data
	}

	var cfg gkConfig
	if err := toml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse gitleaks config: %w", err)
	}

	s := &RuleScanner{stopwords: cfg.Allowlist.Stopwords}
	for _, a := range cfg.Allowlist.Regexes {
		re, err := regexp.Compile(a)
		if err != nil {
			// ponytail: skip unparsable allowlist regex, revisit if one appears
			continue
		}
		s.allowRe = append(s.allowRe, re)
	}

	for _, r := range cfg.Rules {
		// ponytail: path rules only apply to file scanning, never match on
		// request bodies; skip them like gitleaks does for pathless fragments.
		if r.Path != "" {
			continue
		}
		re, err := regexp.Compile(r.Regex)
		if err != nil {
			// ponytail: rules needing RE2 extensions (lookarounds etc.) are
			// skipped; the default config has none. Revisit if one appears.
			continue
		}
		group := r.SecretGroup
		if group < 0 || group > re.NumSubexp() {
			group = 0
		}
		s.rules = append(s.rules, compiledRule{
			id:       r.ID,
			re:       re,
			group:    group,
			entropy:  r.Entropy,
			keywords: r.Keywords,
		})
	}

	if len(s.rules) == 0 {
		return nil, fmt.Errorf("gitleaks config contains no usable rules")
	}
	return s, nil
}

// Scan runs every compiled rule over the text and returns findings with byte
// offsets of the captured secret. Matches below a rule's entropy threshold or
// matching the global allowlist are discarded.
func (s *RuleScanner) Scan(text string) []Finding {
	// Keyword prefilter: gitleaks keywords are lowercase literals.
	lower := strings.ToLower(text)

	var out []Finding
	for _, r := range s.rules {
		if len(r.keywords) > 0 && !containsAny(lower, r.keywords) {
			continue
		}
		for _, loc := range r.re.FindAllStringSubmatchIndex(text, -1) {
			start, end := loc[2*r.group], loc[2*r.group+1]
			if start < 0 || start >= end {
				continue
			}
			secret := text[start:end]
			entropy := ShannonEntropy(secret)
			if r.entropy > 0 && entropy < r.entropy {
				continue
			}
			if s.allowlisted(secret) {
				continue
			}
			out = append(out, Finding{
				RuleID:  r.id,
				Start:   start,
				End:     end,
				Secret:  secret,
				Entropy: float32(entropy),
			})
		}
	}
	return out
}

// allowlisted reports whether the secret matches the global allowlist regexes
// or contains a stopword.
// ponytail: applied to the captured secret only; gitleaks can also target the
// full match. Upgrade path: add a regexTarget field to gkAllowlist.
func (s *RuleScanner) allowlisted(secret string) bool {
	for _, sw := range s.stopwords {
		if strings.Contains(strings.ToLower(secret), sw) {
			return true
		}
	}
	for _, re := range s.allowRe {
		if re.MatchString(secret) {
			return true
		}
	}
	return false
}

// containsAny reports whether s contains any of the given lowercase keywords.
func containsAny(s string, keywords []string) bool {
	for _, kw := range keywords {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}
