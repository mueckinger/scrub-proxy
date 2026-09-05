package main

import (
	"testing"

	"scrub-proxy/secrets"
)

// TestDefaultGitleaksConfigLoads verifies that the embedded default rule set
// parses, compiles with stdlib regexp, and detects real credential formats.
func TestDefaultGitleaksConfigLoads(t *testing.T) {
	s, err := secrets.NewScanner("", defaultGitleaksConfig)
	if err != nil {
		t.Fatalf("NewScanner with embedded default config: %v", err)
	}

	// Note: fixtures must not contain the alphabet sequence — it is a stopword
	// in the default config's global allowlist.
	text := "aws_key=AKIAQ4NDKL7B3MVPX2RO github=ghp_Jk7Qz3Vb9Nm2Xw5Rt8Yp1Lc4Hf6Sd0GqAeBk"
	findings := s.Scan(text)
	ids := map[string]secrets.Finding{}
	for _, f := range findings {
		ids[f.RuleID] = f
	}
	for _, want := range []string{"aws-access-token", "github-pat"} {
		f, ok := ids[want]
		if !ok {
			t.Errorf("expected rule %q to match, got %v", want, ids)
			continue
		}
		if text[f.Start:f.End] != f.Secret {
			t.Errorf("rule %q offsets [%d,%d) slice %q != secret %q",
				want, f.Start, f.End, text[f.Start:f.End], f.Secret)
		}
	}
}
