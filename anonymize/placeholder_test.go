package anonymize

import (
	"testing"
)

func TestPlaceholderGeneration(t *testing.T) {
	g := NewPlaceholderGenerator()

	// Identical values share a placeholder.
	ph1 := g.PlaceholderFor("John Smith", "PERSON")
	ph2 := g.PlaceholderFor("John Smith", "PERSON")
	if ph1 != ph2 {
		t.Fatalf("expected identical placeholders for identical values, got %q and %q", ph1, ph2)
	}
	if ph1 != "<Name_1>" {
		t.Fatalf("expected <Name_1>, got %q", ph1)
	}

	// Different values get different placeholders.
	ph3 := g.PlaceholderFor("Jane Doe", "PERSON")
	if ph3 == ph1 {
		t.Fatalf("expected different placeholders for different values")
	}
	if ph3 != "<Name_2>" {
		t.Fatalf("expected <Name_2>, got %q", ph3)
	}

	// Different entity types use different labels.
	ph4 := g.PlaceholderFor("555-1234", "PHONE_NUMBER")
	if ph4 != "<Phone_1>" {
		t.Fatalf("expected <Phone_1>, got %q", ph4)
	}
}

func TestPlaceholderLookup(t *testing.T) {
	g := NewPlaceholderGenerator()
	g.PlaceholderFor("secret@example.com", "EMAIL_ADDRESS")

	if v, ok := g.Lookup("<Email_1>"); !ok || v != "secret@example.com" {
		t.Fatalf("expected lookup to return secret@example.com, got %q (ok=%v)", v, ok)
	}
	if _, ok := g.Lookup("<Unknown_1>"); ok {
		t.Fatalf("expected unknown placeholder to not be found")
	}
}

func TestPlaceholderFormatBounded(t *testing.T) {
	g := NewPlaceholderGenerator()
	// A very long entity type should be sanitized and capped.
	ph := g.PlaceholderFor("value", "A_VERY_LONG_ENTITY_TYPE_THAT_EXCEEDS_THE_LIMIT_1234567890")
	if len(ph) > MaxPlaceholderLen {
		t.Fatalf("placeholder %q exceeds max length %d", ph, MaxPlaceholderLen)
	}
	if !CompletePlaceholder.MatchString(ph) {
		t.Fatalf("placeholder %q does not match complete format", ph)
	}
}

func TestViablePrefix(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"<", true},
		{"<Na", true},
		{"<Name_", true},
		{"<Name_1", true},
		// A complete placeholder also matches ViablePrefix (the regex has an
		// optional '>'). The hold-back logic checks CompletePlaceholder first
		// and skips complete placeholders, so this is correct behavior.
		{"<Name_1>", true},
		{"hello", false},
		{"<Name_1>extra", false},
	}
	for _, c := range cases {
		got := ViablePrefix.MatchString(c.in)
		if got != c.want {
			t.Errorf("ViablePrefix(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
