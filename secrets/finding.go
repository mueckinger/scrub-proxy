package secrets

// Finding is a single secret detection with byte offsets into the scanned
// text, so findings can be redacted by span.
type Finding struct {
	// RuleID is the rule that matched (e.g. "generic-api-key").
	RuleID string
	// Start is the byte offset of the start of the secret.
	Start int
	// End is the byte offset just past the end of the secret.
	End int
	// Secret is the captured secret value.
	Secret string
	// Entropy is the Shannon entropy of the secret.
	Entropy float32
}
