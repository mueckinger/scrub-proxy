package secrets

import "math"

// ShannonEntropy returns the Shannon entropy of s in bits per byte. It is
// used as a quality gate on regex matches: random-looking secrets score
// high (approaching log2 of the alphabet size), repeated or dictionary-like
// strings score low.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var e float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}
