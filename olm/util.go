package olm

import (
	"github.com/fosrl/olm/peers"
)

// slicesEqual compares two string slices for equality (order-independent)
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	// Create a map to count occurrences in slice a
	counts := make(map[string]int)
	for _, v := range a {
		counts[v]++
	}
	// Check if slice b has the same elements
	for _, v := range b {
		counts[v]--
		if counts[v] < 0 {
			return false
		}
	}
	return true
}

// aliasesEqual compares two Alias slices for equality (order-independent)
func aliasesEqual(a, b []peers.Alias) bool {
	if len(a) != len(b) {
		return false
	}
	// Create a map to count occurrences in slice a (using alias+address as key)
	counts := make(map[string]int)
	for _, v := range a {
		key := v.Alias + "|" + v.AliasAddress
		counts[key]++
	}
	// Check if slice b has the same elements
	for _, v := range b {
		key := v.Alias + "|" + v.AliasAddress
		counts[key]--
		if counts[key] < 0 {
			return false
		}
	}
	return true
}
