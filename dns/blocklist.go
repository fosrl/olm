package dns

import (
	"bufio"
	"io"
	"slices"
	"strings"
)

const (
	fnvOffset64 = 14695981039346656037
	fnvPrime64  = 1099511628211

	// maxBlocklistLine bounds a single line when loading, so a malformed
	// payload can't make the scanner buffer grow without limit.
	maxBlocklistLine = 4096
)

// Blocklist is an immutable set of blocked domain names. A name is blocked when
// it, or any parent domain of it, is in the set, so "example.com" also blocks
// "www.example.com".
//
// Entries are stored as sorted 64-bit FNV-1a hashes of the lowercase name
// rather than as strings. That costs 8 bytes per domain (about 4 MB for 500k
// domains), which matters in memory-constrained hosts such as the iOS network
// extension, and lookups need no allocation. A hash collision would block one
// unrelated name; with a 64-bit hash and a list this size that is not a
// practical concern.
type Blocklist struct {
	hashes []uint64
}

// NewBlocklist builds a Blocklist from domain names.
func NewBlocklist(domains []string) *Blocklist {
	hashes := make([]uint64, 0, len(domains))
	for _, d := range domains {
		if h, ok := hashEntry(d); ok {
			hashes = append(hashes, h)
		}
	}
	return finishBlocklist(hashes)
}

// LoadBlocklist reads newline separated domain names from r. Blank lines and
// lines starting with '#' are ignored.
func LoadBlocklist(r io.Reader) (*Blocklist, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, maxBlocklistLine), maxBlocklistLine)

	var hashes []uint64
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		if h, ok := hashEntry(line); ok {
			hashes = append(hashes, h)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return finishBlocklist(hashes), nil
}

func finishBlocklist(hashes []uint64) *Blocklist {
	slices.Sort(hashes)
	hashes = slices.Compact(hashes)
	// Drop the spare capacity left over from appending.
	return &Blocklist{hashes: slices.Clip(hashes)}
}

// Len returns the number of distinct entries.
func (b *Blocklist) Len() int {
	if b == nil {
		return 0
	}
	return len(b.hashes)
}

// Blocked reports whether name, or one of its parent domains, is in the list.
// A trailing dot and letter case are ignored. A single-label parent such as a
// bare TLD is never checked, so one stray "com" entry cannot block everything.
func (b *Blocklist) Blocked(name string) bool {
	if b == nil || len(b.hashes) == 0 {
		return false
	}
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 {
		return false
	}

	// Check the full name, then each suffix that starts after a dot, stopping
	// before the last label.
	for i := 0; i < len(name); i++ {
		if i != 0 && name[i-1] != '.' {
			continue
		}
		suffix := name[i:]
		if strings.IndexByte(suffix, '.') < 0 {
			return false
		}
		if _, found := slices.BinarySearch(b.hashes, hashLower(suffix)); found {
			return true
		}
	}
	return false
}

// hashEntry normalizes a list entry and hashes it. Entries without a dot
// (single labels, "localhost") are skipped.
func hashEntry(entry string) (uint64, bool) {
	entry = strings.TrimSuffix(strings.TrimSpace(entry), ".")
	if entry == "" || len(entry) > 253 || strings.IndexByte(entry, '.') < 0 {
		return 0, false
	}
	return hashLower(entry), true
}

// hashLower returns the FNV-1a 64-bit hash of s with ASCII letters lowercased.
func hashLower(s string) uint64 {
	h := uint64(fnvOffset64)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		h ^= uint64(c)
		h *= fnvPrime64
	}
	return h
}
