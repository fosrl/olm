package dns

import (
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// RecordType represents the type of DNS record
type RecordType uint16

const (
	RecordTypeA    RecordType = RecordType(dns.TypeA)
	RecordTypeAAAA RecordType = RecordType(dns.TypeAAAA)
)

// DNSRecordStore manages local DNS records for A and AAAA queries
type DNSRecordStore struct {
	mu            sync.RWMutex
	aRecords      map[string][]net.IP // domain -> list of IPv4 addresses
	aaaaRecords   map[string][]net.IP // domain -> list of IPv6 addresses
	aWildcards    map[string][]net.IP // wildcard pattern -> list of IPv4 addresses
	aaaaWildcards map[string][]net.IP // wildcard pattern -> list of IPv6 addresses
}

// NewDNSRecordStore creates a new DNS record store
func NewDNSRecordStore() *DNSRecordStore {
	return &DNSRecordStore{
		aRecords:      make(map[string][]net.IP),
		aaaaRecords:   make(map[string][]net.IP),
		aWildcards:    make(map[string][]net.IP),
		aaaaWildcards: make(map[string][]net.IP),
	}
}

// AddRecord adds a DNS record mapping (A or AAAA)
// domain should be in FQDN format (e.g., "example.com.")
// domain can contain wildcards: * (0+ chars) and ? (exactly 1 char)
// ip should be a valid IPv4 or IPv6 address
func (s *DNSRecordStore) AddRecord(domain string, ip net.IP) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Ensure domain ends with a dot (FQDN format)
	if len(domain) == 0 || domain[len(domain)-1] != '.' {
		domain = domain + "."
	}

	// Normalize domain to lowercase
	domain = dns.Fqdn(domain)

	// Check if domain contains wildcards
	isWildcard := strings.ContainsAny(domain, "*?")

	if ip.To4() != nil {
		// IPv4 address
		if isWildcard {
			s.aWildcards[domain] = append(s.aWildcards[domain], ip)
		} else {
			s.aRecords[domain] = append(s.aRecords[domain], ip)
		}
	} else if ip.To16() != nil {
		// IPv6 address
		if isWildcard {
			s.aaaaWildcards[domain] = append(s.aaaaWildcards[domain], ip)
		} else {
			s.aaaaRecords[domain] = append(s.aaaaRecords[domain], ip)
		}
	} else {
		return &net.ParseError{Type: "IP address", Text: ip.String()}
	}

	return nil
}

// RemoveRecord removes a specific DNS record mapping
// If ip is nil, removes all records for the domain (including wildcards)
func (s *DNSRecordStore) RemoveRecord(domain string, ip net.IP) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Ensure domain ends with a dot (FQDN format)
	if len(domain) == 0 || domain[len(domain)-1] != '.' {
		domain = domain + "."
	}

	// Normalize domain to lowercase
	domain = dns.Fqdn(domain)

	// Check if domain contains wildcards
	isWildcard := strings.ContainsAny(domain, "*?")

	if ip == nil {
		// Remove all records for this domain
		if isWildcard {
			delete(s.aWildcards, domain)
			delete(s.aaaaWildcards, domain)
		} else {
			delete(s.aRecords, domain)
			delete(s.aaaaRecords, domain)
		}
		return
	}

	if ip.To4() != nil {
		// Remove specific IPv4 address
		if isWildcard {
			if ips, ok := s.aWildcards[domain]; ok {
				s.aWildcards[domain] = removeIP(ips, ip)
				if len(s.aWildcards[domain]) == 0 {
					delete(s.aWildcards, domain)
				}
			}
		} else {
			if ips, ok := s.aRecords[domain]; ok {
				s.aRecords[domain] = removeIP(ips, ip)
				if len(s.aRecords[domain]) == 0 {
					delete(s.aRecords, domain)
				}
			}
		}
	} else if ip.To16() != nil {
		// Remove specific IPv6 address
		if isWildcard {
			if ips, ok := s.aaaaWildcards[domain]; ok {
				s.aaaaWildcards[domain] = removeIP(ips, ip)
				if len(s.aaaaWildcards[domain]) == 0 {
					delete(s.aaaaWildcards, domain)
				}
			}
		} else {
			if ips, ok := s.aaaaRecords[domain]; ok {
				s.aaaaRecords[domain] = removeIP(ips, ip)
				if len(s.aaaaRecords[domain]) == 0 {
					delete(s.aaaaRecords, domain)
				}
			}
		}
	}
}

// GetRecords returns all IP addresses for a domain and record type
// First checks for exact matches, then checks wildcard patterns
func (s *DNSRecordStore) GetRecords(domain string, recordType RecordType) []net.IP {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Normalize domain to lowercase FQDN
	domain = dns.Fqdn(domain)

	var records []net.IP
	switch recordType {
	case RecordTypeA:
		// Check exact match first
		if ips, ok := s.aRecords[domain]; ok {
			// Return a copy to prevent external modifications
			records = make([]net.IP, len(ips))
			copy(records, ips)
			return records
		}
		// Check wildcard patterns
		for pattern, ips := range s.aWildcards {
			if matchWildcard(pattern, domain) {
				records = append(records, ips...)
			}
		}
		if len(records) > 0 {
			// Return a copy
			result := make([]net.IP, len(records))
			copy(result, records)
			return result
		}

	case RecordTypeAAAA:
		// Check exact match first
		if ips, ok := s.aaaaRecords[domain]; ok {
			// Return a copy to prevent external modifications
			records = make([]net.IP, len(ips))
			copy(records, ips)
			return records
		}
		// Check wildcard patterns
		for pattern, ips := range s.aaaaWildcards {
			if matchWildcard(pattern, domain) {
				records = append(records, ips...)
			}
		}
		if len(records) > 0 {
			// Return a copy
			result := make([]net.IP, len(records))
			copy(result, records)
			return result
		}
	}

	return records
}

// HasRecord checks if a domain has any records of the specified type
// Checks both exact matches and wildcard patterns
func (s *DNSRecordStore) HasRecord(domain string, recordType RecordType) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Normalize domain to lowercase FQDN
	domain = dns.Fqdn(domain)

	switch recordType {
	case RecordTypeA:
		// Check exact match
		if _, ok := s.aRecords[domain]; ok {
			return true
		}
		// Check wildcard patterns
		for pattern := range s.aWildcards {
			if matchWildcard(pattern, domain) {
				return true
			}
		}
	case RecordTypeAAAA:
		// Check exact match
		if _, ok := s.aaaaRecords[domain]; ok {
			return true
		}
		// Check wildcard patterns
		for pattern := range s.aaaaWildcards {
			if matchWildcard(pattern, domain) {
				return true
			}
		}
	}

	return false
}

// Clear removes all records from the store
func (s *DNSRecordStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.aRecords = make(map[string][]net.IP)
	s.aaaaRecords = make(map[string][]net.IP)
	s.aWildcards = make(map[string][]net.IP)
	s.aaaaWildcards = make(map[string][]net.IP)
}

// removeIP is a helper function to remove a specific IP from a slice
func removeIP(ips []net.IP, toRemove net.IP) []net.IP {
	result := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if !ip.Equal(toRemove) {
			result = append(result, ip)
		}
	}
	return result
}

// matchWildcard checks if a domain matches a wildcard pattern
// Pattern supports * (0+ chars) and ? (exactly 1 char)
// Special case: *.domain.com does not match domain.com itself
func matchWildcard(pattern, domain string) bool {
	return matchWildcardInternal(pattern, domain, 0, 0)
}

// matchWildcardInternal performs the actual wildcard matching recursively
func matchWildcardInternal(pattern, domain string, pi, di int) bool {
	plen := len(pattern)
	dlen := len(domain)

	// Base cases
	if pi == plen && di == dlen {
		return true
	}
	if pi == plen {
		return false
	}

	// Handle wildcard characters
	if pattern[pi] == '*' {
		// Special case: if pattern starts with "*." and we're at the beginning,
		// ensure we don't match the domain without a prefix
		// e.g., *.autoco.internal should not match autoco.internal
		if pi == 0 && pi+1 < plen && pattern[pi+1] == '.' {
			// The * must match at least one character
			if di == dlen {
				return false
			}
			// Try matching 1 or more characters before the dot
			for i := di + 1; i <= dlen; i++ {
				if matchWildcardInternal(pattern, domain, pi+1, i) {
					return true
				}
			}
			return false
		}

		// Normal * matching (0 or more characters)
		// Try matching 0 characters (skip the *)
		if matchWildcardInternal(pattern, domain, pi+1, di) {
			return true
		}
		// Try matching 1+ characters
		if di < dlen {
			return matchWildcardInternal(pattern, domain, pi, di+1)
		}
		return false
	}

	if pattern[pi] == '?' {
		// ? matches exactly one character
		if di >= dlen {
			return false
		}
		return matchWildcardInternal(pattern, domain, pi+1, di+1)
	}

	// Regular character - must match exactly
	if di >= dlen || pattern[pi] != domain[di] {
		return false
	}

	return matchWildcardInternal(pattern, domain, pi+1, di+1)
}
