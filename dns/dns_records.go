package dns

import (
	"fmt"
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
	RecordTypePTR  RecordType = RecordType(dns.TypePTR)
)

// recordSet holds A and AAAA records for a single domain or wildcard pattern
type recordSet struct {
	A    []net.IP
	AAAA []net.IP
}

// domainTrieNode is a node in the trie for exact domain lookups (no wildcards in path)
type domainTrieNode struct {
	children map[string]*domainTrieNode
	data     *recordSet
}

// DNSRecordStore manages local DNS records for A, AAAA, and PTR queries.
// Exact domains are stored in a trie for O(label count) lookup; wildcard patterns
// are in a separate map. Each domain/pattern has a single recordSet (A + AAAA).
type DNSRecordStore struct {
	mu         sync.RWMutex
	root       *domainTrieNode       // trie root for exact lookups
	wildcards  map[string]*recordSet // wildcard pattern -> A/AAAA records
	ptrRecords map[string]string     // IP address string -> domain name
}

// domainToPath converts a FQDN to a trie path (reversed labels, e.g. "host.internal." -> ["internal", "host"])
func domainToPath(domain string) []string {
	domain = strings.ToLower(dns.Fqdn(domain))
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return nil
	}
	labels := strings.Split(domain, ".")
	path := make([]string, 0, len(labels))
	for i := len(labels) - 1; i >= 0; i-- {
		path = append(path, labels[i])
	}
	return path
}

// NewDNSRecordStore creates a new DNS record store
func NewDNSRecordStore() *DNSRecordStore {
	return &DNSRecordStore{
		root:       &domainTrieNode{children: make(map[string]*domainTrieNode)},
		wildcards:  make(map[string]*recordSet),
		ptrRecords: make(map[string]string),
	}
}

// AddRecord adds a DNS record mapping (A or AAAA)
// domain should be in FQDN format (e.g., "example.com.")
// domain can contain wildcards: * (0+ chars) and ? (exactly 1 char)
// ip should be a valid IPv4 or IPv6 address
// Automatically adds a corresponding PTR record for non-wildcard domains
func (s *DNSRecordStore) AddRecord(domain string, ip net.IP) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(domain) == 0 || domain[len(domain)-1] != '.' {
		domain = domain + "."
	}
	domain = strings.ToLower(dns.Fqdn(domain))
	isWildcard := strings.ContainsAny(domain, "*?")

	isV4 := ip.To4() != nil
	if !isV4 && ip.To16() == nil {
		return &net.ParseError{Type: "IP address", Text: ip.String()}
	}

	if isWildcard {
		if s.wildcards[domain] == nil {
			s.wildcards[domain] = &recordSet{}
		}
		rs := s.wildcards[domain]
		if isV4 {
			rs.A = append(rs.A, ip)
		} else {
			rs.AAAA = append(rs.AAAA, ip)
		}
		return nil
	}

	path := domainToPath(domain)
	node := s.root
	for _, label := range path {
		if node.children[label] == nil {
			node.children[label] = &domainTrieNode{children: make(map[string]*domainTrieNode)}
		}
		node = node.children[label]
	}
	if node.data == nil {
		node.data = &recordSet{}
	}
	if isV4 {
		node.data.A = append(node.data.A, ip)
	} else {
		node.data.AAAA = append(node.data.AAAA, ip)
	}
	s.ptrRecords[ip.String()] = domain
	return nil
}

// AddPTRRecord adds a PTR record mapping an IP address to a domain name
// ip should be a valid IPv4 or IPv6 address
// domain should be in FQDN format (e.g., "example.com.")
func (s *DNSRecordStore) AddPTRRecord(ip net.IP, domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Ensure domain ends with a dot (FQDN format)
	if len(domain) == 0 || domain[len(domain)-1] != '.' {
		domain = domain + "."
	}

	// Normalize domain to lowercase FQDN
	domain = strings.ToLower(dns.Fqdn(domain))

	// Store PTR record using IP string as key
	s.ptrRecords[ip.String()] = domain

	return nil
}

// RemoveRecord removes a specific DNS record mapping
// If ip is nil, removes all records for the domain (including wildcards)
// Automatically removes corresponding PTR records for non-wildcard domains
func (s *DNSRecordStore) RemoveRecord(domain string, ip net.IP) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(domain) == 0 || domain[len(domain)-1] != '.' {
		domain = domain + "."
	}
	domain = strings.ToLower(dns.Fqdn(domain))
	isWildcard := strings.ContainsAny(domain, "*?")

	if isWildcard {
		if ip == nil {
			delete(s.wildcards, domain)
			return
		}
		rs := s.wildcards[domain]
		if rs == nil {
			return
		}
		if ip.To4() != nil {
			rs.A = removeIP(rs.A, ip)
		} else {
			rs.AAAA = removeIP(rs.AAAA, ip)
		}
		if len(rs.A) == 0 && len(rs.AAAA) == 0 {
			delete(s.wildcards, domain)
		}
		return
	}

	// Exact domain: find trie node
	path := domainToPath(domain)
	node := s.root
	for _, label := range path {
		node = node.children[label]
		if node == nil {
			return
		}
	}
	if node.data == nil {
		return
	}

	if ip == nil {
		for _, ipAddr := range node.data.A {
			if ptrDomain, exists := s.ptrRecords[ipAddr.String()]; exists && ptrDomain == domain {
				delete(s.ptrRecords, ipAddr.String())
			}
		}
		for _, ipAddr := range node.data.AAAA {
			if ptrDomain, exists := s.ptrRecords[ipAddr.String()]; exists && ptrDomain == domain {
				delete(s.ptrRecords, ipAddr.String())
			}
		}
		node.data = nil
		return
	}

	if ip.To4() != nil {
		node.data.A = removeIP(node.data.A, ip)
		if ptrDomain, exists := s.ptrRecords[ip.String()]; exists && ptrDomain == domain {
			delete(s.ptrRecords, ip.String())
		}
	} else {
		node.data.AAAA = removeIP(node.data.AAAA, ip)
		if ptrDomain, exists := s.ptrRecords[ip.String()]; exists && ptrDomain == domain {
			delete(s.ptrRecords, ip.String())
		}
	}
	if len(node.data.A) == 0 && len(node.data.AAAA) == 0 {
		node.data = nil
	}
}

// RemovePTRRecord removes a PTR record for an IP address
func (s *DNSRecordStore) RemovePTRRecord(ip net.IP) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.ptrRecords, ip.String())
}

// GetRecords returns all IP addresses for a domain and record type
// First checks for exact match in the trie, then wildcard patterns
func (s *DNSRecordStore) GetRecords(domain string, recordType RecordType) []net.IP {
	s.mu.RLock()
	defer s.mu.RUnlock()

	domain = strings.ToLower(dns.Fqdn(domain))
	path := domainToPath(domain)

	// Exact match: walk trie
	node := s.root
	for _, label := range path {
		node = node.children[label]
		if node == nil {
			break
		}
	}
	if node != nil && node.data != nil {
		var ips []net.IP
		if recordType == RecordTypeA {
			ips = node.data.A
		} else {
			ips = node.data.AAAA
		}
		if len(ips) > 0 {
			out := make([]net.IP, len(ips))
			copy(out, ips)
			return out
		}
	}

	// Wildcard match
	var records []net.IP
	for pattern, rs := range s.wildcards {
		if !matchWildcard(pattern, domain) {
			continue
		}
		if recordType == RecordTypeA {
			records = append(records, rs.A...)
		} else {
			records = append(records, rs.AAAA...)
		}
	}
	if len(records) == 0 {
		return nil
	}
	out := make([]net.IP, len(records))
	copy(out, records)
	return out
}

// GetPTRRecord returns the domain name for a PTR record query
// domain should be in reverse DNS format (e.g., "1.0.0.127.in-addr.arpa.")
func (s *DNSRecordStore) GetPTRRecord(domain string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Convert reverse DNS format to IP address
	ip := reverseDNSToIP(domain)
	if ip == nil {
		return "", false
	}

	// Look up the PTR record
	if ptrDomain, ok := s.ptrRecords[ip.String()]; ok {
		return ptrDomain, true
	}

	return "", false
}

// HasRecord checks if a domain has any records of the specified type
// Checks both exact matches (trie) and wildcard patterns
func (s *DNSRecordStore) HasRecord(domain string, recordType RecordType) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	domain = strings.ToLower(dns.Fqdn(domain))
	path := domainToPath(domain)

	node := s.root
	for _, label := range path {
		node = node.children[label]
		if node == nil {
			break
		}
	}
	if node != nil && node.data != nil {
		if recordType == RecordTypeA && len(node.data.A) > 0 {
			return true
		}
		if recordType == RecordTypeAAAA && len(node.data.AAAA) > 0 {
			return true
		}
	}

	for pattern, rs := range s.wildcards {
		if !matchWildcard(pattern, domain) {
			continue
		}
		if recordType == RecordTypeA && len(rs.A) > 0 {
			return true
		}
		if recordType == RecordTypeAAAA && len(rs.AAAA) > 0 {
			return true
		}
	}
	return false
}

// HasPTRRecord checks if a PTR record exists for the given reverse DNS domain
func (s *DNSRecordStore) HasPTRRecord(domain string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Convert reverse DNS format to IP address
	ip := reverseDNSToIP(domain)
	if ip == nil {
		return false
	}

	_, ok := s.ptrRecords[ip.String()]
	return ok
}

// Clear removes all records from the store
func (s *DNSRecordStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.root = &domainTrieNode{children: make(map[string]*domainTrieNode)}
	s.wildcards = make(map[string]*recordSet)
	s.ptrRecords = make(map[string]string)
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

// reverseDNSToIP converts a reverse DNS query name to an IP address
// Supports both IPv4 (in-addr.arpa) and IPv6 (ip6.arpa) formats
func reverseDNSToIP(domain string) net.IP {
	// Normalize to lowercase and ensure FQDN
	domain = strings.ToLower(dns.Fqdn(domain))

	// Check for IPv4 reverse DNS (in-addr.arpa)
	if strings.HasSuffix(domain, ".in-addr.arpa.") {
		// Remove the suffix
		ipPart := strings.TrimSuffix(domain, ".in-addr.arpa.")
		// Split by dots and reverse
		parts := strings.Split(ipPart, ".")
		if len(parts) != 4 {
			return nil
		}
		// Reverse the octets
		reversed := make([]string, 4)
		for i := 0; i < 4; i++ {
			reversed[i] = parts[3-i]
		}
		// Parse as IP
		return net.ParseIP(strings.Join(reversed, "."))
	}

	// Check for IPv6 reverse DNS (ip6.arpa)
	if strings.HasSuffix(domain, ".ip6.arpa.") {
		// Remove the suffix
		ipPart := strings.TrimSuffix(domain, ".ip6.arpa.")
		// Split by dots and reverse
		parts := strings.Split(ipPart, ".")
		if len(parts) != 32 {
			return nil
		}
		// Reverse the nibbles and group into 16-bit hex values
		reversed := make([]string, 32)
		for i := 0; i < 32; i++ {
			reversed[i] = parts[31-i]
		}
		// Join into IPv6 format (groups of 4 nibbles separated by colons)
		var ipv6Parts []string
		for i := 0; i < 32; i += 4 {
			ipv6Parts = append(ipv6Parts, reversed[i]+reversed[i+1]+reversed[i+2]+reversed[i+3])
		}
		// Parse as IP
		return net.ParseIP(strings.Join(ipv6Parts, ":"))
	}

	return nil
}

// IPToReverseDNS converts an IP address to reverse DNS format
// Returns the domain name for PTR queries (e.g., "1.0.0.127.in-addr.arpa.")
func IPToReverseDNS(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		// IPv4: reverse octets and append .in-addr.arpa.
		return dns.Fqdn(fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa",
			ip4[3], ip4[2], ip4[1], ip4[0]))
	}

	if ip6 := ip.To16(); ip6 != nil && ip.To4() == nil {
		// IPv6: expand to 32 nibbles, reverse, and append .ip6.arpa.
		var nibbles []string
		for i := 15; i >= 0; i-- {
			nibbles = append(nibbles, fmt.Sprintf("%x", ip6[i]&0x0f))
			nibbles = append(nibbles, fmt.Sprintf("%x", ip6[i]>>4))
		}
		return dns.Fqdn(strings.Join(nibbles, ".") + ".ip6.arpa")
	}

	return ""
}
