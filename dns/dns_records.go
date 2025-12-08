package dns

import (
	"net"
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
	mu          sync.RWMutex
	aRecords    map[string][]net.IP // domain -> list of IPv4 addresses
	aaaaRecords map[string][]net.IP // domain -> list of IPv6 addresses
}

// NewDNSRecordStore creates a new DNS record store
func NewDNSRecordStore() *DNSRecordStore {
	return &DNSRecordStore{
		aRecords:    make(map[string][]net.IP),
		aaaaRecords: make(map[string][]net.IP),
	}
}

// AddRecord adds a DNS record mapping (A or AAAA)
// domain should be in FQDN format (e.g., "example.com.")
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

	if ip.To4() != nil {
		// IPv4 address
		s.aRecords[domain] = append(s.aRecords[domain], ip)
	} else if ip.To16() != nil {
		// IPv6 address
		s.aaaaRecords[domain] = append(s.aaaaRecords[domain], ip)
	} else {
		return &net.ParseError{Type: "IP address", Text: ip.String()}
	}

	return nil
}

// RemoveRecord removes a specific DNS record mapping
// If ip is nil, removes all records for the domain
func (s *DNSRecordStore) RemoveRecord(domain string, ip net.IP) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Ensure domain ends with a dot (FQDN format)
	if len(domain) == 0 || domain[len(domain)-1] != '.' {
		domain = domain + "."
	}

	// Normalize domain to lowercase
	domain = dns.Fqdn(domain)

	if ip == nil {
		// Remove all records for this domain
		delete(s.aRecords, domain)
		delete(s.aaaaRecords, domain)
		return
	}

	if ip.To4() != nil {
		// Remove specific IPv4 address
		if ips, ok := s.aRecords[domain]; ok {
			s.aRecords[domain] = removeIP(ips, ip)
			if len(s.aRecords[domain]) == 0 {
				delete(s.aRecords, domain)
			}
		}
	} else if ip.To16() != nil {
		// Remove specific IPv6 address
		if ips, ok := s.aaaaRecords[domain]; ok {
			s.aaaaRecords[domain] = removeIP(ips, ip)
			if len(s.aaaaRecords[domain]) == 0 {
				delete(s.aaaaRecords, domain)
			}
		}
	}
}

// GetRecords returns all IP addresses for a domain and record type
func (s *DNSRecordStore) GetRecords(domain string, recordType RecordType) []net.IP {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Normalize domain to lowercase FQDN
	domain = dns.Fqdn(domain)

	var records []net.IP
	switch recordType {
	case RecordTypeA:
		if ips, ok := s.aRecords[domain]; ok {
			// Return a copy to prevent external modifications
			records = make([]net.IP, len(ips))
			copy(records, ips)
		}
	case RecordTypeAAAA:
		if ips, ok := s.aaaaRecords[domain]; ok {
			// Return a copy to prevent external modifications
			records = make([]net.IP, len(ips))
			copy(records, ips)
		}
	}

	return records
}

// HasRecord checks if a domain has any records of the specified type
func (s *DNSRecordStore) HasRecord(domain string, recordType RecordType) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Normalize domain to lowercase FQDN
	domain = dns.Fqdn(domain)

	switch recordType {
	case RecordTypeA:
		_, ok := s.aRecords[domain]
		return ok
	case RecordTypeAAAA:
		_, ok := s.aaaaRecords[domain]
		return ok
	}

	return false
}

// Clear removes all records from the store
func (s *DNSRecordStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.aRecords = make(map[string][]net.IP)
	s.aaaaRecords = make(map[string][]net.IP)
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
