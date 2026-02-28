package dns

import (
	"net"
	"testing"
)

func TestWildcardMatching(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		domain   string
		expected bool
	}{
		// Basic wildcard tests
		{
			name:     "*.autoco.internal matches host.autoco.internal",
			pattern:  "*.autoco.internal.",
			domain:   "host.autoco.internal.",
			expected: true,
		},
		{
			name:     "*.autoco.internal matches longerhost.autoco.internal",
			pattern:  "*.autoco.internal.",
			domain:   "longerhost.autoco.internal.",
			expected: true,
		},
		{
			name:     "*.autoco.internal matches sub.host.autoco.internal",
			pattern:  "*.autoco.internal.",
			domain:   "sub.host.autoco.internal.",
			expected: true,
		},
		{
			name:     "*.autoco.internal does NOT match autoco.internal",
			pattern:  "*.autoco.internal.",
			domain:   "autoco.internal.",
			expected: false,
		},

		// Question mark wildcard tests
		{
			name:     "host-0?.autoco.internal matches host-01.autoco.internal",
			pattern:  "host-0?.autoco.internal.",
			domain:   "host-01.autoco.internal.",
			expected: true,
		},
		{
			name:     "host-0?.autoco.internal matches host-0a.autoco.internal",
			pattern:  "host-0?.autoco.internal.",
			domain:   "host-0a.autoco.internal.",
			expected: true,
		},
		{
			name:     "host-0?.autoco.internal does NOT match host-0.autoco.internal",
			pattern:  "host-0?.autoco.internal.",
			domain:   "host-0.autoco.internal.",
			expected: false,
		},
		{
			name:     "host-0?.autoco.internal does NOT match host-012.autoco.internal",
			pattern:  "host-0?.autoco.internal.",
			domain:   "host-012.autoco.internal.",
			expected: false,
		},

		// Combined wildcard tests
		{
			name:     "*.host-0?.autoco.internal matches sub.host-01.autoco.internal",
			pattern:  "*.host-0?.autoco.internal.",
			domain:   "sub.host-01.autoco.internal.",
			expected: true,
		},
		{
			name:     "*.host-0?.autoco.internal matches prefix.host-0a.autoco.internal",
			pattern:  "*.host-0?.autoco.internal.",
			domain:   "prefix.host-0a.autoco.internal.",
			expected: true,
		},
		{
			name:     "*.host-0?.autoco.internal does NOT match host-01.autoco.internal",
			pattern:  "*.host-0?.autoco.internal.",
			domain:   "host-01.autoco.internal.",
			expected: false,
		},

		// Multiple asterisks
		{
			name:     "*.*. autoco.internal matches any.thing.autoco.internal",
			pattern:  "*.*.autoco.internal.",
			domain:   "any.thing.autoco.internal.",
			expected: true,
		},
		{
			name:     "*.*.autoco.internal does NOT match single.autoco.internal",
			pattern:  "*.*.autoco.internal.",
			domain:   "single.autoco.internal.",
			expected: false,
		},

		// Asterisk in middle
		{
			name:     "host-*.autoco.internal matches host-anything.autoco.internal",
			pattern:  "host-*.autoco.internal.",
			domain:   "host-anything.autoco.internal.",
			expected: true,
		},
		{
			name:     "host-*.autoco.internal matches host-.autoco.internal (empty match)",
			pattern:  "host-*.autoco.internal.",
			domain:   "host-.autoco.internal.",
			expected: true,
		},

		// Multiple question marks
		{
			name:     "host-??.autoco.internal matches host-01.autoco.internal",
			pattern:  "host-??.autoco.internal.",
			domain:   "host-01.autoco.internal.",
			expected: true,
		},
		{
			name:     "host-??.autoco.internal does NOT match host-1.autoco.internal",
			pattern:  "host-??.autoco.internal.",
			domain:   "host-1.autoco.internal.",
			expected: false,
		},

		// Exact match (no wildcards)
		{
			name:     "exact.autoco.internal matches exact.autoco.internal",
			pattern:  "exact.autoco.internal.",
			domain:   "exact.autoco.internal.",
			expected: true,
		},
		{
			name:     "exact.autoco.internal does NOT match other.autoco.internal",
			pattern:  "exact.autoco.internal.",
			domain:   "other.autoco.internal.",
			expected: false,
		},

		// Edge cases
		{
			name:     "* matches anything",
			pattern:  "*",
			domain:   "anything.at.all.",
			expected: true,
		},
		{
			name:     "*.* matches multi.level.",
			pattern:  "*.*",
			domain:   "multi.level.",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchWildcard(tt.pattern, tt.domain)
			if result != tt.expected {
				t.Errorf("matchWildcard(%q, %q) = %v, want %v", tt.pattern, tt.domain, result, tt.expected)
			}
		})
	}
}

func TestDNSRecordStoreWildcard(t *testing.T) {
	store := NewDNSRecordStore()

	// Add wildcard records
	wildcardIP := net.ParseIP("10.0.0.1")
	err := store.AddRecord("*.autoco.internal", wildcardIP)
	if err != nil {
		t.Fatalf("Failed to add wildcard record: %v", err)
	}

	// Add exact record
	exactIP := net.ParseIP("10.0.0.2")
	err = store.AddRecord("exact.autoco.internal", exactIP)
	if err != nil {
		t.Fatalf("Failed to add exact record: %v", err)
	}

	// Test exact match takes precedence
	ips, exists := store.GetRecords("exact.autoco.internal.", RecordTypeA)
	if !exists {
		t.Error("Expected domain to exist")
	}
	if len(ips) != 1 {
		t.Errorf("Expected 1 IP for exact match, got %d", len(ips))
	}
	if len(ips) > 0 && !ips[0].Equal(exactIP) {
		t.Errorf("Expected exact IP %v, got %v", exactIP, ips[0])
	}

	// Test wildcard match
	ips, exists = store.GetRecords("host.autoco.internal.", RecordTypeA)
	if !exists {
		t.Error("Expected wildcard match to exist")
	}
	if len(ips) != 1 {
		t.Errorf("Expected 1 IP for wildcard match, got %d", len(ips))
	}
	if len(ips) > 0 && !ips[0].Equal(wildcardIP) {
		t.Errorf("Expected wildcard IP %v, got %v", wildcardIP, ips[0])
	}

	// Test non-match (base domain)
	ips, exists = store.GetRecords("autoco.internal.", RecordTypeA)
	if exists {
		t.Error("Expected base domain to not exist")
	}
	if len(ips) != 0 {
		t.Errorf("Expected 0 IPs for base domain, got %d", len(ips))
	}
}

func TestDNSRecordStoreComplexWildcard(t *testing.T) {
	store := NewDNSRecordStore()

	// Add complex wildcard pattern
	ip1 := net.ParseIP("10.0.0.1")
	err := store.AddRecord("*.host-0?.autoco.internal", ip1)
	if err != nil {
		t.Fatalf("Failed to add wildcard record: %v", err)
	}

	// Test matching domain
	ips, exists := store.GetRecords("sub.host-01.autoco.internal.", RecordTypeA)
	if !exists {
		t.Error("Expected complex wildcard match to exist")
	}
	if len(ips) != 1 {
		t.Errorf("Expected 1 IP for complex wildcard match, got %d", len(ips))
	}
	if len(ips) > 0 && !ips[0].Equal(ip1) {
		t.Errorf("Expected IP %v, got %v", ip1, ips[0])
	}

	// Test non-matching domain (missing prefix)
	ips, exists = store.GetRecords("host-01.autoco.internal.", RecordTypeA)
	if exists {
		t.Error("Expected domain without prefix to not exist")
	}
	if len(ips) != 0 {
		t.Errorf("Expected 0 IPs for domain without prefix, got %d", len(ips))
	}

	// Test non-matching domain (wrong ? position)
	ips, exists = store.GetRecords("sub.host-012.autoco.internal.", RecordTypeA)
	if exists {
		t.Error("Expected domain with wrong ? match to not exist")
	}
	if len(ips) != 0 {
		t.Errorf("Expected 0 IPs for domain with wrong ? match, got %d", len(ips))
	}
}

func TestDNSRecordStoreRemoveWildcard(t *testing.T) {
	store := NewDNSRecordStore()

	// Add wildcard record
	ip := net.ParseIP("10.0.0.1")
	err := store.AddRecord("*.autoco.internal", ip)
	if err != nil {
		t.Fatalf("Failed to add wildcard record: %v", err)
	}

	// Verify it exists
	ips, exists := store.GetRecords("host.autoco.internal.", RecordTypeA)
	if !exists {
		t.Error("Expected domain to exist before removal")
	}
	if len(ips) != 1 {
		t.Errorf("Expected 1 IP before removal, got %d", len(ips))
	}

	// Remove wildcard record
	store.RemoveRecord("*.autoco.internal", nil)

	// Verify it's gone
	ips, exists = store.GetRecords("host.autoco.internal.", RecordTypeA)
	if exists {
		t.Error("Expected domain to not exist after removal")
	}
	if len(ips) != 0 {
		t.Errorf("Expected 0 IPs after removal, got %d", len(ips))
	}
}

func TestDNSRecordStoreMultipleWildcards(t *testing.T) {
	store := NewDNSRecordStore()

	// Add multiple wildcard patterns that don't overlap
	ip1 := net.ParseIP("10.0.0.1")
	ip2 := net.ParseIP("10.0.0.2")
	ip3 := net.ParseIP("10.0.0.3")

	err := store.AddRecord("*.prod.autoco.internal", ip1)
	if err != nil {
		t.Fatalf("Failed to add first wildcard: %v", err)
	}

	err = store.AddRecord("*.dev.autoco.internal", ip2)
	if err != nil {
		t.Fatalf("Failed to add second wildcard: %v", err)
	}

	// Add a broader wildcard that matches both
	err = store.AddRecord("*.autoco.internal", ip3)
	if err != nil {
		t.Fatalf("Failed to add third wildcard: %v", err)
	}

	// Test domain matching only the prod pattern and the broad pattern
	ips, _ := store.GetRecords("host.prod.autoco.internal.", RecordTypeA)
	if len(ips) != 2 {
		t.Errorf("Expected 2 IPs (prod + broad), got %d", len(ips))
	}

	// Test domain matching only the dev pattern and the broad pattern
	ips, _ = store.GetRecords("service.dev.autoco.internal.", RecordTypeA)
	if len(ips) != 2 {
		t.Errorf("Expected 2 IPs (dev + broad), got %d", len(ips))
	}

	// Test domain matching only the broad pattern
	ips, _ = store.GetRecords("host.test.autoco.internal.", RecordTypeA)
	if len(ips) != 1 {
		t.Errorf("Expected 1 IP (broad only), got %d", len(ips))
	}
}

func TestDNSRecordStoreIPv6Wildcard(t *testing.T) {
	store := NewDNSRecordStore()

	// Add IPv6 wildcard record
	ip := net.ParseIP("2001:db8::1")
	err := store.AddRecord("*.autoco.internal", ip)
	if err != nil {
		t.Fatalf("Failed to add IPv6 wildcard record: %v", err)
	}

	// Test wildcard match for IPv6
	ips, _ := store.GetRecords("host.autoco.internal.", RecordTypeAAAA)
	if len(ips) != 1 {
		t.Errorf("Expected 1 IPv6 for wildcard match, got %d", len(ips))
	}
	if len(ips) > 0 && !ips[0].Equal(ip) {
		t.Errorf("Expected IPv6 %v, got %v", ip, ips[0])
	}
}

func TestHasRecordWildcard(t *testing.T) {
	store := NewDNSRecordStore()

	// Add wildcard record
	ip := net.ParseIP("10.0.0.1")
	err := store.AddRecord("*.autoco.internal", ip)
	if err != nil {
		t.Fatalf("Failed to add wildcard record: %v", err)
	}

	// Test HasRecord with wildcard match
	if !store.HasRecord("host.autoco.internal.", RecordTypeA) {
		t.Error("Expected HasRecord to return true for wildcard match")
	}

	// Test HasRecord with non-match
	if store.HasRecord("autoco.internal.", RecordTypeA) {
		t.Error("Expected HasRecord to return false for base domain")
	}
}

func TestDNSRecordStoreCaseInsensitive(t *testing.T) {
	store := NewDNSRecordStore()

	// Add record with mixed case
	ip := net.ParseIP("10.0.0.1")
	err := store.AddRecord("MyHost.AutoCo.Internal", ip)
	if err != nil {
		t.Fatalf("Failed to add mixed case record: %v", err)
	}

	// Test lookup with different cases
	testCases := []string{
		"myhost.autoco.internal.",
		"MYHOST.AUTOCO.INTERNAL.",
		"MyHost.AutoCo.Internal.",
		"mYhOsT.aUtOcO.iNtErNaL.",
	}

	for _, domain := range testCases {
		ips, _ := store.GetRecords(domain, RecordTypeA)
		if len(ips) != 1 {
			t.Errorf("Expected 1 IP for domain %q, got %d", domain, len(ips))
		}
		if len(ips) > 0 && !ips[0].Equal(ip) {
			t.Errorf("Expected IP %v for domain %q, got %v", ip, domain, ips[0])
		}
	}

	// Test wildcard with mixed case
	wildcardIP := net.ParseIP("10.0.0.2")
	err = store.AddRecord("*.Example.Com", wildcardIP)
	if err != nil {
		t.Fatalf("Failed to add mixed case wildcard: %v", err)
	}

	wildcardTestCases := []string{
		"host.example.com.",
		"HOST.EXAMPLE.COM.",
		"Host.Example.Com.",
		"HoSt.ExAmPlE.CoM.",
	}

	for _, domain := range wildcardTestCases {
		ips, _ := store.GetRecords(domain, RecordTypeA)
		if len(ips) != 1 {
			t.Errorf("Expected 1 IP for wildcard domain %q, got %d", domain, len(ips))
		}
		if len(ips) > 0 && !ips[0].Equal(wildcardIP) {
			t.Errorf("Expected IP %v for wildcard domain %q, got %v", wildcardIP, domain, ips[0])
		}
	}

	// Test removal with different case
	store.RemoveRecord("MYHOST.AUTOCO.INTERNAL", nil)
	ips, _ := store.GetRecords("myhost.autoco.internal.", RecordTypeA)
	if len(ips) != 0 {
		t.Errorf("Expected 0 IPs after removal, got %d", len(ips))
	}

	// Test HasRecord with different case
	if !store.HasRecord("HOST.EXAMPLE.COM.", RecordTypeA) {
		t.Error("Expected HasRecord to return true for mixed case wildcard match")
	}
}

func TestPTRRecordIPv4(t *testing.T) {
	store := NewDNSRecordStore()

	// Add PTR record for IPv4
	ip := net.ParseIP("192.168.1.1")
	domain := "host.example.com."
	err := store.AddPTRRecord(ip, domain)
	if err != nil {
		t.Fatalf("Failed to add PTR record: %v", err)
	}

	// Test reverse DNS lookup
	reverseDomain := "1.1.168.192.in-addr.arpa."
	result, ok := store.GetPTRRecord(reverseDomain)
	if !ok {
		t.Error("Expected PTR record to be found")
	}
	if result != domain {
		t.Errorf("Expected domain %q, got %q", domain, result)
	}

	// Test HasPTRRecord
	if !store.HasPTRRecord(reverseDomain) {
		t.Error("Expected HasPTRRecord to return true")
	}

	// Test non-existent PTR record
	_, ok = store.GetPTRRecord("2.1.168.192.in-addr.arpa.")
	if ok {
		t.Error("Expected PTR record not to be found for different IP")
	}
}

func TestPTRRecordIPv6(t *testing.T) {
	store := NewDNSRecordStore()

	// Add PTR record for IPv6
	ip := net.ParseIP("2001:db8::1")
	domain := "ipv6host.example.com."
	err := store.AddPTRRecord(ip, domain)
	if err != nil {
		t.Fatalf("Failed to add PTR record: %v", err)
	}

	// Test reverse DNS lookup
	// 2001:db8::1 = 2001:0db8:0000:0000:0000:0000:0000:0001
	// Reverse: 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.
	reverseDomain := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
	result, ok := store.GetPTRRecord(reverseDomain)
	if !ok {
		t.Error("Expected IPv6 PTR record to be found")
	}
	if result != domain {
		t.Errorf("Expected domain %q, got %q", domain, result)
	}

	// Test HasPTRRecord
	if !store.HasPTRRecord(reverseDomain) {
		t.Error("Expected HasPTRRecord to return true for IPv6")
	}
}

func TestRemovePTRRecord(t *testing.T) {
	store := NewDNSRecordStore()

	// Add PTR record
	ip := net.ParseIP("10.0.0.1")
	domain := "test.example.com."
	err := store.AddPTRRecord(ip, domain)
	if err != nil {
		t.Fatalf("Failed to add PTR record: %v", err)
	}

	// Verify it exists
	reverseDomain := "1.0.0.10.in-addr.arpa."
	_, ok := store.GetPTRRecord(reverseDomain)
	if !ok {
		t.Error("Expected PTR record to exist before removal")
	}

	// Remove PTR record
	store.RemovePTRRecord(ip)

	// Verify it's gone
	_, ok = store.GetPTRRecord(reverseDomain)
	if ok {
		t.Error("Expected PTR record to be removed")
	}

	// Test HasPTRRecord after removal
	if store.HasPTRRecord(reverseDomain) {
		t.Error("Expected HasPTRRecord to return false after removal")
	}
}

func TestIPToReverseDNS(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected string
	}{
		{
			name:     "IPv4 simple",
			ip:       "192.168.1.1",
			expected: "1.1.168.192.in-addr.arpa.",
		},
		{
			name:     "IPv4 localhost",
			ip:       "127.0.0.1",
			expected: "1.0.0.127.in-addr.arpa.",
		},
		{
			name:     "IPv4 with zeros",
			ip:       "10.0.0.1",
			expected: "1.0.0.10.in-addr.arpa.",
		},
		{
			name:     "IPv6 simple",
			ip:       "2001:db8::1",
			expected: "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
		},
		{
			name:     "IPv6 localhost",
			ip:       "::1",
			expected: "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ip)
			}
			result := IPToReverseDNS(ip)
			if result != tt.expected {
				t.Errorf("IPToReverseDNS(%s) = %q, want %q", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestReverseDNSToIP(t *testing.T) {
	tests := []struct {
		name        string
		reverseDNS  string
		expectedIP  string
		shouldMatch bool
	}{
		{
			name:        "IPv4 simple",
			reverseDNS:  "1.1.168.192.in-addr.arpa.",
			expectedIP:  "192.168.1.1",
			shouldMatch: true,
		},
		{
			name:        "IPv4 localhost",
			reverseDNS:  "1.0.0.127.in-addr.arpa.",
			expectedIP:  "127.0.0.1",
			shouldMatch: true,
		},
		{
			name:        "IPv6 simple",
			reverseDNS:  "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
			expectedIP:  "2001:db8::1",
			shouldMatch: true,
		},
		{
			name:        "Invalid IPv4 format",
			reverseDNS:  "1.1.168.in-addr.arpa.",
			expectedIP:  "",
			shouldMatch: false,
		},
		{
			name:        "Invalid IPv6 format",
			reverseDNS:  "1.0.0.0.ip6.arpa.",
			expectedIP:  "",
			shouldMatch: false,
		},
		{
			name:        "Not a reverse DNS domain",
			reverseDNS:  "example.com.",
			expectedIP:  "",
			shouldMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reverseDNSToIP(tt.reverseDNS)
			if tt.shouldMatch {
				if result == nil {
					t.Errorf("reverseDNSToIP(%q) returned nil, expected IP", tt.reverseDNS)
					return
				}
				expectedIP := net.ParseIP(tt.expectedIP)
				if !result.Equal(expectedIP) {
					t.Errorf("reverseDNSToIP(%q) = %v, want %v", tt.reverseDNS, result, expectedIP)
				}
			} else {
				if result != nil {
					t.Errorf("reverseDNSToIP(%q) = %v, expected nil", tt.reverseDNS, result)
				}
			}
		})
	}
}

func TestPTRRecordCaseInsensitive(t *testing.T) {
	store := NewDNSRecordStore()

	// Add PTR record with mixed case domain
	ip := net.ParseIP("192.168.1.1")
	domain := "MyHost.Example.Com"
	err := store.AddPTRRecord(ip, domain)
	if err != nil {
		t.Fatalf("Failed to add PTR record: %v", err)
	}

	// Test lookup with different cases in reverse DNS format
	reverseDomain := "1.1.168.192.in-addr.arpa."
	result, ok := store.GetPTRRecord(reverseDomain)
	if !ok {
		t.Error("Expected PTR record to be found")
	}
	// Domain should be normalized to lowercase
	if result != "myhost.example.com." {
		t.Errorf("Expected normalized domain %q, got %q", "myhost.example.com.", result)
	}

	// Test with uppercase reverse DNS
	reverseDomainUpper := "1.1.168.192.IN-ADDR.ARPA."
	result, ok = store.GetPTRRecord(reverseDomainUpper)
	if !ok {
		t.Error("Expected PTR record to be found with uppercase reverse DNS")
	}
	if result != "myhost.example.com." {
		t.Errorf("Expected normalized domain %q, got %q", "myhost.example.com.", result)
	}
}

func TestClearPTRRecords(t *testing.T) {
	store := NewDNSRecordStore()

	// Add some PTR records
	ip1 := net.ParseIP("192.168.1.1")
	ip2 := net.ParseIP("192.168.1.2")
	store.AddPTRRecord(ip1, "host1.example.com.")
	store.AddPTRRecord(ip2, "host2.example.com.")

	// Add some A records too
	store.AddRecord("test.example.com.", net.ParseIP("10.0.0.1"))

	// Verify PTR records exist
	if !store.HasPTRRecord("1.1.168.192.in-addr.arpa.") {
		t.Error("Expected PTR record to exist before clear")
	}

	// Clear all records
	store.Clear()

	// Verify PTR records are gone
	if store.HasPTRRecord("1.1.168.192.in-addr.arpa.") {
		t.Error("Expected PTR record to be cleared")
	}
	if store.HasPTRRecord("2.1.168.192.in-addr.arpa.") {
		t.Error("Expected PTR record to be cleared")
	}

	// Verify A records are also gone
	if store.HasRecord("test.example.com.", RecordTypeA) {
		t.Error("Expected A record to be cleared")
	}
}

func TestAutomaticPTRRecordOnAdd(t *testing.T) {
	store := NewDNSRecordStore()

	// Add an A record - should automatically add PTR record
	domain := "host.example.com."
	ip := net.ParseIP("192.168.1.100")
	err := store.AddRecord(domain, ip)
	if err != nil {
		t.Fatalf("Failed to add A record: %v", err)
	}

	// Verify PTR record was automatically created
	reverseDomain := "100.1.168.192.in-addr.arpa."
	result, ok := store.GetPTRRecord(reverseDomain)
	if !ok {
		t.Error("Expected PTR record to be automatically created")
	}
	if result != domain {
		t.Errorf("Expected PTR to point to %q, got %q", domain, result)
	}

	// Add AAAA record - should also automatically add PTR record
	domain6 := "ipv6host.example.com."
	ip6 := net.ParseIP("2001:db8::1")
	err = store.AddRecord(domain6, ip6)
	if err != nil {
		t.Fatalf("Failed to add AAAA record: %v", err)
	}

	// Verify IPv6 PTR record was automatically created
	reverseDomain6 := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
	result6, ok := store.GetPTRRecord(reverseDomain6)
	if !ok {
		t.Error("Expected IPv6 PTR record to be automatically created")
	}
	if result6 != domain6 {
		t.Errorf("Expected PTR to point to %q, got %q", domain6, result6)
	}
}

func TestAutomaticPTRRecordOnRemove(t *testing.T) {
	store := NewDNSRecordStore()

	// Add an A record (with automatic PTR)
	domain := "host.example.com."
	ip := net.ParseIP("192.168.1.100")
	store.AddRecord(domain, ip)

	// Verify PTR exists
	reverseDomain := "100.1.168.192.in-addr.arpa."
	if !store.HasPTRRecord(reverseDomain) {
		t.Error("Expected PTR record to exist after adding A record")
	}

	// Remove the A record
	store.RemoveRecord(domain, ip)

	// Verify PTR was automatically removed
	if store.HasPTRRecord(reverseDomain) {
		t.Error("Expected PTR record to be automatically removed")
	}

	// Verify A record is also gone
	ips, _ := store.GetRecords(domain, RecordTypeA)
	if len(ips) != 0 {
		t.Errorf("Expected A record to be removed, got %d records", len(ips))
	}
}

func TestAutomaticPTRRecordOnRemoveAll(t *testing.T) {
	store := NewDNSRecordStore()

	// Add multiple IPs for the same domain
	domain := "host.example.com."
	ip1 := net.ParseIP("192.168.1.100")
	ip2 := net.ParseIP("192.168.1.101")
	store.AddRecord(domain, ip1)
	store.AddRecord(domain, ip2)

	// Verify both PTR records exist
	reverseDomain1 := "100.1.168.192.in-addr.arpa."
	reverseDomain2 := "101.1.168.192.in-addr.arpa."
	if !store.HasPTRRecord(reverseDomain1) {
		t.Error("Expected first PTR record to exist")
	}
	if !store.HasPTRRecord(reverseDomain2) {
		t.Error("Expected second PTR record to exist")
	}

	// Remove all records for the domain
	store.RemoveRecord(domain, nil)

	// Verify both PTR records were removed
	if store.HasPTRRecord(reverseDomain1) {
		t.Error("Expected first PTR record to be removed")
	}
	if store.HasPTRRecord(reverseDomain2) {
		t.Error("Expected second PTR record to be removed")
	}
}

func TestNoPTRForWildcardRecords(t *testing.T) {
	store := NewDNSRecordStore()

	// Add wildcard record - should NOT create PTR record
	domain := "*.example.com."
	ip := net.ParseIP("192.168.1.100")
	err := store.AddRecord(domain, ip)
	if err != nil {
		t.Fatalf("Failed to add wildcard record: %v", err)
	}

	// Verify no PTR record was created
	reverseDomain := "100.1.168.192.in-addr.arpa."
	_, ok := store.GetPTRRecord(reverseDomain)
	if ok {
		t.Error("Expected no PTR record for wildcard domain")
	}

	// Verify wildcard A record exists
	if !store.HasRecord("host.example.com.", RecordTypeA) {
		t.Error("Expected wildcard A record to exist")
	}
}

func TestPTRRecordOverwrite(t *testing.T) {
	store := NewDNSRecordStore()

	// Add first domain with IP
	domain1 := "host1.example.com."
	ip := net.ParseIP("192.168.1.100")
	store.AddRecord(domain1, ip)

	// Verify PTR points to first domain
	reverseDomain := "100.1.168.192.in-addr.arpa."
	result, ok := store.GetPTRRecord(reverseDomain)
	if !ok {
		t.Fatal("Expected PTR record to exist")
	}
	if result != domain1 {
		t.Errorf("Expected PTR to point to %q, got %q", domain1, result)
	}

	// Add second domain with same IP - should overwrite PTR
	domain2 := "host2.example.com."
	store.AddRecord(domain2, ip)

	// Verify PTR now points to second domain (last one added)
	result, ok = store.GetPTRRecord(reverseDomain)
	if !ok {
		t.Fatal("Expected PTR record to still exist")
	}
	if result != domain2 {
		t.Errorf("Expected PTR to point to %q (overwritten), got %q", domain2, result)
	}

	// Remove first domain - PTR should remain pointing to second domain
	store.RemoveRecord(domain1, ip)
	result, ok = store.GetPTRRecord(reverseDomain)
	if !ok {
		t.Error("Expected PTR record to still exist after removing first domain")
	}
	if result != domain2 {
		t.Errorf("Expected PTR to still point to %q, got %q", domain2, result)
	}

	// Remove second domain - PTR should now be gone
	store.RemoveRecord(domain2, ip)
	_, ok = store.GetPTRRecord(reverseDomain)
	if ok {
		t.Error("Expected PTR record to be removed after removing second domain")
	}
}
