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
	ips := store.GetRecords("exact.autoco.internal.", RecordTypeA)
	if len(ips) != 1 {
		t.Errorf("Expected 1 IP for exact match, got %d", len(ips))
	}
	if !ips[0].Equal(exactIP) {
		t.Errorf("Expected exact IP %v, got %v", exactIP, ips[0])
	}

	// Test wildcard match
	ips = store.GetRecords("host.autoco.internal.", RecordTypeA)
	if len(ips) != 1 {
		t.Errorf("Expected 1 IP for wildcard match, got %d", len(ips))
	}
	if !ips[0].Equal(wildcardIP) {
		t.Errorf("Expected wildcard IP %v, got %v", wildcardIP, ips[0])
	}

	// Test non-match (base domain)
	ips = store.GetRecords("autoco.internal.", RecordTypeA)
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
	ips := store.GetRecords("sub.host-01.autoco.internal.", RecordTypeA)
	if len(ips) != 1 {
		t.Errorf("Expected 1 IP for complex wildcard match, got %d", len(ips))
	}
	if len(ips) > 0 && !ips[0].Equal(ip1) {
		t.Errorf("Expected IP %v, got %v", ip1, ips[0])
	}

	// Test non-matching domain (missing prefix)
	ips = store.GetRecords("host-01.autoco.internal.", RecordTypeA)
	if len(ips) != 0 {
		t.Errorf("Expected 0 IPs for domain without prefix, got %d", len(ips))
	}

	// Test non-matching domain (wrong ? position)
	ips = store.GetRecords("sub.host-012.autoco.internal.", RecordTypeA)
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
	ips := store.GetRecords("host.autoco.internal.", RecordTypeA)
	if len(ips) != 1 {
		t.Errorf("Expected 1 IP before removal, got %d", len(ips))
	}

	// Remove wildcard record
	store.RemoveRecord("*.autoco.internal", nil)

	// Verify it's gone
	ips = store.GetRecords("host.autoco.internal.", RecordTypeA)
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
	ips := store.GetRecords("host.prod.autoco.internal.", RecordTypeA)
	if len(ips) != 2 {
		t.Errorf("Expected 2 IPs (prod + broad), got %d", len(ips))
	}

	// Test domain matching only the dev pattern and the broad pattern
	ips = store.GetRecords("service.dev.autoco.internal.", RecordTypeA)
	if len(ips) != 2 {
		t.Errorf("Expected 2 IPs (dev + broad), got %d", len(ips))
	}

	// Test domain matching only the broad pattern
	ips = store.GetRecords("host.test.autoco.internal.", RecordTypeA)
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
	ips := store.GetRecords("host.autoco.internal.", RecordTypeAAAA)
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
