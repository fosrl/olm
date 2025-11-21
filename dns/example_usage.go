package dns

// Example usage of DNS record management (not compiled, just for reference)
/*

import (
	"net"
	"github.com/fosrl/olm/dns"
)

func exampleUsage() {
	// Assuming you have a DNSProxy instance
	var proxy *dns.DNSProxy

	// Add an A record for example.com pointing to 192.168.1.100
	ip := net.ParseIP("192.168.1.100")
	err := proxy.AddDNSRecord("example.com", ip)
	if err != nil {
		// Handle error
	}

	// Add multiple A records for the same domain (round-robin)
	proxy.AddDNSRecord("example.com", net.ParseIP("192.168.1.101"))
	proxy.AddDNSRecord("example.com", net.ParseIP("192.168.1.102"))

	// Add an AAAA record (IPv6)
	ipv6 := net.ParseIP("2001:db8::1")
	proxy.AddDNSRecord("example.com", ipv6)

	// Query records
	aRecords := proxy.GetDNSRecords("example.com", dns.RecordTypeA)
	// Returns: [192.168.1.100, 192.168.1.101, 192.168.1.102]

	aaaaRecords := proxy.GetDNSRecords("example.com", dns.RecordTypeAAAA)
	// Returns: [2001:db8::1]

	// Remove a specific record
	proxy.RemoveDNSRecord("example.com", net.ParseIP("192.168.1.101"))

	// Remove all records for a domain
	proxy.RemoveDNSRecord("example.com", nil)

	// Clear all DNS records
	proxy.ClearDNSRecords()
}

// How it works:
// 1. When a DNS query arrives, the proxy first checks its local record store
// 2. If a matching A or AAAA record exists locally, it returns that immediately
// 3. If no local record exists, it forwards the query to upstream DNS (8.8.8.8 or 8.8.4.4)
// 4. All other DNS record types (MX, CNAME, TXT, etc.) are always forwarded upstream

*/
