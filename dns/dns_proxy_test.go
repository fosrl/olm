package dns

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestCheckLocalRecordsNODATAForAAAA(t *testing.T) {
	proxy := &DNSProxy{
		recordStore: NewDNSRecordStore(),
	}

	// Add an A record for a domain (no AAAA record)
	ip := net.ParseIP("10.0.0.1")
	err := proxy.recordStore.AddRecord("myservice.internal", ip)
	if err != nil {
		t.Fatalf("Failed to add A record: %v", err)
	}

	// Query AAAA for domain with only A record - should return NODATA
	query := new(dns.Msg)
	query.SetQuestion("myservice.internal.", dns.TypeAAAA)
	response := proxy.checkLocalRecords(query, query.Question[0])

	if response == nil {
		t.Fatal("Expected NODATA response, got nil (would forward to upstream)")
	}
	if response.Rcode != dns.RcodeSuccess {
		t.Errorf("Expected Rcode NOERROR (0), got %d", response.Rcode)
	}
	if len(response.Answer) != 0 {
		t.Errorf("Expected empty answer section for NODATA, got %d answers", len(response.Answer))
	}
	if !response.Authoritative {
		t.Error("Expected response to be authoritative")
	}

	// Query A for same domain - should return the record
	query = new(dns.Msg)
	query.SetQuestion("myservice.internal.", dns.TypeA)
	response = proxy.checkLocalRecords(query, query.Question[0])

	if response == nil {
		t.Fatal("Expected response with A record, got nil")
	}
	if len(response.Answer) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(response.Answer))
	}
	aRecord, ok := response.Answer[0].(*dns.A)
	if !ok {
		t.Fatal("Expected A record in answer")
	}
	if !aRecord.A.Equal(ip.To4()) {
		t.Errorf("Expected IP %v, got %v", ip.To4(), aRecord.A)
	}
}

func TestCheckLocalRecordsNODATAForA(t *testing.T) {
	proxy := &DNSProxy{
		recordStore: NewDNSRecordStore(),
	}

	// Add an AAAA record for a domain (no A record)
	ip := net.ParseIP("2001:db8::1")
	err := proxy.recordStore.AddRecord("ipv6only.internal", ip)
	if err != nil {
		t.Fatalf("Failed to add AAAA record: %v", err)
	}

	// Query A for domain with only AAAA record - should return NODATA
	query := new(dns.Msg)
	query.SetQuestion("ipv6only.internal.", dns.TypeA)
	response := proxy.checkLocalRecords(query, query.Question[0])

	if response == nil {
		t.Fatal("Expected NODATA response, got nil")
	}
	if response.Rcode != dns.RcodeSuccess {
		t.Errorf("Expected Rcode NOERROR (0), got %d", response.Rcode)
	}
	if len(response.Answer) != 0 {
		t.Errorf("Expected empty answer section, got %d answers", len(response.Answer))
	}
	if !response.Authoritative {
		t.Error("Expected response to be authoritative")
	}

	// Query AAAA for same domain - should return the record
	query = new(dns.Msg)
	query.SetQuestion("ipv6only.internal.", dns.TypeAAAA)
	response = proxy.checkLocalRecords(query, query.Question[0])

	if response == nil {
		t.Fatal("Expected response with AAAA record, got nil")
	}
	if len(response.Answer) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(response.Answer))
	}
	aaaaRecord, ok := response.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatal("Expected AAAA record in answer")
	}
	if !aaaaRecord.AAAA.Equal(ip) {
		t.Errorf("Expected IP %v, got %v", ip, aaaaRecord.AAAA)
	}
}

func TestCheckLocalRecordsNonExistentDomain(t *testing.T) {
	proxy := &DNSProxy{
		recordStore: NewDNSRecordStore(),
	}

	// Add a record so the store isn't empty
	err := proxy.recordStore.AddRecord("exists.internal", net.ParseIP("10.0.0.1"))
	if err != nil {
		t.Fatalf("Failed to add record: %v", err)
	}

	// Query A for non-existent domain - should return nil (forward to upstream)
	query := new(dns.Msg)
	query.SetQuestion("unknown.internal.", dns.TypeA)
	response := proxy.checkLocalRecords(query, query.Question[0])

	if response != nil {
		t.Error("Expected nil for non-existent domain, got response")
	}

	// Query AAAA for non-existent domain - should also return nil
	query = new(dns.Msg)
	query.SetQuestion("unknown.internal.", dns.TypeAAAA)
	response = proxy.checkLocalRecords(query, query.Question[0])

	if response != nil {
		t.Error("Expected nil for non-existent domain, got response")
	}
}

func TestCheckLocalRecordsNODATAWildcard(t *testing.T) {
	proxy := &DNSProxy{
		recordStore: NewDNSRecordStore(),
	}

	// Add a wildcard A record (no AAAA)
	ip := net.ParseIP("10.0.0.1")
	err := proxy.recordStore.AddRecord("*.wildcard.internal", ip)
	if err != nil {
		t.Fatalf("Failed to add wildcard A record: %v", err)
	}

	// Query AAAA for wildcard-matched domain - should return NODATA
	query := new(dns.Msg)
	query.SetQuestion("host.wildcard.internal.", dns.TypeAAAA)
	response := proxy.checkLocalRecords(query, query.Question[0])

	if response == nil {
		t.Fatal("Expected NODATA response for wildcard match, got nil")
	}
	if response.Rcode != dns.RcodeSuccess {
		t.Errorf("Expected Rcode NOERROR (0), got %d", response.Rcode)
	}
	if len(response.Answer) != 0 {
		t.Errorf("Expected empty answer section, got %d answers", len(response.Answer))
	}

	// Query A for wildcard-matched domain - should return the record
	query = new(dns.Msg)
	query.SetQuestion("host.wildcard.internal.", dns.TypeA)
	response = proxy.checkLocalRecords(query, query.Question[0])

	if response == nil {
		t.Fatal("Expected response with A record, got nil")
	}
	if len(response.Answer) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(response.Answer))
	}
}
