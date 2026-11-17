package dns

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestBlocklistBlocked(t *testing.T) {
	bl := NewBlocklist([]string{
		"ads.example.com",
		"Tracker.NET.",
		"localhost",
		"com",
		"  spaced.org  ",
		"ads.example.com", // duplicate
	})

	tests := []struct {
		name    string
		blocked bool
	}{
		{"ads.example.com", true},
		{"ads.example.com.", true},
		{"ADS.Example.COM.", true},
		{"deep.sub.ads.example.com", true},
		{"example.com", false},
		{"www.example.com", false},
		{"notads.example.com", false},
		{"tracker.net", true},
		{"x.tracker.net", true},
		{"spaced.org", true},
		{"localhost", false},
		{"other.com", false}, // a bare "com" entry must not block the TLD
		{"", false},
		{".", false},
	}
	for _, tt := range tests {
		if got := bl.Blocked(tt.name); got != tt.blocked {
			t.Errorf("Blocked(%q) = %v, want %v", tt.name, got, tt.blocked)
		}
	}

	if bl.Len() != 3 {
		t.Errorf("Len() = %d, want 3 (duplicates, single labels dropped)", bl.Len())
	}
}

func TestBlocklistNilAndEmpty(t *testing.T) {
	var nilList *Blocklist
	if nilList.Blocked("a.example.com") || nilList.Len() != 0 {
		t.Error("nil blocklist must block nothing")
	}
	if NewBlocklist(nil).Blocked("a.example.com") {
		t.Error("empty blocklist must block nothing")
	}
}

func TestLoadBlocklist(t *testing.T) {
	input := "# comment\n\nads.example.com\r\n  tracker.net  \n# another\nads.example.com\n"
	bl, err := LoadBlocklist(strings.NewReader(input))
	if err != nil {
		t.Fatalf("LoadBlocklist: %v", err)
	}
	if bl.Len() != 2 {
		t.Errorf("Len() = %d, want 2", bl.Len())
	}
	if !bl.Blocked("ads.example.com") || !bl.Blocked("tracker.net") {
		t.Error("expected both entries to be blocked")
	}
}

func TestLoadBlocklistLineTooLong(t *testing.T) {
	if _, err := LoadBlocklist(strings.NewReader(strings.Repeat("a", maxBlocklistLine*2))); err == nil {
		t.Error("expected an error for an over-long line")
	}
}

func TestBlocklistLarge(t *testing.T) {
	var sb strings.Builder
	const n = 300000
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, "host%d.ads.example.net\n", i)
	}
	bl, err := LoadBlocklist(strings.NewReader(sb.String()))
	if err != nil {
		t.Fatalf("LoadBlocklist: %v", err)
	}
	if bl.Len() != n {
		t.Fatalf("Len() = %d, want %d", bl.Len(), n)
	}
	if !bl.Blocked("host123456.ads.example.net") {
		t.Error("expected listed host to be blocked")
	}
	if bl.Blocked("host300000.ads.example.net") || bl.Blocked("ads.example.net") {
		t.Error("unlisted names must not be blocked")
	}
}

func BenchmarkBlocklistBlocked(b *testing.B) {
	domains := make([]string, 300000)
	for i := range domains {
		domains[i] = fmt.Sprintf("host%d.ads.example.net", i)
	}
	bl := NewBlocklist(domains)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bl.Blocked("www.some.unlisted.example.org.")
	}
}

func TestProxyShouldBlock(t *testing.T) {
	proxy := &DNSProxy{recordStore: NewDNSRecordStore()}

	if proxy.shouldBlock("ads.example.com.") {
		t.Fatal("nothing should be blocked before a blocklist is set")
	}

	proxy.SetBlocklist(NewBlocklist([]string{"ads.example.com", "corp.internal"}))
	if !proxy.shouldBlock("ads.example.com.") {
		t.Error("expected ads.example.com to be blocked")
	}
	if proxy.shouldBlock("ok.example.com.") {
		t.Error("ok.example.com must not be blocked")
	}

	// A Pangolin alias wins over the blocklist.
	if err := proxy.recordStore.AddRecord("corp.internal", net.ParseIP("10.0.0.1"), 1); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}
	if proxy.shouldBlock("corp.internal.") {
		t.Error("a name with a local record must not be blocked")
	}

	proxy.SetBlocklist(nil)
	if proxy.shouldBlock("ads.example.com.") {
		t.Error("clearing the blocklist must stop blocking")
	}
}

func TestBlockedResponse(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("ads.example.com.", dns.TypeA)

	resp := blockedResponse(query)
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("Rcode = %d, want NXDOMAIN (%d)", resp.Rcode, dns.RcodeNameError)
	}
	if resp.Id != query.Id || len(resp.Question) != 1 {
		t.Error("response must echo the query id and question")
	}
	if len(resp.Answer) != 0 {
		t.Error("blocked response must have no answers")
	}
}
