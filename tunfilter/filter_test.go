package tunfilter_test

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/fosrl/olm/tunfilter"
)

// TestIPFilter validates the IP-based packet filtering
func TestIPFilter(t *testing.T) {
	filter := tunfilter.NewIPFilter()

	// Create a test handler that just tracks calls
	handler := func(packet []byte, direction tunfilter.Direction) error {
		return nil
	}

	// Add IP to intercept
	targetIP := netip.MustParseAddr("10.30.30.30")
	filter.AddInterceptIP(targetIP, handler)

	// Create a test packet destined for 10.30.30.30
	packet := buildTestPacket(
		netip.MustParseAddr("192.168.1.1"),
		netip.MustParseAddr("10.30.30.30"),
		12345,
		51821,
	)

	// Filter the packet (outbound direction)
	action := filter.FilterOutbound(packet, len(packet))

	// Should be intercepted
	if action != tunfilter.FilterActionIntercept {
		t.Errorf("Expected FilterActionIntercept, got %v", action)
	}

	// Handler should eventually be called (async)
	// In real tests you'd use sync primitives
}

// TestPacketParsing validates packet information extraction
func TestPacketParsing(t *testing.T) {
	srcIP := netip.MustParseAddr("192.168.1.100")
	dstIP := netip.MustParseAddr("10.30.30.30")
	srcPort := uint16(54321)
	dstPort := uint16(51821)

	packet := buildTestPacket(srcIP, dstIP, srcPort, dstPort)

	info, ok := tunfilter.ParsePacket(packet)
	if !ok {
		t.Fatal("Failed to parse packet")
	}

	if info.SrcIP != srcIP {
		t.Errorf("Expected src IP %s, got %s", srcIP, info.SrcIP)
	}

	if info.DstIP != dstIP {
		t.Errorf("Expected dst IP %s, got %s", dstIP, info.DstIP)
	}

	if info.SrcPort != srcPort {
		t.Errorf("Expected src port %d, got %d", srcPort, info.SrcPort)
	}

	if info.DstPort != dstPort {
		t.Errorf("Expected dst port %d, got %d", dstPort, info.DstPort)
	}

	if !info.IsUDP {
		t.Error("Expected UDP packet")
	}

	if info.Protocol != 17 {
		t.Errorf("Expected protocol 17 (UDP), got %d", info.Protocol)
	}
}

// TestUDPResponsePacketConstruction validates packet building
func TestUDPResponsePacketConstruction(t *testing.T) {
	// This would test the buildUDPResponse function
	// For now, it's internal to NetstackHandler
	// You could expose it or test via the full handler
}

// Benchmark packet filtering performance
func BenchmarkIPFilterPassthrough(b *testing.B) {
	filter := tunfilter.NewIPFilter()
	packet := buildTestPacket(
		netip.MustParseAddr("192.168.1.1"),
		netip.MustParseAddr("192.168.1.2"),
		12345,
		80,
	)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filter.FilterOutbound(packet, len(packet))
	}
}

func BenchmarkIPFilterWithIntercept(b *testing.B) {
	filter := tunfilter.NewIPFilter()

	targetIP := netip.MustParseAddr("10.30.30.30")
	filter.AddInterceptIP(targetIP, func(p []byte, d tunfilter.Direction) error {
		return nil
	})

	packet := buildTestPacket(
		netip.MustParseAddr("192.168.1.1"),
		netip.MustParseAddr("10.30.30.30"),
		12345,
		51821,
	)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filter.FilterOutbound(packet, len(packet))
	}
}

// buildTestPacket creates a minimal UDP/IP packet for testing
func buildTestPacket(srcIP, dstIP netip.Addr, srcPort, dstPort uint16) []byte {
	payload := []byte("test payload")
	totalLen := 20 + 8 + len(payload) // IP + UDP + payload
	packet := make([]byte, totalLen)

	// IP Header
	packet[0] = 0x45 // Version 4, IHL 5
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	packet[8] = 64 // TTL
	packet[9] = 17 // UDP

	srcIPBytes := srcIP.As4()
	copy(packet[12:16], srcIPBytes[:])

	dstIPBytes := dstIP.As4()
	copy(packet[16:20], dstIPBytes[:])

	// IP Checksum (simplified - just set to 0 for testing)
	packet[10] = 0
	packet[11] = 0

	// UDP Header
	binary.BigEndian.PutUint16(packet[20:22], srcPort)
	binary.BigEndian.PutUint16(packet[22:24], dstPort)
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(payload)))
	binary.BigEndian.PutUint16(packet[26:28], 0) // Checksum

	// Payload
	copy(packet[28:], payload)

	return packet
}
