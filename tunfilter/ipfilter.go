package tunfilter

import (
	"encoding/binary"
	"net/netip"
	"sync"
)

// IPFilter provides fast IP-based packet filtering and interception
type IPFilter struct {
	// Map of IP addresses to intercept (for O(1) lookup)
	interceptIPs map[netip.Addr]HandlerFunc
	mutex        sync.RWMutex
}

// NewIPFilter creates a new IP-based packet filter
func NewIPFilter() *IPFilter {
	return &IPFilter{
		interceptIPs: make(map[netip.Addr]HandlerFunc),
	}
}

// AddInterceptIP adds an IP address to intercept
// All packets to/from this IP will be passed to the handler function
func (f *IPFilter) AddInterceptIP(ip netip.Addr, handler HandlerFunc) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.interceptIPs[ip] = handler
}

// RemoveInterceptIP removes an IP from interception
func (f *IPFilter) RemoveInterceptIP(ip netip.Addr) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	delete(f.interceptIPs, ip)
}

// FilterOutbound filters packets going from host to tunnel
func (f *IPFilter) FilterOutbound(packet []byte, size int) FilterAction {
	// Fast path: no interceptors configured
	f.mutex.RLock()
	hasInterceptors := len(f.interceptIPs) > 0
	f.mutex.RUnlock()

	if !hasInterceptors {
		return FilterActionPass
	}

	// Parse IP header (minimum 20 bytes)
	if size < 20 {
		return FilterActionPass
	}

	// Check IP version (IPv4 only for now)
	version := packet[0] >> 4
	if version != 4 {
		return FilterActionPass
	}

	// Extract destination IP (bytes 16-20 in IPv4 header)
	dstIP, ok := netip.AddrFromSlice(packet[16:20])
	if !ok {
		return FilterActionPass
	}

	// Check if this IP should be intercepted
	f.mutex.RLock()
	handler, shouldIntercept := f.interceptIPs[dstIP]
	f.mutex.RUnlock()

	if shouldIntercept && handler != nil {
		// Make a copy of the packet for the handler (to avoid data races)
		packetCopy := make([]byte, size)
		copy(packetCopy, packet[:size])

		// Call handler in background to avoid blocking packet processing
		go handler(packetCopy, DirectionOutbound)

		// Intercept the packet (don't send it through the tunnel)
		return FilterActionIntercept
	}

	return FilterActionPass
}

// FilterInbound filters packets coming from tunnel to host
func (f *IPFilter) FilterInbound(packet []byte, size int) FilterAction {
	// Fast path: no interceptors configured
	f.mutex.RLock()
	hasInterceptors := len(f.interceptIPs) > 0
	f.mutex.RUnlock()

	if !hasInterceptors {
		return FilterActionPass
	}

	// Parse IP header (minimum 20 bytes)
	if size < 20 {
		return FilterActionPass
	}

	// Check IP version (IPv4 only for now)
	version := packet[0] >> 4
	if version != 4 {
		return FilterActionPass
	}

	// Extract source IP (bytes 12-16 in IPv4 header)
	srcIP, ok := netip.AddrFromSlice(packet[12:16])
	if !ok {
		return FilterActionPass
	}

	// Check if this IP should be intercepted
	f.mutex.RLock()
	handler, shouldIntercept := f.interceptIPs[srcIP]
	f.mutex.RUnlock()

	if shouldIntercept && handler != nil {
		// Make a copy of the packet for the handler
		packetCopy := make([]byte, size)
		copy(packetCopy, packet[:size])

		// Call handler in background
		go handler(packetCopy, DirectionInbound)

		// Intercept the packet (don't deliver to host)
		return FilterActionIntercept
	}

	return FilterActionPass
}

// ParsePacketInfo extracts useful information from a packet for debugging/logging
type PacketInfo struct {
	Version    uint8
	Protocol   uint8
	SrcIP      netip.Addr
	DstIP      netip.Addr
	SrcPort    uint16
	DstPort    uint16
	IsUDP      bool
	IsTCP      bool
	PayloadLen int
}

// ParsePacket extracts packet information (useful for handlers)
func ParsePacket(packet []byte) (*PacketInfo, bool) {
	if len(packet) < 20 {
		return nil, false
	}

	info := &PacketInfo{}

	// IP version
	info.Version = packet[0] >> 4
	if info.Version != 4 {
		return nil, false
	}

	// Protocol
	info.Protocol = packet[9]
	info.IsUDP = info.Protocol == 17
	info.IsTCP = info.Protocol == 6

	// Source and destination IPs
	if srcIP, ok := netip.AddrFromSlice(packet[12:16]); ok {
		info.SrcIP = srcIP
	}
	if dstIP, ok := netip.AddrFromSlice(packet[16:20]); ok {
		info.DstIP = dstIP
	}

	// Get IP header length
	ihl := int(packet[0]&0x0f) * 4
	if len(packet) < ihl {
		return info, true
	}

	// Extract ports for TCP/UDP
	if (info.IsUDP || info.IsTCP) && len(packet) >= ihl+4 {
		info.SrcPort = binary.BigEndian.Uint16(packet[ihl : ihl+2])
		info.DstPort = binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
	}

	// Payload length
	totalLen := binary.BigEndian.Uint16(packet[2:4])
	info.PayloadLen = int(totalLen) - ihl
	if info.IsUDP || info.IsTCP {
		info.PayloadLen -= 8 // UDP header size
	}

	return info, true
}
