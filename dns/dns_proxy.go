package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/util"
	"github.com/fosrl/olm/device"
	"github.com/miekg/dns"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	DNSPort = 53
)

// DNSProxy implements a DNS proxy using gvisor netstack
type DNSProxy struct {
	stack        *stack.Stack
	ep           *channel.Endpoint
	proxyIP      netip.Addr
	upstreamDNS  []string
	mtu          int
	tunDevice    tun.Device           // Direct reference to underlying TUN device for responses
	middleDevice *device.MiddleDevice // Reference to MiddleDevice for packet filtering
	recordStore  *DNSRecordStore      // Local DNS records

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewDNSProxy creates a new DNS proxy
func NewDNSProxy(tunDevice tun.Device, middleDevice *device.MiddleDevice, mtu int, utilitySubnet string, upstreamDns []string) (*DNSProxy, error) {
	proxyIP, err := PickIPFromSubnet(utilitySubnet)
	if err != nil {
		return nil, fmt.Errorf("failed to pick DNS proxy IP from subnet: %v", err)
	}

	if len(upstreamDns) == 0 {
		return nil, fmt.Errorf("at least one upstream DNS server must be specified")
	}

	ctx, cancel := context.WithCancel(context.Background())

	proxy := &DNSProxy{
		proxyIP:     proxyIP,
		mtu:         mtu,
		tunDevice:   tunDevice,
		recordStore: NewDNSRecordStore(),
		ctx:         ctx,
		cancel:      cancel,
	}

	// Create gvisor netstack
	stackOpts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
		HandleLocal:        true,
	}

	proxy.ep = channel.New(256, uint32(mtu), "")
	proxy.stack = stack.New(stackOpts)

	// Create NIC
	if err := proxy.stack.CreateNIC(1, proxy.ep); err != nil {
		return nil, fmt.Errorf("failed to create NIC: %v", err)
	}

	// Add IP address
	// Parse the proxy IP to get the octets
	ipBytes := proxyIP.As4()
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4(ipBytes).WithPrefix(),
	}

	if err := proxy.stack.AddProtocolAddress(1, protoAddr, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("failed to add protocol address: %v", err)
	}

	// Add default route
	proxy.stack.AddRoute(tcpip.Route{
		Destination: header.IPv4EmptySubnet,
		NIC:         1,
	})

	return proxy, nil
}

// Start starts the DNS proxy and registers with the filter
func (p *DNSProxy) Start() error {
	// Install packet filter rule
	p.middleDevice.AddRule(p.proxyIP, p.handlePacket)

	// Start DNS listener
	p.wg.Add(2)
	go p.runDNSListener()
	go p.runPacketSender()

	logger.Info("DNS proxy started on %s:%d", p.proxyIP.String(), DNSPort)
	return nil
}

// Stop stops the DNS proxy
func (p *DNSProxy) Stop() {
	if p.middleDevice != nil {
		p.middleDevice.RemoveRule(p.proxyIP)
	}
	p.cancel()
	p.wg.Wait()

	if p.stack != nil {
		p.stack.Close()
	}
	if p.ep != nil {
		p.ep.Close()
	}

	logger.Info("DNS proxy stopped")
}

// handlePacket is called by the filter for packets destined to DNS proxy IP
func (p *DNSProxy) handlePacket(packet []byte) bool {
	if len(packet) < 20 {
		return false // Don't drop, malformed
	}

	// Quick check for UDP port 53
	proto, ok := util.GetProtocol(packet)
	if !ok || proto != 17 { // 17 = UDP
		return false // Not UDP, don't handle
	}

	port, ok := util.GetDestPort(packet)
	if !ok || port != DNSPort {
		return false // Not DNS port
	}

	// Inject packet into our netstack
	version := packet[0] >> 4
	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(packet),
	})

	switch version {
	case 4:
		p.ep.InjectInbound(ipv4.ProtocolNumber, pkb)
	case 6:
		p.ep.InjectInbound(ipv6.ProtocolNumber, pkb)
	default:
		pkb.DecRef()
		return false
	}

	pkb.DecRef()
	return true // Drop packet from normal path
}

// runDNSListener listens for DNS queries on the netstack
func (p *DNSProxy) runDNSListener() {
	defer p.wg.Done()

	// Create UDP listener using gonet
	// Parse the proxy IP to get the octets
	ipBytes := p.proxyIP.As4()
	laddr := &tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFrom4(ipBytes),
		Port: DNSPort,
	}

	udpConn, err := gonet.DialUDP(p.stack, laddr, nil, ipv4.ProtocolNumber)
	if err != nil {
		logger.Error("Failed to create DNS listener: %v", err)
		return
	}
	defer udpConn.Close()

	logger.Debug("DNS proxy listening on netstack")

	// Handle DNS queries
	buf := make([]byte, 4096)
	for {
		select {
		case <-p.ctx.Done():
			return
		default:
		}

		udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remoteAddr, err := udpConn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if p.ctx.Err() != nil {
				return
			}
			logger.Error("DNS read error: %v", err)
			continue
		}

		query := make([]byte, n)
		copy(query, buf[:n])

		// Handle query in background
		go p.handleDNSQuery(udpConn, query, remoteAddr)
	}
}

// handleDNSQuery processes a DNS query, checking local records first, then forwarding upstream
func (p *DNSProxy) handleDNSQuery(udpConn *gonet.UDPConn, queryData []byte, clientAddr net.Addr) {
	// Parse the DNS query
	msg := new(dns.Msg)
	if err := msg.Unpack(queryData); err != nil {
		logger.Error("Failed to parse DNS query: %v", err)
		return
	}

	if len(msg.Question) == 0 {
		logger.Debug("DNS query has no questions")
		return
	}

	question := msg.Question[0]
	logger.Debug("DNS query for %s (type %s)", question.Name, dns.TypeToString[question.Qtype])

	// Check if we have local records for this query
	var response *dns.Msg
	if question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA {
		response = p.checkLocalRecords(msg, question)
	}

	// If no local records, forward to upstream
	if response == nil {
		logger.Debug("No local record for %s, forwarding upstream", question.Name)
		response = p.forwardToUpstream(msg)
	}

	if response == nil {
		logger.Error("Failed to get DNS response for %s", question.Name)
		return
	}

	// Pack and send response
	responseData, err := response.Pack()
	if err != nil {
		logger.Error("Failed to pack DNS response: %v", err)
		return
	}

	_, err = udpConn.WriteTo(responseData, clientAddr)
	if err != nil {
		logger.Error("Failed to send DNS response: %v", err)
	}
}

// checkLocalRecords checks if we have local records for the query
func (p *DNSProxy) checkLocalRecords(query *dns.Msg, question dns.Question) *dns.Msg {
	var recordType RecordType
	if question.Qtype == dns.TypeA {
		recordType = RecordTypeA
	} else if question.Qtype == dns.TypeAAAA {
		recordType = RecordTypeAAAA
	} else {
		return nil
	}

	ips := p.recordStore.GetRecords(question.Name, recordType)
	if len(ips) == 0 {
		return nil
	}

	logger.Debug("Found %d local record(s) for %s", len(ips), question.Name)

	// Create response message
	response := new(dns.Msg)
	response.SetReply(query)
	response.Authoritative = true

	// Add answer records
	for _, ip := range ips {
		var rr dns.RR
		if question.Qtype == dns.TypeA {
			rr = &dns.A{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300, // 5 minutes
				},
				A: ip.To4(),
			}
		} else { // TypeAAAA
			rr = &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    300, // 5 minutes
				},
				AAAA: ip.To16(),
			}
		}
		response.Answer = append(response.Answer, rr)
	}

	return response
}

// forwardToUpstream forwards a DNS query to upstream DNS servers
func (p *DNSProxy) forwardToUpstream(query *dns.Msg) *dns.Msg {
	// Try primary DNS server
	response, err := p.queryUpstream(p.upstreamDNS[0], query, 2*time.Second)
	if err != nil && len(p.upstreamDNS) > 1 {
		// Try secondary DNS server
		logger.Debug("Primary DNS failed, trying secondary: %v", err)
		response, err = p.queryUpstream(p.upstreamDNS[1], query, 2*time.Second)
		if err != nil {
			logger.Error("Both DNS servers failed: %v", err)
			return nil
		}
	}
	return response
}

// queryUpstream sends a DNS query to upstream server using miekg/dns
func (p *DNSProxy) queryUpstream(server string, query *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	client := &dns.Client{
		Timeout: timeout,
	}

	response, _, err := client.Exchange(query, server)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// runPacketSender sends packets from netstack back to TUN
func (p *DNSProxy) runPacketSender() {
	defer p.wg.Done()

	// MessageTransportHeaderSize is the offset used by WireGuard device
	// for reading/writing packets to the TUN interface
	const offset = 16

	for {
		select {
		case <-p.ctx.Done():
			return
		default:
		}

		// Read packets from netstack endpoint
		pkt := p.ep.Read()
		if pkt == nil {
			// No packet available, small sleep to avoid busy loop
			time.Sleep(1 * time.Millisecond)
			continue
		}

		// Extract packet data as slices
		slices := pkt.AsSlices()
		if len(slices) > 0 {
			// Flatten all slices into a single packet buffer
			var totalSize int
			for _, slice := range slices {
				totalSize += len(slice)
			}

			// Allocate buffer with offset space for WireGuard transport header
			// The first 'offset' bytes are reserved for the transport header
			buf := make([]byte, offset+totalSize)

			// Copy packet data after the offset
			pos := offset
			for _, slice := range slices {
				copy(buf[pos:], slice)
				pos += len(slice)
			}

			// Write packet to TUN device
			// offset=16 indicates packet data starts at position 16 in the buffer
			_, err := p.tunDevice.Write([][]byte{buf}, offset)
			if err != nil {
				logger.Error("Failed to write DNS response to TUN: %v", err)
			}
		}

		pkt.DecRef()
	}
}

// AddDNSRecord adds a DNS record to the local store
// domain should be a domain name (e.g., "example.com" or "example.com.")
// ip should be a valid IPv4 or IPv6 address
func (p *DNSProxy) AddDNSRecord(domain string, ip net.IP) error {
	return p.recordStore.AddRecord(domain, ip)
}

// RemoveDNSRecord removes a DNS record from the local store
// If ip is nil, removes all records for the domain
func (p *DNSProxy) RemoveDNSRecord(domain string, ip net.IP) {
	p.recordStore.RemoveRecord(domain, ip)
}

// GetDNSRecords returns all IP addresses for a domain and record type
func (p *DNSProxy) GetDNSRecords(domain string, recordType RecordType) []net.IP {
	return p.recordStore.GetRecords(domain, recordType)
}

// ClearDNSRecords removes all DNS records from the local store
func (p *DNSProxy) ClearDNSRecords() {
	p.recordStore.Clear()
}

func PickIPFromSubnet(subnet string) (netip.Addr, error) {
	// given a subnet in CIDR notation, pick the first usable IP
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid subnet: %w", err)
	}

	// Pick the first usable IP address from the subnet
	ip := prefix.Addr().Next()
	if !ip.IsValid() {
		return netip.Addr{}, fmt.Errorf("no valid IP address found in subnet: %s", subnet)
	}

	return ip, nil
}
