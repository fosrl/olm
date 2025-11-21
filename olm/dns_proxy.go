package olm

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
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
	// DNS proxy listening address
	DNSProxyIP = "10.30.30.30"
	DNSPort    = 53

	// Upstream DNS servers
	UpstreamDNS1 = "8.8.8.8:53"
	UpstreamDNS2 = "8.8.4.4:53"
)

// DNSProxy implements a DNS proxy using gvisor netstack
type DNSProxy struct {
	stack     *stack.Stack
	ep        *channel.Endpoint
	proxyIP   netip.Addr
	mtu       int
	tunDevice tun.Device // Direct reference to underlying TUN device for responses

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewDNSProxy creates a new DNS proxy
func NewDNSProxy(tunDevice tun.Device, mtu int) (*DNSProxy, error) {
	proxyIP, err := netip.ParseAddr(DNSProxyIP)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy IP: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	proxy := &DNSProxy{
		proxyIP:   proxyIP,
		mtu:       mtu,
		tunDevice: tunDevice,
		ctx:       ctx,
		cancel:    cancel,
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
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4([4]byte{10, 30, 30, 30}).WithPrefix(),
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
func (p *DNSProxy) Start(filter *FilteredDevice) error {
	// Install packet filter rule
	filter.AddRule(p.proxyIP, p.handlePacket)

	// Start DNS listener
	p.wg.Add(2)
	go p.runDNSListener()
	go p.runPacketSender()

	logger.Info("DNS proxy started on %s:%d", DNSProxyIP, DNSPort)
	return nil
}

// Stop stops the DNS proxy
func (p *DNSProxy) Stop(filter *FilteredDevice) {
	if filter != nil {
		filter.RemoveRule(p.proxyIP)
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
	proto, ok := GetProtocol(packet)
	if !ok || proto != 17 { // 17 = UDP
		return false // Not UDP, don't handle
	}

	port, ok := GetDestPort(packet)
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
	laddr := &tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFrom4([4]byte{10, 30, 30, 30}),
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
		go p.forwardDNSQuery(udpConn, query, remoteAddr)
	}
}

// forwardDNSQuery forwards a DNS query to upstream DNS server
func (p *DNSProxy) forwardDNSQuery(udpConn *gonet.UDPConn, query []byte, clientAddr net.Addr) {
	// Try primary DNS server
	response, err := p.queryUpstream(UpstreamDNS1, query, 2*time.Second)
	if err != nil {
		// Try secondary DNS server
		logger.Debug("Primary DNS failed, trying secondary: %v", err)
		response, err = p.queryUpstream(UpstreamDNS2, query, 2*time.Second)
		if err != nil {
			logger.Error("Both DNS servers failed: %v", err)
			return
		}
	}

	// Send response back to client through netstack
	_, err = udpConn.WriteTo(response, clientAddr)
	if err != nil {
		logger.Error("Failed to send DNS response: %v", err)
	}
}

// queryUpstream sends a DNS query to upstream server
func (p *DNSProxy) queryUpstream(server string, query []byte, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("udp", server, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	return response[:n], nil
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
