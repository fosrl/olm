package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/util"
	"github.com/fosrl/olm/device"
	"github.com/miekg/dns"
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
	tunnelDNS    bool // Whether to tunnel DNS queries over WireGuard or to spit them out locally
	mtu          int
	middleDevice *device.MiddleDevice // Reference to MiddleDevice for packet filtering and TUN writes
	recordStore  *DNSRecordStore      // Local DNS records

	// matchDomains lists the FQDN wildcard patterns (using * and ? wildcards, see
	// matchWildcard) that this proxy is responsible for. Queries whose name matches
	// one of these patterns are checked against local records and, failing that,
	// forwarded to upstreamDNS. Queries that match none of the patterns are sent
	// directly to localDNS instead, bypassing local records and upstreamDNS
	// entirely. An empty matchDomains means "match everything" (i.e. behave as if
	// this feature were not configured).
	matchDomains []string
	// localDNS holds the host's own system DNS servers (as reported by
	// SystemDNSMonitor / PublicDNS), used to resolve queries that don't match
	// matchDomains rather than sending them upstream or through the tunnel.
	localDNS   []string
	matchMu    sync.RWMutex

	// Tunnel DNS fields - for sending queries over WireGuard
	tunnelIP          netip.Addr   // WireGuard interface IP (source for tunneled queries)
	tunnelStack       *stack.Stack // Separate netstack for outbound tunnel queries
	tunnelEp          *channel.Endpoint
	tunnelActivePorts map[uint16]bool
	tunnelPortsLock   sync.Mutex

	// jitHandler is called when a local record is resolved for a site that may not be
	// connected yet, giving the caller a chance to initiate a JIT connection.
	// It is invoked asynchronously so it never blocks DNS resolution.
	jitHandler func(siteId int)

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewDNSProxy creates a new DNS proxy.
//
// matchDomains, if non-empty, restricts local-record lookup and upstream
// forwarding to queries whose name matches one of the given wildcard patterns
// (see matchWildcard). Queries that match none of the patterns are instead
// forwarded directly to localDNS (the host's own system DNS servers). Pass an
// empty matchDomains to match every query, preserving prior behavior.
func NewDNSProxy(middleDevice *device.MiddleDevice, mtu int, utilitySubnet string, upstreamDns []string, tunnelDns bool, tunnelIP string, matchDomains []string, localDNS []string) (*DNSProxy, error) {
	proxyIP, err := PickIPFromSubnet(utilitySubnet)
	if err != nil {
		return nil, fmt.Errorf("failed to pick DNS proxy IP from subnet: %v", err)
	}

	if len(upstreamDns) == 0 {
		return nil, fmt.Errorf("at least one upstream DNS server must be specified")
	}

	ctx, cancel := context.WithCancel(context.Background())

	proxy := &DNSProxy{
		proxyIP:           proxyIP,
		mtu:               mtu,
		middleDevice:      middleDevice,
		upstreamDNS:       upstreamDns,
		tunnelDNS:         tunnelDns,
		recordStore:       NewDNSRecordStore(),
		tunnelActivePorts: make(map[uint16]bool),
		matchDomains:      matchDomains,
		localDNS:          localDNS,
		ctx:               ctx,
		cancel:            cancel,
	}

	// Parse tunnel IP if provided (needed for tunneled DNS)
	if tunnelIP != "" {
		addr, err := netip.ParseAddr(tunnelIP)
		if err != nil {
			return nil, fmt.Errorf("failed to parse tunnel IP: %v", err)
		}
		proxy.tunnelIP = addr
	}

	// Create gvisor netstack for receiving DNS queries
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

	// Initialize tunnel netstack if tunnel DNS is enabled
	if tunnelDns {
		if !proxy.tunnelIP.IsValid() {
			return nil, fmt.Errorf("tunnel IP is required when tunnelDNS is enabled")
		}

		// TODO: DO WE NEED TO ESTABLISH ANOTHER NETSTACK HERE OR CAN WE COMBINE WITH WGTESTER?
		if err := proxy.initTunnelNetstack(); err != nil {
			return nil, fmt.Errorf("failed to initialize tunnel netstack: %v", err)
		}
	}

	return proxy, nil
}

// initTunnelNetstack creates a separate netstack for outbound DNS queries through the tunnel
func (p *DNSProxy) initTunnelNetstack() error {
	// Create gvisor netstack for outbound tunnel queries
	stackOpts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
		HandleLocal:        true,
	}

	p.tunnelEp = channel.New(256, uint32(p.mtu), "")
	p.tunnelStack = stack.New(stackOpts)

	// Create NIC
	if err := p.tunnelStack.CreateNIC(1, p.tunnelEp); err != nil {
		return fmt.Errorf("failed to create tunnel NIC: %v", err)
	}

	// Add tunnel IP address (WireGuard interface IP)
	ipBytes := p.tunnelIP.As4()
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4(ipBytes).WithPrefix(),
	}

	if err := p.tunnelStack.AddProtocolAddress(1, protoAddr, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("failed to add tunnel protocol address: %v", err)
	}

	// Add default route
	p.tunnelStack.AddRoute(tcpip.Route{
		Destination: header.IPv4EmptySubnet,
		NIC:         1,
	})

	// Register filter rule on MiddleDevice to intercept responses
	p.middleDevice.AddRule(p.tunnelIP, p.handleTunnelResponse)

	return nil
}

// handleTunnelResponse handles packets coming back from the tunnel destined for the tunnel IP
func (p *DNSProxy) handleTunnelResponse(packet []byte) bool {
	// Check if it's UDP
	proto, ok := util.GetProtocol(packet)
	if !ok || proto != 17 { // UDP
		return false
	}

	// Check destination port - should be one of our active outbound ports
	port, ok := util.GetDestPort(packet)
	if !ok {
		return false
	}

	// Check if we are expecting a response on this port
	p.tunnelPortsLock.Lock()
	active := p.tunnelActivePorts[uint16(port)]
	p.tunnelPortsLock.Unlock()

	if !active {
		return false
	}

	// Inject into tunnel netstack
	version := packet[0] >> 4
	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(packet),
	})

	switch version {
	case 4:
		p.tunnelEp.InjectInbound(ipv4.ProtocolNumber, pkb)
	case 6:
		p.tunnelEp.InjectInbound(ipv6.ProtocolNumber, pkb)
	default:
		pkb.DecRef()
		return false
	}

	pkb.DecRef()
	return true // Handled
}

// Start starts the DNS proxy and registers with the filter
func (p *DNSProxy) Start() error {
	// Install packet filter rule
	p.middleDevice.AddRule(p.proxyIP, p.handlePacket)

	// Start DNS listener
	p.wg.Add(2)
	go p.runDNSListener()
	go p.runPacketSender()

	// Start tunnel packet sender if tunnel DNS is enabled
	if p.tunnelDNS {
		p.wg.Add(1)
		go p.runTunnelPacketSender()
	}

	logger.Info("DNS proxy started on %s:%d (tunnelDNS=%v)", p.proxyIP.String(), DNSPort, p.tunnelDNS)
	return nil
}

// Stop stops the DNS proxy
func (p *DNSProxy) Stop() {
	if p.middleDevice != nil {
		p.middleDevice.RemoveRule(p.proxyIP)
		if p.tunnelDNS && p.tunnelIP.IsValid() {
			p.middleDevice.RemoveRule(p.tunnelIP)
		}
	}
	p.cancel()

	// Close the endpoint first to unblock any pending Read() calls in runPacketSender
	if p.ep != nil {
		p.ep.Close()
	}

	// Close tunnel endpoint if it exists
	if p.tunnelEp != nil {
		p.tunnelEp.Close()
	}

	p.wg.Wait()

	if p.stack != nil {
		p.stack.Close()
	}

	if p.tunnelStack != nil {
		p.tunnelStack.Close()
	}

	logger.Info("DNS proxy stopped")
}

func (p *DNSProxy) GetProxyIP() netip.Addr {
	return p.proxyIP
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

	// If matchDomains is configured and this query's name doesn't match any of
	// the configured patterns, skip local records and upstream entirely and
	// send it straight to the host's own system DNS servers.
	if !p.matchesConfiguredDomains(question.Name) {
		logger.Debug("Query for %s does not match configured domains, forwarding to local DNS %v", question.Name, p.getLocalDNS())
		response := p.forwardToLocalDNS(msg)
		if response == nil {
			logger.Error("Failed to get DNS response for %s from local DNS", question.Name)
			return
		}
		responseData, err := response.Pack()
		if err != nil {
			logger.Error("Failed to pack DNS response: %v", err)
			return
		}
		if _, err := udpConn.WriteTo(responseData, clientAddr); err != nil {
			logger.Error("Failed to send DNS response: %v", err)
		}
		return
	}

	// Check if we have local records for this query
	var response *dns.Msg
	if question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA || question.Qtype == dns.TypePTR {
		response = p.checkLocalRecords(msg, question)
	}

	// If a local A/AAAA record was found, notify the JIT handler so that the owning
	// site can be connected on-demand if it is not yet active.
	if response != nil && p.jitHandler != nil &&
		(question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA) {
		if siteId, ok := p.recordStore.GetSiteIdForDomain(question.Name); ok && siteId != 0 {
			handler := p.jitHandler
			go handler(siteId)
		}
	}

	// If no local records, forward to upstream
	if response == nil {
		logger.Debug("No local record for %s, forwarding upstream to %v", question.Name, p.upstreamDNS)
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
	// Handle PTR queries
	if question.Qtype == dns.TypePTR {
		if ptrDomain, ok := p.recordStore.GetPTRRecord(question.Name); ok {
			logger.Debug("Found local PTR record for %s -> %s", question.Name, ptrDomain)

			// Create response message
			response := new(dns.Msg)
			response.SetReply(query)
			response.Authoritative = true

			// Add PTR answer record
			rr := &dns.PTR{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypePTR,
					Class:  dns.ClassINET,
					Ttl:    300, // 5 minutes
				},
				Ptr: ptrDomain,
			}
			response.Answer = append(response.Answer, rr)

			return response
		}
		return nil
	}

	// Handle A and AAAA queries
	var recordType RecordType
	if question.Qtype == dns.TypeA {
		recordType = RecordTypeA
	} else if question.Qtype == dns.TypeAAAA {
		recordType = RecordTypeAAAA
	} else {
		return nil
	}

	ips, exists := p.recordStore.GetRecords(question.Name, recordType)
	if !exists {
		// Domain not found in local records, forward to upstream
		return nil
	}

	logger.Debug("Found %d local record(s) for %s", len(ips), question.Name)

	// Create response message (NODATA if no records, otherwise with answers)
	response := new(dns.Msg)
	response.SetReply(query)
	response.Authoritative = true

	// Add answer records (loop is a no-op if ips is empty)
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

// matchesConfiguredDomains reports whether name matches one of the configured
// matchDomains wildcard patterns. If matchDomains is empty, every name is
// considered a match (i.e. the feature is disabled).
func (p *DNSProxy) matchesConfiguredDomains(name string) bool {
	p.matchMu.RLock()
	patterns := p.matchDomains
	p.matchMu.RUnlock()

	if len(patterns) == 0 {
		return true
	}

	name = strings.ToLower(dns.Fqdn(name))
	for _, pattern := range patterns {
		pattern = strings.ToLower(dns.Fqdn(pattern))
		if matchWildcard(pattern, name) {
			return true
		}
	}
	return false
}

// getLocalDNS returns the currently configured local (system) DNS servers.
func (p *DNSProxy) getLocalDNS() []string {
	p.matchMu.RLock()
	defer p.matchMu.RUnlock()
	return p.localDNS
}

// forwardToLocalDNS forwards a DNS query directly to the host's own system DNS
// servers (localDNS), always using host networking regardless of tunnelDNS -
// these queries are for domains the caller has explicitly excluded from
// Pangolin resolution, so they should never traverse the tunnel.
func (p *DNSProxy) forwardToLocalDNS(query *dns.Msg) *dns.Msg {
	servers := p.getLocalDNS()
	if len(servers) == 0 {
		logger.Warn("No local DNS servers configured, dropping query for %s", query.Question[0].Name)
		return nil
	}

	var lastErr error
	for _, server := range servers {
		response, err := p.queryUpstreamDirect(server, query, 2*time.Second)
		if err == nil {
			return response
		}
		lastErr = err
	}
	logger.Error("All local DNS servers failed: %v", lastErr)
	return nil
}

// SetMatchDomains replaces the list of wildcard domain patterns (see
// matchWildcard) that this proxy checks against local records / upstream DNS.
// Queries not matching any pattern are sent to localDNS instead. Pass an
// empty slice to match every query (i.e. disable filtering).
func (p *DNSProxy) SetMatchDomains(patterns []string) {
	p.matchMu.Lock()
	defer p.matchMu.Unlock()
	p.matchDomains = patterns
}

// SetLocalDNS replaces the list of local (host system) DNS servers used to
// resolve queries that don't match matchDomains. Servers must be in
// "host:port" format (e.g. "192.168.1.1:53").
func (p *DNSProxy) SetLocalDNS(servers []string) {
	p.matchMu.Lock()
	defer p.matchMu.Unlock()
	p.localDNS = servers
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

// queryUpstream sends a DNS query to upstream server
func (p *DNSProxy) queryUpstream(server string, query *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	if p.tunnelDNS {
		return p.queryUpstreamTunnel(server, query, timeout)
	}
	return p.queryUpstreamDirect(server, query, timeout)
}

// queryUpstreamDirect sends a DNS query to upstream server using miekg/dns directly (host networking)
func (p *DNSProxy) queryUpstreamDirect(server string, query *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	client := &dns.Client{
		Timeout: timeout,
	}

	response, _, err := client.Exchange(query, server)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// queryUpstreamTunnel sends a DNS query through the WireGuard tunnel
func (p *DNSProxy) queryUpstreamTunnel(server string, query *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	// Dial through the tunnel netstack
	conn, port, err := p.dialTunnel("udp", server)
	if err != nil {
		return nil, fmt.Errorf("failed to dial tunnel: %v", err)
	}
	defer func() {
		conn.Close()
		p.removeTunnelPort(port)
	}()

	// Pack the query
	queryData, err := query.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack query: %v", err)
	}

	// Set deadline
	conn.SetDeadline(time.Now().Add(timeout))

	// Send the query
	_, err = conn.Write(queryData)
	if err != nil {
		return nil, fmt.Errorf("failed to send query: %v", err)
	}

	// Read the response
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	// Parse the response
	response := new(dns.Msg)
	if err := response.Unpack(buf[:n]); err != nil {
		return nil, fmt.Errorf("failed to unpack response: %v", err)
	}

	return response, nil
}

// dialTunnel creates a UDP connection through the tunnel netstack
func (p *DNSProxy) dialTunnel(network, addr string) (net.Conn, uint16, error) {
	if p.tunnelStack == nil {
		return nil, 0, fmt.Errorf("tunnel netstack not initialized")
	}

	// Parse remote address
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, 0, err
	}

	// Use tunnel IP as source
	ipBytes := p.tunnelIP.As4()

	// Create UDP connection with ephemeral port
	laddr := &tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFrom4(ipBytes),
		Port: 0,
	}

	raddrTcpip := &tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFrom4([4]byte(raddr.IP.To4())),
		Port: uint16(raddr.Port),
	}

	conn, err := gonet.DialUDP(p.tunnelStack, laddr, raddrTcpip, ipv4.ProtocolNumber)
	if err != nil {
		return nil, 0, err
	}

	// Get local port
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	port := uint16(localAddr.Port)

	// Register port so we can receive responses
	p.tunnelPortsLock.Lock()
	p.tunnelActivePorts[port] = true
	p.tunnelPortsLock.Unlock()

	return conn, port, nil
}

// removeTunnelPort removes a port from the active ports map
func (p *DNSProxy) removeTunnelPort(port uint16) {
	p.tunnelPortsLock.Lock()
	delete(p.tunnelActivePorts, port)
	p.tunnelPortsLock.Unlock()
}

// runTunnelPacketSender reads packets from tunnel netstack and injects them into WireGuard
func (p *DNSProxy) runTunnelPacketSender() {
	defer p.wg.Done()
	logger.Debug("DNS tunnel packet sender goroutine started")

	for {
		// Use blocking ReadContext instead of polling - much more CPU efficient
		// This will block until a packet is available or context is cancelled
		pkt := p.tunnelEp.ReadContext(p.ctx)
		if pkt == nil {
			// Context was cancelled or endpoint closed
			logger.Debug("DNS tunnel packet sender exiting")
			// Drain any remaining packets
			for {
				pkt := p.tunnelEp.Read()
				if pkt == nil {
					break
				}
				pkt.DecRef()
			}
			return
		}

		// Extract packet data
		slices := pkt.AsSlices()
		if len(slices) > 0 {
			var totalSize int
			for _, slice := range slices {
				totalSize += len(slice)
			}

			buf := make([]byte, totalSize)
			pos := 0
			for _, slice := range slices {
				copy(buf[pos:], slice)
				pos += len(slice)
			}

			// Inject into MiddleDevice (outbound to WG)
			p.middleDevice.InjectOutbound(buf)
		}

		pkt.DecRef()
	}
}

// runPacketSender sends packets from netstack back to TUN
func (p *DNSProxy) runPacketSender() {
	defer p.wg.Done()

	// MessageTransportHeaderSize is the offset used by WireGuard device
	// for reading/writing packets to the TUN interface
	const offset = 16

	for {
		// Use blocking ReadContext instead of polling - much more CPU efficient
		// This will block until a packet is available or context is cancelled
		pkt := p.ep.ReadContext(p.ctx)
		if pkt == nil {
			// Context was cancelled or endpoint closed
			return
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

			// Write packet to TUN device via MiddleDevice
			// offset=16 indicates packet data starts at position 16 in the buffer
			_, err := p.middleDevice.WriteToTun([][]byte{buf}, offset)
			if err != nil {
				logger.Error("Failed to write DNS response to TUN: %v", err)
			}
		}

		pkt.DecRef()
	}
}

// SetJITHandler registers a callback that is invoked whenever a local DNS record is
// resolved for an A or AAAA query. The siteId identifies which site owns the record.
// The handler is called in its own goroutine so it must be safe to call concurrently.
// Pass nil to disable JIT notifications.
func (p *DNSProxy) SetJITHandler(handler func(siteId int)) {
	p.jitHandler = handler
}

// SetUpstreamDNS replaces the list of upstream DNS servers used to forward
// queries that are not served by local records.  The servers must be in
// "host:port" format (e.g. "8.8.8.8:53").
func (p *DNSProxy) SetUpstreamDNS(servers []string) {
	if len(servers) == 0 {
		return
	}
	p.upstreamDNS = servers
}

// SetTunnelDNS changes whether upstream DNS queries are sent over the
// WireGuard tunnel (true) or directly via host networking (false). Only
// takes effect for queries issued after the call; in-flight queries keep
// using whichever path they already started on. Switching to true after the
// proxy has already started lazily brings up the tunnel netstack and its
// packet-forwarding goroutine if they weren't already running - NewDNSProxy
// only does that eagerly when tunnelDns is true from the start.
func (p *DNSProxy) SetTunnelDNS(tunnelDNS bool) {
	if tunnelDNS && p.tunnelStack == nil {
		if !p.tunnelIP.IsValid() {
			logger.Warn("Cannot enable tunnel DNS: tunnel IP not set")
			return
		}
		if err := p.initTunnelNetstack(); err != nil {
			logger.Error("Failed to initialize tunnel netstack for tunnel DNS: %v", err)
			return
		}
		p.wg.Add(1)
		go p.runTunnelPacketSender()
	}
	p.tunnelDNS = tunnelDNS
}

// AddDNSRecord adds a DNS record to the local store
// domain should be a domain name (e.g., "example.com" or "example.com.")
// ip should be a valid IPv4 or IPv6 address
func (p *DNSProxy) AddDNSRecord(domain string, ip net.IP, siteId int) error {
	logger.Debug("Adding dns record for domain %s with IP %s (siteId=%d)", domain, ip.String(), siteId)
	return p.recordStore.AddRecord(domain, ip, siteId)
}

// RemoveDNSRecord removes a DNS record from the local store
// If ip is nil, removes all records for the domain
func (p *DNSProxy) RemoveDNSRecord(domain string, ip net.IP) {
	p.recordStore.RemoveRecord(domain, ip)
}

// RemoveDNSRecordForSite removes DNS records for a domain that are owned by a specific site.
// If ip is nil, removes all records for the domain that are owned by that site.
func (p *DNSProxy) RemoveDNSRecordForSite(domain string, ip net.IP, siteId int) {
	p.recordStore.RemoveRecordForSite(domain, ip, siteId)
}

// GetDNSRecords returns all IP addresses for a domain and record type.
// The second return value indicates whether the domain exists.
func (p *DNSProxy) GetDNSRecords(domain string, recordType RecordType) ([]net.IP, bool) {
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
