package monitor

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/fosrl/newt/bind"
	"github.com/fosrl/newt/holepunch"
	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/util"
	"github.com/fosrl/olm/api"
	middleDevice "github.com/fosrl/olm/device"
	"github.com/fosrl/olm/websocket"
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

// PeerMonitor handles monitoring the connection status to multiple WireGuard peers
type PeerMonitor struct {
	monitors    map[int]*Client
	mutex       sync.Mutex
	running     bool
	interval    time.Duration
	timeout     time.Duration
	maxAttempts int
	wsClient    *websocket.Client

	// Netstack fields
	middleDev   *middleDevice.MiddleDevice
	localIP     string
	stack       *stack.Stack
	ep          *channel.Endpoint
	activePorts map[uint16]bool
	portsLock   sync.Mutex
	nsCtx       context.Context
	nsCancel    context.CancelFunc
	nsWg        sync.WaitGroup

	// Holepunch testing fields
	sharedBind         *bind.SharedBind
	holepunchTester    *holepunch.HolepunchTester
	holepunchInterval  time.Duration
	holepunchTimeout   time.Duration
	holepunchEndpoints map[int]string // siteID -> endpoint for holepunch testing
	holepunchStatus    map[int]bool   // siteID -> connected status
	holepunchStopChan  chan struct{}

	// Relay tracking fields
	relayedPeers         map[int]bool // siteID -> whether the peer is currently relayed
	holepunchMaxAttempts int          // max consecutive failures before triggering relay
	holepunchFailures    map[int]int  // siteID -> consecutive failure count

	// API server for status updates
	apiServer *api.API

	// WG connection status tracking
	wgConnectionStatus map[int]bool // siteID -> WG connected status
}

// NewPeerMonitor creates a new peer monitor with the given callback
func NewPeerMonitor(wsClient *websocket.Client, middleDev *middleDevice.MiddleDevice, localIP string, sharedBind *bind.SharedBind, apiServer *api.API) *PeerMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	pm := &PeerMonitor{
		monitors:             make(map[int]*Client),
		interval:             3 * time.Second, // Default check interval
		timeout:              5 * time.Second,
		maxAttempts:          3,
		wsClient:             wsClient,
		middleDev:            middleDev,
		localIP:              localIP,
		activePorts:          make(map[uint16]bool),
		nsCtx:                ctx,
		nsCancel:             cancel,
		sharedBind:           sharedBind,
		holepunchInterval:    3 * time.Second, // Check holepunch every 5 seconds
		holepunchTimeout:     5 * time.Second,
		holepunchEndpoints:   make(map[int]string),
		holepunchStatus:      make(map[int]bool),
		relayedPeers:         make(map[int]bool),
		holepunchMaxAttempts: 3, // Trigger relay after 5 consecutive failures
		holepunchFailures:    make(map[int]int),
		apiServer:            apiServer,
		wgConnectionStatus:   make(map[int]bool),
	}

	if err := pm.initNetstack(); err != nil {
		logger.Error("Failed to initialize netstack for peer monitor: %v", err)
	}

	// Initialize holepunch tester if sharedBind is available
	if sharedBind != nil {
		pm.holepunchTester = holepunch.NewHolepunchTester(sharedBind)
	}

	return pm
}

// SetInterval changes how frequently peers are checked
func (pm *PeerMonitor) SetInterval(interval time.Duration) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.interval = interval

	// Update interval for all existing monitors
	for _, client := range pm.monitors {
		client.SetPacketInterval(interval)
	}
}

// SetTimeout changes the timeout for waiting for responses
func (pm *PeerMonitor) SetTimeout(timeout time.Duration) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.timeout = timeout

	// Update timeout for all existing monitors
	for _, client := range pm.monitors {
		client.SetTimeout(timeout)
	}
}

// SetMaxAttempts changes the maximum number of attempts for TestConnection
func (pm *PeerMonitor) SetMaxAttempts(attempts int) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.maxAttempts = attempts

	// Update max attempts for all existing monitors
	for _, client := range pm.monitors {
		client.SetMaxAttempts(attempts)
	}
}

// AddPeer adds a new peer to monitor
func (pm *PeerMonitor) AddPeer(siteID int, endpoint string, holepunchEndpoint string) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if _, exists := pm.monitors[siteID]; exists {
		return nil // Already monitoring
	}

	// Use our custom dialer that uses netstack
	client, err := NewClient(endpoint, pm.dial)
	if err != nil {
		return err
	}

	client.SetPacketInterval(pm.interval)
	client.SetTimeout(pm.timeout)
	client.SetMaxAttempts(pm.maxAttempts)

	pm.monitors[siteID] = client

	pm.holepunchEndpoints[siteID] = holepunchEndpoint
	pm.holepunchStatus[siteID] = false // Initially unknown/disconnected

	if pm.running {
		if err := client.StartMonitor(func(status ConnectionStatus) {
			pm.handleConnectionStatusChange(siteID, status)
		}); err != nil {
			return err
		}
	}

	return nil
}

// update holepunch endpoint for a peer
func (pm *PeerMonitor) UpdateHolepunchEndpoint(siteID int, endpoint string) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.holepunchEndpoints[siteID] = endpoint
}

// UpdatePeerEndpoint updates the monitor endpoint for a peer
func (pm *PeerMonitor) UpdatePeerEndpoint(siteID int, monitorPeer string) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	client, exists := pm.monitors[siteID]
	if !exists {
		logger.Warn("Cannot update endpoint: peer %d not found in monitor", siteID)
		return
	}

	// Update the client's server address
	client.UpdateServerAddr(monitorPeer)

	logger.Info("Updated monitor endpoint for site %d to %s", siteID, monitorPeer)
}

// removePeerUnlocked stops monitoring a peer and removes it from the monitor
// This function assumes the mutex is already held by the caller
func (pm *PeerMonitor) removePeerUnlocked(siteID int) {
	client, exists := pm.monitors[siteID]
	if !exists {
		return
	}

	client.StopMonitor()
	client.Close()
	delete(pm.monitors, siteID)
}

// RemovePeer stops monitoring a peer and removes it from the monitor
func (pm *PeerMonitor) RemovePeer(siteID int) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// remove the holepunch endpoint info
	delete(pm.holepunchEndpoints, siteID)
	delete(pm.holepunchStatus, siteID)
	delete(pm.relayedPeers, siteID)
	delete(pm.holepunchFailures, siteID)

	pm.removePeerUnlocked(siteID)
}

// Start begins monitoring all peers
func (pm *PeerMonitor) Start() {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if pm.running {
		return // Already running
	}

	pm.running = true

	// Start monitoring all peers
	for siteID, client := range pm.monitors {
		siteIDCopy := siteID // Create a copy for the closure
		err := client.StartMonitor(func(status ConnectionStatus) {
			pm.handleConnectionStatusChange(siteIDCopy, status)
		})
		if err != nil {
			logger.Error("Failed to start monitoring peer %d: %v\n", siteID, err)
			continue
		}
		logger.Info("Started monitoring peer %d\n", siteID)
	}

	pm.startHolepunchMonitor()
}

// handleConnectionStatusChange is called when a peer's connection status changes
func (pm *PeerMonitor) handleConnectionStatusChange(siteID int, status ConnectionStatus) {
	pm.mutex.Lock()
	previousStatus, exists := pm.wgConnectionStatus[siteID]
	pm.wgConnectionStatus[siteID] = status.Connected
	isRelayed := pm.relayedPeers[siteID]
	endpoint := pm.holepunchEndpoints[siteID]
	pm.mutex.Unlock()

	// Log status changes
	if !exists || previousStatus != status.Connected {
		if status.Connected {
			logger.Info("WireGuard connection to site %d is CONNECTED (RTT: %v)", siteID, status.RTT)
		} else {
			logger.Warn("WireGuard connection to site %d is DISCONNECTED", siteID)
		}
	}

	// Update API with connection status
	if pm.apiServer != nil {
		pm.apiServer.UpdatePeerStatus(siteID, status.Connected, status.RTT, endpoint, isRelayed)
	}
}

// sendRelay sends a relay message to the server
func (pm *PeerMonitor) sendRelay(siteID int) error {
	if pm.wsClient == nil {
		return fmt.Errorf("websocket client is nil")
	}

	err := pm.wsClient.SendMessage("olm/wg/relay", map[string]interface{}{
		"siteId": siteID,
	})
	if err != nil {
		logger.Error("Failed to send registration message: %v", err)
		return err
	}
	logger.Info("Sent relay message")
	return nil
}

// sendRelay sends a relay message to the server
func (pm *PeerMonitor) sendUnRelay(siteID int) error {
	if pm.wsClient == nil {
		return fmt.Errorf("websocket client is nil")
	}

	err := pm.wsClient.SendMessage("olm/wg/unrelay", map[string]interface{}{
		"siteId": siteID,
	})
	if err != nil {
		logger.Error("Failed to send registration message: %v", err)
		return err
	}
	logger.Info("Sent unrelay message")
	return nil
}

// Stop stops monitoring all peers
func (pm *PeerMonitor) Stop() {
	// Stop holepunch monitor first (outside of mutex to avoid deadlock)
	pm.stopHolepunchMonitor()

	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if !pm.running {
		return
	}

	pm.running = false

	// Stop all monitors
	for _, client := range pm.monitors {
		client.StopMonitor()
	}
}

// MarkPeerRelayed marks a peer as currently using relay
func (pm *PeerMonitor) MarkPeerRelayed(siteID int, relayed bool) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	pm.relayedPeers[siteID] = relayed
	if relayed {
		// Reset failure count when marked as relayed
		pm.holepunchFailures[siteID] = 0
	}
}

// IsPeerRelayed returns whether a peer is currently using relay
func (pm *PeerMonitor) IsPeerRelayed(siteID int) bool {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	return pm.relayedPeers[siteID]
}

// startHolepunchMonitor starts the holepunch connection monitoring
// Note: This function assumes the mutex is already held by the caller (called from Start())
func (pm *PeerMonitor) startHolepunchMonitor() error {
	if pm.holepunchTester == nil {
		return fmt.Errorf("holepunch tester not initialized (sharedBind not provided)")
	}

	if pm.holepunchStopChan != nil {
		return fmt.Errorf("holepunch monitor already running")
	}

	if err := pm.holepunchTester.Start(); err != nil {
		return fmt.Errorf("failed to start holepunch tester: %w", err)
	}

	pm.holepunchStopChan = make(chan struct{})

	go pm.runHolepunchMonitor()

	logger.Info("Started holepunch connection monitor")
	return nil
}

// stopHolepunchMonitor stops the holepunch connection monitoring
func (pm *PeerMonitor) stopHolepunchMonitor() {
	pm.mutex.Lock()
	stopChan := pm.holepunchStopChan
	pm.holepunchStopChan = nil
	pm.mutex.Unlock()

	if stopChan != nil {
		close(stopChan)
	}

	if pm.holepunchTester != nil {
		pm.holepunchTester.Stop()
	}

	logger.Info("Stopped holepunch connection monitor")
}

// runHolepunchMonitor runs the holepunch monitoring loop
func (pm *PeerMonitor) runHolepunchMonitor() {
	ticker := time.NewTicker(pm.holepunchInterval)
	defer ticker.Stop()

	// Do initial check immediately
	pm.checkHolepunchEndpoints()

	for {
		select {
		case <-pm.holepunchStopChan:
			return
		case <-ticker.C:
			pm.checkHolepunchEndpoints()
		}
	}
}

// checkHolepunchEndpoints tests all holepunch endpoints
func (pm *PeerMonitor) checkHolepunchEndpoints() {
	pm.mutex.Lock()
	// Check if we're still running before doing any work
	if !pm.running {
		pm.mutex.Unlock()
		return
	}
	endpoints := make(map[int]string, len(pm.holepunchEndpoints))
	for siteID, endpoint := range pm.holepunchEndpoints {
		endpoints[siteID] = endpoint
	}
	timeout := pm.holepunchTimeout
	maxAttempts := pm.holepunchMaxAttempts
	pm.mutex.Unlock()

	for siteID, endpoint := range endpoints {
		result := pm.holepunchTester.TestEndpoint(endpoint, timeout)

		pm.mutex.Lock()
		// Check if peer was removed while we were testing
		if _, stillExists := pm.holepunchEndpoints[siteID]; !stillExists {
			pm.mutex.Unlock()
			continue // Peer was removed, skip processing
		}

		previousStatus, exists := pm.holepunchStatus[siteID]
		pm.holepunchStatus[siteID] = result.Success
		isRelayed := pm.relayedPeers[siteID]

		// Track consecutive failures for relay triggering
		if result.Success {
			pm.holepunchFailures[siteID] = 0
		} else {
			pm.holepunchFailures[siteID]++
		}
		failureCount := pm.holepunchFailures[siteID]
		pm.mutex.Unlock()

		// Log status changes
		if !exists || previousStatus != result.Success {
			if result.Success {
				logger.Info("Holepunch to site %d (%s) is CONNECTED (RTT: %v)", siteID, endpoint, result.RTT)
			} else {
				if result.Error != nil {
					logger.Warn("Holepunch to site %d (%s) is DISCONNECTED: %v", siteID, endpoint, result.Error)
				} else {
					logger.Warn("Holepunch to site %d (%s) is DISCONNECTED", siteID, endpoint)
				}
			}
		}

		// Update API with holepunch status
		if pm.apiServer != nil {
			// Update holepunch connection status
			pm.apiServer.UpdatePeerHolepunchStatus(siteID, result.Success)

			// Get the current WG connection status for this peer
			pm.mutex.Lock()
			wgConnected := pm.wgConnectionStatus[siteID]
			pm.mutex.Unlock()

			// Update API - use holepunch endpoint and relay status
			pm.apiServer.UpdatePeerStatus(siteID, wgConnected, result.RTT, endpoint, isRelayed)
		}

		// Handle relay logic based on holepunch status
		// Check if we're still running before sending relay messages
		pm.mutex.Lock()
		stillRunning := pm.running
		pm.mutex.Unlock()

		if !stillRunning {
			return // Stop processing if shutdown is in progress
		}

		if !result.Success && !isRelayed && failureCount >= maxAttempts {
			// Holepunch failed and we're not relayed - trigger relay
			logger.Info("Holepunch to site %d failed %d times, triggering relay", siteID, failureCount)
			if pm.wsClient != nil {
				pm.sendRelay(siteID)
			}
		} else if result.Success && isRelayed {
			// Holepunch succeeded and we ARE relayed - switch back to direct
			logger.Info("Holepunch to site %d succeeded while relayed, switching to direct connection", siteID)
			if pm.wsClient != nil {
				pm.sendUnRelay(siteID)
			}
		}
	}
}

// GetHolepunchStatus returns the current holepunch status for all endpoints
func (pm *PeerMonitor) GetHolepunchStatus() map[int]bool {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	status := make(map[int]bool, len(pm.holepunchStatus))
	for siteID, connected := range pm.holepunchStatus {
		status[siteID] = connected
	}
	return status
}

// Close stops monitoring and cleans up resources
func (pm *PeerMonitor) Close() {
	// Stop holepunch monitor first (outside of mutex to avoid deadlock)
	pm.stopHolepunchMonitor()

	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	logger.Debug("PeerMonitor: Starting cleanup")

	// Stop and close all clients first
	for siteID, client := range pm.monitors {
		logger.Debug("PeerMonitor: Stopping client for site %d", siteID)
		client.StopMonitor()
		client.Close()
		delete(pm.monitors, siteID)
	}

	pm.running = false

	// Clean up netstack resources
	logger.Debug("PeerMonitor: Cancelling netstack context")
	if pm.nsCancel != nil {
		pm.nsCancel() // Signal goroutines to stop
	}

	// Close the channel endpoint to unblock any pending reads
	logger.Debug("PeerMonitor: Closing endpoint")
	if pm.ep != nil {
		pm.ep.Close()
	}

	// Wait for packet sender goroutine to finish with timeout
	logger.Debug("PeerMonitor: Waiting for goroutines to finish")
	done := make(chan struct{})
	go func() {
		pm.nsWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Debug("PeerMonitor: Goroutines finished cleanly")
	case <-time.After(2 * time.Second):
		logger.Warn("PeerMonitor: Timeout waiting for goroutines to finish, proceeding anyway")
	}

	// Destroy the stack last, after all goroutines are done
	logger.Debug("PeerMonitor: Destroying stack")
	if pm.stack != nil {
		pm.stack.Destroy()
		pm.stack = nil
	}

	logger.Debug("PeerMonitor: Cleanup complete")
}

// TestPeer tests connectivity to a specific peer
func (pm *PeerMonitor) TestPeer(siteID int) (bool, time.Duration, error) {
	pm.mutex.Lock()
	client, exists := pm.monitors[siteID]
	pm.mutex.Unlock()

	if !exists {
		return false, 0, fmt.Errorf("peer with siteID %d not found", siteID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), pm.timeout*time.Duration(pm.maxAttempts))
	defer cancel()

	connected, rtt := client.TestConnection(ctx)
	return connected, rtt, nil
}

// TestAllPeers tests connectivity to all peers
func (pm *PeerMonitor) TestAllPeers() map[int]struct {
	Connected bool
	RTT       time.Duration
} {
	pm.mutex.Lock()
	peers := make(map[int]*Client, len(pm.monitors))
	for siteID, client := range pm.monitors {
		peers[siteID] = client
	}
	pm.mutex.Unlock()

	results := make(map[int]struct {
		Connected bool
		RTT       time.Duration
	})
	for siteID, client := range peers {
		ctx, cancel := context.WithTimeout(context.Background(), pm.timeout*time.Duration(pm.maxAttempts))
		connected, rtt := client.TestConnection(ctx)
		cancel()

		results[siteID] = struct {
			Connected bool
			RTT       time.Duration
		}{
			Connected: connected,
			RTT:       rtt,
		}
	}

	return results
}

// initNetstack initializes the gvisor netstack
func (pm *PeerMonitor) initNetstack() error {
	if pm.localIP == "" {
		return fmt.Errorf("local IP not provided")
	}

	addr, err := netip.ParseAddr(pm.localIP)
	if err != nil {
		return fmt.Errorf("invalid local IP: %v", err)
	}

	// Create gvisor netstack
	stackOpts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
		HandleLocal:        true,
	}

	pm.ep = channel.New(256, 1420, "") // MTU 1420 (standard WG)
	pm.stack = stack.New(stackOpts)

	// Create NIC
	if err := pm.stack.CreateNIC(1, pm.ep); err != nil {
		return fmt.Errorf("failed to create NIC: %v", err)
	}

	// Add IP address
	ipBytes := addr.As4()
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4(ipBytes).WithPrefix(),
	}

	if err := pm.stack.AddProtocolAddress(1, protoAddr, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("failed to add protocol address: %v", err)
	}

	// Add default route
	pm.stack.AddRoute(tcpip.Route{
		Destination: header.IPv4EmptySubnet,
		NIC:         1,
	})

	// Register filter rule on MiddleDevice
	// We want to intercept packets destined to our local IP
	// But ONLY if they are for ports we are listening on
	pm.middleDev.AddRule(addr, pm.handlePacket)

	// Start packet sender (Stack -> WG)
	pm.nsWg.Add(1)
	go pm.runPacketSender()

	return nil
}

// handlePacket is called by MiddleDevice when a packet arrives for our IP
func (pm *PeerMonitor) handlePacket(packet []byte) bool {
	// Check if it's UDP
	proto, ok := util.GetProtocol(packet)
	if !ok || proto != 17 { // UDP
		return false
	}

	// Check destination port
	port, ok := util.GetDestPort(packet)
	if !ok {
		return false
	}

	// Check if we are listening on this port
	pm.portsLock.Lock()
	active := pm.activePorts[uint16(port)]
	pm.portsLock.Unlock()

	if !active {
		return false
	}

	// Inject into netstack
	version := packet[0] >> 4
	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(packet),
	})

	switch version {
	case 4:
		pm.ep.InjectInbound(ipv4.ProtocolNumber, pkb)
	case 6:
		pm.ep.InjectInbound(ipv6.ProtocolNumber, pkb)
	default:
		pkb.DecRef()
		return false
	}

	pkb.DecRef()
	return true // Handled
}

// runPacketSender reads packets from netstack and injects them into WireGuard
func (pm *PeerMonitor) runPacketSender() {
	defer pm.nsWg.Done()
	logger.Debug("PeerMonitor: Packet sender goroutine started")

	// Use a ticker to periodically check for packets without blocking indefinitely
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-pm.nsCtx.Done():
			logger.Debug("PeerMonitor: Packet sender context cancelled, draining packets")
			// Drain any remaining packets before exiting
			for {
				pkt := pm.ep.Read()
				if pkt == nil {
					break
				}
				pkt.DecRef()
			}
			logger.Debug("PeerMonitor: Packet sender goroutine exiting")
			return
		case <-ticker.C:
			// Try to read packets in batches
			for i := 0; i < 10; i++ {
				pkt := pm.ep.Read()
				if pkt == nil {
					break
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
					pm.middleDev.InjectOutbound(buf)
				}

				pkt.DecRef()
			}
		}
	}
}

// dial creates a UDP connection using the netstack
func (pm *PeerMonitor) dial(network, addr string) (net.Conn, error) {
	if pm.stack == nil {
		return nil, fmt.Errorf("netstack not initialized")
	}

	// Parse remote address
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	// Parse local IP
	localIP, err := netip.ParseAddr(pm.localIP)
	if err != nil {
		return nil, err
	}
	ipBytes := localIP.As4()

	// Create UDP connection
	// We bind to port 0 (ephemeral)
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

	conn, err := gonet.DialUDP(pm.stack, laddr, raddrTcpip, ipv4.ProtocolNumber)
	if err != nil {
		return nil, err
	}

	// Get local port
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	port := uint16(localAddr.Port)

	// Register port
	pm.portsLock.Lock()
	pm.activePorts[port] = true
	pm.portsLock.Unlock()

	// Wrap connection to cleanup port on close
	return &trackedConn{
		Conn: conn,
		pm:   pm,
		port: port,
	}, nil
}

func (pm *PeerMonitor) removePort(port uint16) {
	pm.portsLock.Lock()
	delete(pm.activePorts, port)
	pm.portsLock.Unlock()
}

type trackedConn struct {
	net.Conn
	pm   *PeerMonitor
	port uint16
}

func (c *trackedConn) Close() error {
	c.pm.removePort(c.port)
	if c.Conn != nil {
		return c.Conn.Close()
	}
	return nil
}
