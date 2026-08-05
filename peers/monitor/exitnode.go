package monitor

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/fosrl/newt/logger"
	"golang.org/x/net/icmp"
	xipv4 "golang.org/x/net/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip"
	gipv4 "gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	gstack "gvisor.dev/gvisor/pkg/tcpip/stack"
	gicmp "gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	exitNodePingInterval    = 3 * time.Second
	exitNodePingTimeout     = 1 * time.Second
	exitNodePingMaxAttempts = 3
)

// SetExitNode starts (or, if the exit node changed, restarts) ICMP
// connectivity monitoring of the exit node at serverIP. tunnelIP is the
// secondary address assigned to us for this exit node (ExitNodeConfig.TunnelIP) -
// the exit node's WireGuard peer entry only accepts traffic sourced from that
// address, so probes must be sourced from it rather than the site tunnel IP.
// Both serverIP and tunnelIP must be bare IP addresses (no CIDR suffix).
func (pm *PeerMonitor) SetExitNode(serverIP, tunnelIP string) {
	pm.exitNodeMu.Lock()
	if pm.exitNodeCancel != nil && pm.exitNodeServerIP == serverIP && pm.exitNodeTunnelIP == tunnelIP {
		pm.exitNodeMu.Unlock()
		return
	}
	prevTunnelIP := pm.exitNodeTunnelIP
	if pm.exitNodeCancel != nil {
		pm.exitNodeCancel()
	}
	pm.exitNodeServerIP = serverIP
	pm.exitNodeTunnelIP = tunnelIP
	ctx, cancel := context.WithCancel(context.Background())
	pm.exitNodeCancel = cancel
	pm.exitNodeMu.Unlock()

	if prevTunnelIP != "" && prevTunnelIP != tunnelIP {
		pm.removeExitNodeAddress(prevTunnelIP)
	}
	if tunnelIP != prevTunnelIP {
		if err := pm.addExitNodeAddress(tunnelIP); err != nil {
			logger.Error("Failed to register exit node tunnel address %s: %v", tunnelIP, err)
		}
	}

	logger.Info("Started exit node connectivity monitor for %s (via %s)", serverIP, tunnelIP)
	go pm.runExitNodeMonitor(ctx, serverIP, tunnelIP)
}

// ClearExitNode stops ICMP monitoring of the exit node and clears its status
// from the API.
func (pm *PeerMonitor) ClearExitNode() {
	pm.exitNodeMu.Lock()
	if pm.exitNodeCancel != nil {
		pm.exitNodeCancel()
		pm.exitNodeCancel = nil
	}
	tunnelIP := pm.exitNodeTunnelIP
	pm.exitNodeServerIP = ""
	pm.exitNodeTunnelIP = ""
	pm.exitNodeMu.Unlock()

	if tunnelIP != "" {
		pm.removeExitNodeAddress(tunnelIP)
	}

	if pm.apiServer != nil {
		pm.apiServer.ClearExitNodeStatus()
	}

	logger.Info("Stopped exit node connectivity monitor")
}

// addExitNodeAddress registers tunnelIP as a protocol address on the peer
// monitor's netstack NIC and adds a MiddleDevice rule so ICMP replies destined
// to it are intercepted and redirected into the netstack instead of being
// delivered to the host TUN device.
func (pm *PeerMonitor) addExitNodeAddress(tunnelIP string) error {
	pm.mutex.Lock()
	st := pm.stack
	pm.mutex.Unlock()

	if st == nil {
		return fmt.Errorf("netstack not initialized")
	}

	addr, err := netip.ParseAddr(tunnelIP)
	if err != nil {
		return fmt.Errorf("invalid tunnel IP: %w", err)
	}

	protoAddr := tcpip.ProtocolAddress{
		Protocol:          gipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4(addr.As4()).WithPrefix(),
	}
	if tcpipErr := st.AddProtocolAddress(1, protoAddr, gstack.AddressProperties{}); tcpipErr != nil {
		return fmt.Errorf("failed to add protocol address: %s", tcpipErr)
	}

	pm.middleDev.AddRule(addr, pm.handlePacket)
	return nil
}

// removeExitNodeAddress undoes addExitNodeAddress.
func (pm *PeerMonitor) removeExitNodeAddress(tunnelIP string) {
	addr, err := netip.ParseAddr(tunnelIP)
	if err != nil {
		return
	}

	pm.middleDev.RemoveRule(addr)

	pm.mutex.Lock()
	st := pm.stack
	pm.mutex.Unlock()

	if st != nil {
		st.RemoveAddress(1, tcpip.AddrFrom4(addr.As4()))
	}
}

// runExitNodeMonitor periodically pings the exit node and reports its status
// to the API server until ctx is cancelled.
func (pm *PeerMonitor) runExitNodeMonitor(ctx context.Context, serverIP, tunnelIP string) {
	check := func() {
		var (
			connected bool
			rtt       time.Duration
		)
		for attempt := 0; attempt < exitNodePingMaxAttempts; attempt++ {
			if d, err := pm.pingExitNode(serverIP, tunnelIP, exitNodePingTimeout); err == nil {
				connected = true
				rtt = d
				break
			} else {
				logger.Debug("Exit node ping attempt %d/%d to %s failed: %v", attempt+1, exitNodePingMaxAttempts, serverIP, err)
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
		}
		if pm.apiServer != nil {
			pm.apiServer.SetExitNodeStatus(connected, rtt, serverIP)
		}
	}

	check()

	ticker := time.NewTicker(exitNodePingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			check()
		}
	}
}

// pingExitNode sends a single ICMP echo request from localTunnelIP to dst and
// waits up to timeout for the matching reply. The request is built and read
// directly on the peer monitor's gvisor netstack, so it's injected into (and
// intercepted from) the WireGuard device via MiddleDevice - it never touches
// the host's real network stack, matching how the UDP peer tests above work.
func (pm *PeerMonitor) pingExitNode(dst, localTunnelIP string, timeout time.Duration) (time.Duration, error) {
	pm.mutex.Lock()
	st := pm.stack
	pm.mutex.Unlock()

	if st == nil {
		return 0, fmt.Errorf("netstack not initialized")
	}

	dstAddr, err := netip.ParseAddr(dst)
	if err != nil {
		return 0, fmt.Errorf("invalid destination address: %w", err)
	}
	localAddr, err := netip.ParseAddr(localTunnelIP)
	if err != nil {
		return 0, fmt.Errorf("invalid local address: %w", err)
	}

	var wq waiter.Queue
	ep, tcpipErr := st.NewEndpoint(gicmp.ProtocolNumber4, gipv4.ProtocolNumber, &wq)
	if tcpipErr != nil {
		return 0, fmt.Errorf("failed to create ICMP endpoint: %s", tcpipErr)
	}
	defer ep.Close()

	if tcpipErr := ep.Bind(tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(localAddr.AsSlice())}); tcpipErr != nil {
		return 0, fmt.Errorf("failed to bind ICMP endpoint: %s", tcpipErr)
	}

	// gvisor's ICMP endpoint overwrites whatever Identifier we put in the outgoing
	// echo with its own bound "port" (assigned above by Bind), and demuxes incoming
	// Echo Replies by that same value - so we must use it, not one we generate
	// ourselves, both for the outgoing message and to register with handlePacket's
	// filter below.
	laddr, tcpipErr := ep.GetLocalAddress()
	if tcpipErr != nil {
		return 0, fmt.Errorf("failed to get local ICMP endpoint address: %s", tcpipErr)
	}
	echoID := int(laddr.Port)

	pm.portsLock.Lock()
	pm.activeICMPIdents[laddr.Port] = true
	pm.portsLock.Unlock()
	defer func() {
		pm.portsLock.Lock()
		delete(pm.activeICMPIdents, laddr.Port)
		pm.portsLock.Unlock()
	}()

	if tcpipErr := ep.Connect(tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(dstAddr.AsSlice())}); tcpipErr != nil {
		return 0, fmt.Errorf("failed to connect ICMP endpoint: %s", tcpipErr)
	}

	requestPing := icmp.Echo{
		ID:   echoID,
		Seq:  1,
		Data: []byte("olmping"),
	}
	icmpBytes, err := (&icmp.Message{Type: xipv4.ICMPTypeEcho, Code: 0, Body: &requestPing}).Marshal(nil)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal ICMP message: %w", err)
	}

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventIn)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	start := time.Now()

	if _, tcpipErr := ep.Write(bytes.NewReader(icmpBytes), tcpip.WriteOptions{}); tcpipErr != nil {
		return 0, fmt.Errorf("failed to write ICMP echo request: %s", tcpipErr)
	}

	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	readBuf := make([]byte, 1500)
	for {
		select {
		case <-deadline.C:
			return 0, fmt.Errorf("ping to %s timed out", dst)
		case <-notifyCh:
			w := tcpip.SliceWriter(readBuf)
			res, tcpipErr := ep.Read(&w, tcpip.ReadOptions{})
			if tcpipErr != nil {
				continue
			}

			reply, err := icmp.ParseMessage(1, readBuf[:res.Count])
			if err != nil {
				continue
			}
			replyEcho, ok := reply.Body.(*icmp.Echo)
			if !ok || replyEcho.ID != echoID || replyEcho.Seq != requestPing.Seq {
				continue
			}

			return time.Since(start), nil
		}
	}
}
