package olm

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/network"
	"github.com/fosrl/newt/util"
	olmDevice "github.com/fosrl/olm/device"
	"github.com/fosrl/olm/peers"
	"github.com/fosrl/olm/websocket"
)

// exitNodeAliasSiteId is the sentinel siteId used when registering exit node
// aliases with the DNS proxy. It is not a real site, and the JIT handler
// treats siteId 0 as "no JIT lookup", which is correct here since the exit
// node is connected directly rather than on demand.
const exitNodeAliasSiteId = 0

// connectExitNode configures a WireGuard peer connection to an exit node, on the
// same interface and WireGuard device already used for site peers. The exit node
// lives in a different address space than the site tunnel, so a secondary address
// (ExitNodeConfig.TunnelIP) is added to the interface for it - the exit node's own
// WireGuard peer entry only accepts traffic sourced from that address. Nothing here
// is persisted; it's purely in-memory WireGuard/routing state, same as site peers.
func (o *Olm) connectExitNode(cfg ExitNodeConfig) error {
	if !o.tunnelRunning {
		return fmt.Errorf("tunnel not running")
	}
	if cfg.PublicKey == "" || cfg.Endpoint == "" || cfg.ServerIP == "" || cfg.TunnelIP == "" {
		return fmt.Errorf("incomplete exit node configuration")
	}

	o.exitNodeMu.Lock()
	defer o.exitNodeMu.Unlock()

	dev := o.dev
	if dev == nil {
		return fmt.Errorf("wireguard device not initialized")
	}

	if o.exitNode != nil && o.exitNode.PublicKey == cfg.PublicKey &&
		o.exitNode.Endpoint == cfg.Endpoint && o.exitNode.ServerIP == cfg.ServerIP &&
		o.exitNode.TunnelIP == cfg.TunnelIP {
		if !slicesEqual(o.exitNode.Aliases, cfg.Aliases) {
			logger.Info("Already connected to exit node %s, updating aliases", cfg.PublicKey)
			o.updateExitNodeAliasesLocked(cfg.Aliases)
		} else {
			logger.Info("Already connected to exit node %s, ignoring duplicate connect message", cfg.PublicKey)
		}
		return nil
	}

	if o.exitNode != nil && o.exitNode.PublicKey != cfg.PublicKey {
		logger.Info("Switching exit nodes, removing previous exit node peer")
		if err := o.removeExitNodePeerLocked(); err != nil {
			logger.Warn("Failed to remove previous exit node peer: %v", err)
		}
	}

	endpoint := cfg.Endpoint
	if !strings.Contains(endpoint, ":") {
		relayPort := cfg.RelayPort
		if relayPort == 0 {
			relayPort = 21820
		}
		endpoint = fmt.Sprintf("%s:%d", endpoint, relayPort)
	}

	resolvedEndpoint, err := util.ResolveDomain(endpoint)
	if err != nil {
		return fmt.Errorf("failed to resolve exit node endpoint: %w", err)
	}

	interfaceName := o.tunnelConfig.InterfaceName
	tunnelIP := cfg.TunnelIP
	if !strings.Contains(tunnelIP, "/") {
		tunnelIP += "/32"
	}
	// Add the secondary address before configuring the peer or route below, and
	// fail closed if it doesn't succeed: AddSecondaryAddress (via AddIPv4Address)
	// refuses to add when no primary address is configured yet, which would
	// otherwise silently make the exit node's address the interface's primary
	// one on mobile platforms (array order is what determines primary there).
	// Bailing out here before touching the WireGuard device at all means there's
	// never a half-configured peer left behind to roll back.
	if err := network.AddSecondaryAddress(interfaceName, tunnelIP); err != nil {
		return fmt.Errorf("failed to add secondary address %s for exit node: %w", tunnelIP, err)
	}

	persistentKeepalive := 0
	if pm := o.getPeerManager(); pm != nil {
		persistentKeepalive = pm.PersistentKeepalive
	}

	allowedIP := strings.Split(cfg.ServerIP, "/")[0] + "/32"

	wgConfig := fmt.Sprintf(`public_key=%s
allowed_ip=%s
endpoint=%s
persistent_keepalive_interval=%d`, util.FixKey(cfg.PublicKey), allowedIP, resolvedEndpoint, persistentKeepalive)

	if err := dev.IpcSet(wgConfig); err != nil {
		return fmt.Errorf("failed to configure exit node peer: %w", err)
	}

	// ServerIP arrives as a bare IP with no CIDR suffix, but AddRouteForServerIP
	// parses it as a CIDR on darwin (to explicitly route the subnet up the tunnel,
	// since unlike Linux, adding the address to the interface does not implicitly
	// create a route for it) - without a mask that parse fails and the route (and
	// its corresponding NetworkSettings entry, which is what surfaces it via the
	// API) is silently never added.
	serverIPForRoute := strings.Split(cfg.ServerIP, "/")[0] + "/32"
	// The route must also be pinned to our exit node tunnel address as its source
	// (darwin route(8) -ifa): the interface carries a second address for the site
	// tunnel too, and without an explicit source darwin picks that one instead,
	// which the exit node's WireGuard AllowedIPs filtering then silently drops.
	tunnelIPForRoute := strings.Split(cfg.TunnelIP, "/")[0]
	if err := network.AddRouteForServerIPWithSource(serverIPForRoute, interfaceName, tunnelIPForRoute); err != nil {
		logger.Warn("Failed to add route for exit node server IP: %v", err)
	}

	// On macOS/iOS NetworkExtension, the OS can't reliably pin an outbound socket's
	// source address to this interface's secondary address the way BSD route(8)
	// -ifa does for the CLI path above - unbound sockets still get the primary
	// (site tunnel) address stamped as source even for traffic destined to the
	// exit node, which the exit node's WireGuard AllowedIPs filtering then
	// silently drops. Fix it in-tunnel: intercept outbound packets addressed to
	// the exit node and rewrite their source back to tunnelIP before WireGuard
	// encrypts them.
	//
	// That alone isn't enough for anything that expects a reply (TCP, or any
	// request/response over UDP): rewriting the outbound packet only changes
	// what goes out on the wire - it doesn't change the OS's own connection
	// state, which already recorded the *wrong* (primary) address as this
	// socket's local address at connect()/send() time, before the packet ever
	// reached this interception point. When the exit node's reply comes back
	// correctly addressed to tunnelIP, the OS can't match it to a socket whose
	// local address it thinks is the primary tunnel IP, and silently drops it -
	// the connection hangs even though the corrected request reached the server
	// fine. So also intercept inbound replies from the exit node and translate
	// their destination back to the primary address, but only for flows we
	// actually corrected outbound (tracked by ExitNodeNAT) - a socket that
	// happened to already be bound to the correct address must be left alone.
	//
	// The fast path (address already correct) is cheap enough - a 4-byte
	// comparison and nothing else when no rewrite is needed - to just leave
	// this on unconditionally rather than gate it per-GOOS. Every platform's
	// route-based source pinning (AddRouteForServerIPWithSource and friends)
	// is a best-effort hint to the OS, not a guarantee: Android's
	// VpnService.Builder only supports plain destination/prefix routes with
	// no source/gateway at all, and even where the OS route can carry a
	// source, an unbound socket's address selection is the OS's call, not
	// ours. Keeping this rule active everywhere means any platform that gets
	// the source wrong for any reason - not just the ones we've already hit
	// this bug on - self-corrects instead of silently blackholing exit node
	// traffic.
	if o.middleDev != nil {
		serverAddr, errS := netip.ParseAddr(strings.Split(cfg.ServerIP, "/")[0])
		correctAddr, errC := netip.ParseAddr(tunnelIPForRoute)
		switch {
		case errS != nil || errC != nil || !correctAddr.Is4():
			logger.Warn("Exit node NAT: skipping source-NAT setup, invalid address (server=%v tunnel=%v)", errS, errC)
		case !o.primaryTunnelIP.IsValid() || !o.primaryTunnelIP.Is4():
			logger.Warn("Exit node NAT: skipping source-NAT setup, no primary tunnel IP recorded")
		default:
			correctSrc := correctAddr.As4()
			wrongSrc := o.primaryTunnelIP.As4()
			serverSrc := serverAddr.As4()
			nat := olmDevice.NewExitNodeNAT()

			o.middleDev.AddRule(serverAddr, func(packet []byte) bool {
				nat.FixOutboundSource(packet, correctSrc)
				return false
			})
			o.middleDev.AddRule(correctAddr, func(packet []byte) bool {
				// Only packets that actually came from the exit node's own
				// peer should ever be translated - this rule's key (tunnelIP)
				// is also used by the ICMP connectivity monitor's own address,
				// so a defensive source check keeps this from ever touching
				// unrelated traffic that happens to be addressed to tunnelIP.
				if olmDevice.IPv4SourceEquals(packet, serverSrc) {
					nat.FixInboundDest(packet, wrongSrc)
				}
				return false
			})

			logger.Debug("Exit node NAT: intercepting traffic to %s, translating source/dest between %s (primary) and %s (exit node secondary)", serverAddr, o.primaryTunnelIP, correctAddr)
		}
	}

	cfgCopy := cfg
	o.exitNode = &cfgCopy

	if o.dnsProxy != nil {
		serverIP := net.ParseIP(cfg.ServerIP)
		if serverIP != nil {
			for _, alias := range cfg.Aliases {
				logger.Debug("Adding alias %s to the edit node", alias)
				if err := o.dnsProxy.AddDNSRecord(alias, serverIP, exitNodeAliasSiteId); err != nil {
					logger.Warn("Failed to add DNS record for exit node alias %s: %v", alias, err)
				}
			}
		}
	}

	if pm := o.getPeerManager(); pm != nil {
		pm.SetExitNode(strings.Split(cfg.ServerIP, "/")[0], strings.Split(cfg.TunnelIP, "/")[0])
	}

	logger.Info("Connected to exit node at %s", resolvedEndpoint)
	return nil
}

// disconnectExitNode tears down the current exit node peer connection, if any.
func (o *Olm) disconnectExitNode() error {
	o.exitNodeMu.Lock()
	defer o.exitNodeMu.Unlock()

	return o.removeExitNodePeerLocked()
}

// removeExitNodePeerLocked removes the current exit node peer, its secondary
// interface address, and its server IP route. Must be called with exitNodeMu held.
func (o *Olm) removeExitNodePeerLocked() error {
	if o.exitNode == nil {
		return nil
	}
	cfg := o.exitNode
	o.exitNode = nil

	if pm := o.getPeerManager(); pm != nil {
		pm.ClearExitNode()
	}

	if o.dnsProxy != nil {
		serverIP := net.ParseIP(cfg.ServerIP)
		if serverIP != nil {
			for _, alias := range cfg.Aliases {
				o.dnsProxy.RemoveDNSRecordForSite(alias, serverIP, exitNodeAliasSiteId)
			}
		}
	}

	if o.dev != nil {
		if err := peers.RemovePeer(o.dev, 0, cfg.PublicKey); err != nil {
			logger.Warn("Failed to remove exit node peer: %v", err)
		}
	}

	interfaceName := o.tunnelConfig.InterfaceName

	if o.middleDev != nil {
		if serverAddr, err := netip.ParseAddr(strings.Split(cfg.ServerIP, "/")[0]); err == nil {
			o.middleDev.RemoveRule(serverAddr)
		}
		// Also removes the ICMP connectivity monitor's own rule under this same
		// key (pm.ClearExitNode, called just above, already does this too - see
		// RemoveRule's doc comment on it clearing every rule for a key rather
		// than being handler-specific), so this call is normally a harmless
		// no-op by the time it runs; kept for defensiveness/independence from
		// that other subsystem's cleanup ordering.
		if tunnelAddr, err := netip.ParseAddr(strings.Split(cfg.TunnelIP, "/")[0]); err == nil {
			o.middleDev.RemoveRule(tunnelAddr)
		}
	}

	serverIPForRoute := strings.Split(cfg.ServerIP, "/")[0] + "/32"
	tunnelIPForRoute := strings.Split(cfg.TunnelIP, "/")[0]
	if err := network.RemoveRouteForServerIPWithSource(serverIPForRoute, interfaceName, tunnelIPForRoute); err != nil {
		logger.Warn("Failed to remove route for exit node server IP: %v", err)
	}

	tunnelIP := cfg.TunnelIP
	if !strings.Contains(tunnelIP, "/") {
		tunnelIP += "/32"
	}
	if err := network.RemoveSecondaryAddress(interfaceName, tunnelIP); err != nil {
		logger.Warn("Failed to remove secondary address %s for exit node: %v", tunnelIP, err)
	}

	logger.Info("Disconnected from exit node")
	return nil
}

// syncExitNodeConnection reconciles the client's own exit node connection (used
// for site resources hosted on the exit node) with the desired state sent in a
// sync message - connecting, switching, updating aliases, or disconnecting as
// needed. This mirrors what the initial "olm/wg/connect" message does, so a
// client that reconnects with a stale exit node assignment (or none at all)
// converges without needing to fully re-register.
func (o *Olm) syncExitNodeConnection(cfg *ExitNodeConfig) {
	if !o.tunnelRunning {
		logger.Debug("Tunnel stopped, ignoring exit node sync")
		return
	}

	if cfg == nil || !cfg.Connect {
		if err := o.disconnectExitNode(); err != nil {
			logger.Error("Sync: Failed to disconnect from exit node: %v", err)
		}
		return
	}

	if err := o.connectExitNode(*cfg); err != nil {
		logger.Error("Sync: Failed to connect to exit node: %v", err)
	}
}

// updateExitNodeAliasesLocked reconciles the currently connected exit node's
// aliases with newAliases, adding new ones before removing stale ones so a
// rename never has a gap in resolution. Must be called with exitNodeMu held.
func (o *Olm) updateExitNodeAliasesLocked(newAliases []string) {
	if o.exitNode == nil {
		return
	}

	added := stringSliceDiff(newAliases, o.exitNode.Aliases)
	removed := stringSliceDiff(o.exitNode.Aliases, newAliases)

	serverIP := net.ParseIP(o.exitNode.ServerIP)
	if o.dnsProxy != nil && serverIP != nil {
		for _, alias := range added {
			if err := o.dnsProxy.AddDNSRecord(alias, serverIP, exitNodeAliasSiteId); err != nil {
				logger.Warn("Failed to add DNS record for exit node alias %s: %v", alias, err)
			}
		}
		for _, alias := range removed {
			o.dnsProxy.RemoveDNSRecordForSite(alias, serverIP, exitNodeAliasSiteId)
		}
	}

	o.exitNode.Aliases = applyStringListUpdate(o.exitNode.Aliases, removed, added)
}

// stringSliceDiff returns the elements of a that are not present in b.
func stringSliceDiff(a, b []string) []string {
	inB := make(map[string]struct{}, len(b))
	for _, s := range b {
		inB[s] = struct{}{}
	}
	diff := make([]string, 0, len(a))
	for _, s := range a {
		if _, ok := inB[s]; !ok {
			diff = append(diff, s)
		}
	}
	return diff
}

// handleExitNodeConnect handles a server-initiated request to connect to (or switch to)
// an exit node, delivered as a full ExitNodeConfig payload.
func (o *Olm) handleExitNodeConnect(msg websocket.WSMessage) {
	logger.Debug("Received exit node connect message: %v", msg.Data)

	if !o.tunnelRunning {
		logger.Debug("Tunnel stopped, ignoring exit node connect message")
		return
	}

	// The primary tunnel interface must already be configured before an exit
	// node's secondary address can safely be added (see the ordering
	// enforcement in connectExitNode) - o.registered is only set true after
	// that happens in handleConnect. This guards against a stray/early
	// message reaching connectExitNode before then.
	if !o.registered {
		logger.Debug("Not yet registered, ignoring exit node connect message")
		return
	}

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Error("Error marshaling exit node connect data: %v", err)
		return
	}

	var cfg ExitNodeConfig
	if err := json.Unmarshal(jsonData, &cfg); err != nil {
		logger.Error("Error unmarshaling exit node connect data: %v", err)
		return
	}

	if !cfg.Connect {
		logger.Debug("Exit node connect message has connect=false, disconnecting instead")
		if err := o.disconnectExitNode(); err != nil {
			logger.Error("Failed to disconnect from exit node: %v", err)
		}
		return
	}

	if err := o.connectExitNode(cfg); err != nil {
		logger.Error("Failed to connect to exit node: %v", err)
	}
}

// handleExitNodeDisconnect handles a server-initiated request to disconnect from the
// currently connected exit node.
func (o *Olm) handleExitNodeDisconnect(msg websocket.WSMessage) {
	logger.Debug("Received exit node disconnect message: %v", msg.Data)

	if !o.tunnelRunning {
		logger.Debug("Tunnel stopped, ignoring exit node disconnect message")
		return
	}

	if err := o.disconnectExitNode(); err != nil {
		logger.Error("Failed to disconnect from exit node: %v", err)
	}
}

// handleExitNodeUpdateData handles a server-initiated request to change data
// associated with the currently connected exit node, such as its aliases (e.g. a
// resource was renamed). Unlike site aliases, there is no per-alias address to
// track since every exit node alias resolves to the exit node's own ServerIP.
func (o *Olm) handleExitNodeUpdateData(msg websocket.WSMessage) {
	logger.Debug("Received exit node update data message: %v", msg.Data)

	if !o.tunnelRunning {
		logger.Debug("Tunnel stopped, ignoring exit node update data message")
		return
	}

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Error("Error marshaling exit node update data: %v", err)
		return
	}

	var update ExitNodeUpdateData
	if err := json.Unmarshal(jsonData, &update); err != nil {
		logger.Error("Error unmarshaling exit node update data: %v", err)
		return
	}

	o.exitNodeMu.Lock()
	defer o.exitNodeMu.Unlock()

	if o.exitNode == nil {
		logger.Debug("Ignoring exit node update data message: no exit node connected")
		return
	}

	serverIP := net.ParseIP(o.exitNode.ServerIP)

	// Add new aliases BEFORE removing old ones, same as site aliases, so a rename
	// that keeps the same underlying address never has a gap in resolution.
	if o.dnsProxy != nil && serverIP != nil {
		for _, alias := range update.NewAliases {
			if err := o.dnsProxy.AddDNSRecord(alias, serverIP, exitNodeAliasSiteId); err != nil {
				logger.Warn("Failed to add DNS record for exit node alias %s: %v", alias, err)
			}
		}
	}

	if o.dnsProxy != nil && serverIP != nil {
		for _, alias := range update.OldAliases {
			o.dnsProxy.RemoveDNSRecordForSite(alias, serverIP, exitNodeAliasSiteId)
		}
	}

	o.exitNode.Aliases = applyStringListUpdate(o.exitNode.Aliases, update.OldAliases, update.NewAliases)

	logger.Info("Successfully updated exit node data")
}

// applyStringListUpdate returns list with every entry in removed dropped and every
// entry in added appended, preserving the add-before-remove semantics of the caller.
func applyStringListUpdate(list, removed, added []string) []string {
	next := make([]string, 0, len(list)+len(added))
	next = append(next, list...)
	next = append(next, added...)

	removedSet := make(map[string]struct{}, len(removed))
	for _, alias := range removed {
		removedSet[alias] = struct{}{}
	}

	filtered := next[:0]
	for _, alias := range next {
		if _, ok := removedSet[alias]; ok {
			continue
		}
		filtered = append(filtered, alias)
	}
	return filtered
}
