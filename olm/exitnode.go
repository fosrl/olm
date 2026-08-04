package olm

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/network"
	"github.com/fosrl/newt/util"
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

	interfaceName := o.tunnelConfig.InterfaceName
	tunnelIP := cfg.TunnelIP
	if !strings.Contains(tunnelIP, "/") {
		tunnelIP += "/32"
	}
	if err := network.AddSecondaryAddress(interfaceName, tunnelIP); err != nil {
		logger.Warn("Failed to add secondary address %s for exit node: %v", tunnelIP, err)
	}

	if err := network.AddRouteForServerIP(cfg.ServerIP, interfaceName); err != nil {
		logger.Warn("Failed to add route for exit node server IP: %v", err)
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
	if err := network.RemoveRouteForServerIP(cfg.ServerIP, interfaceName); err != nil {
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
