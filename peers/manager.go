package peers

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fosrl/newt/bind"
	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/network"
	olmDevice "github.com/fosrl/olm/device"
	"github.com/fosrl/olm/dns"
	"github.com/fosrl/olm/peers/monitor"
	"github.com/fosrl/olm/websocket"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// PeerStatusCallback is called when a peer's connection status changes
type PeerStatusCallback func(siteID int, connected bool, rtt time.Duration)

// HolepunchStatusCallback is called when holepunch connection status changes
// This is an alias for monitor.HolepunchStatusCallback
type HolepunchStatusCallback = monitor.HolepunchStatusCallback

// PeerManagerConfig contains the configuration for creating a PeerManager
type PeerManagerConfig struct {
	Device        *device.Device
	DNSProxy      *dns.DNSProxy
	InterfaceName string
	PrivateKey    wgtypes.Key
	// For peer monitoring
	MiddleDev  *olmDevice.MiddleDevice
	LocalIP    string
	SharedBind *bind.SharedBind
	// WSClient is optional - if nil, relay messages won't be sent
	WSClient *websocket.Client
	// StatusCallback is called when peer connection status changes
	StatusCallback PeerStatusCallback
}

type PeerManager struct {
	mu            sync.RWMutex
	device        *device.Device
	peers         map[int]SiteConfig
	peerMonitor   *monitor.PeerMonitor
	dnsProxy      *dns.DNSProxy
	interfaceName string
	privateKey    wgtypes.Key
	// allowedIPOwners tracks which peer currently "owns" each allowed IP in WireGuard
	// key is the CIDR string, value is the siteId that has it configured in WG
	allowedIPOwners map[string]int
	// allowedIPClaims tracks all peers that claim each allowed IP
	// key is the CIDR string, value is a set of siteIds that want this IP
	allowedIPClaims map[string]map[int]bool
	// statusCallback is called when peer connection status changes
	statusCallback PeerStatusCallback
}

// NewPeerManager creates a new PeerManager with an internal PeerMonitor
func NewPeerManager(config PeerManagerConfig) *PeerManager {
	pm := &PeerManager{
		device:          config.Device,
		peers:           make(map[int]SiteConfig),
		dnsProxy:        config.DNSProxy,
		interfaceName:   config.InterfaceName,
		privateKey:      config.PrivateKey,
		allowedIPOwners: make(map[string]int),
		allowedIPClaims: make(map[string]map[int]bool),
		statusCallback:  config.StatusCallback,
	}

	// Create the peer monitor
	pm.peerMonitor = monitor.NewPeerMonitor(
		func(siteID int, connected bool, rtt time.Duration) {
			// Call the external status callback if set
			if pm.statusCallback != nil {
				pm.statusCallback(siteID, connected, rtt)
			}
		},
		config.WSClient,
		config.MiddleDev,
		config.LocalIP,
		config.SharedBind,
	)

	return pm
}

func (pm *PeerManager) GetPeer(siteId int) (SiteConfig, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	peer, ok := pm.peers[siteId]
	return peer, ok
}

func (pm *PeerManager) GetAllPeers() []SiteConfig {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	peers := make([]SiteConfig, 0, len(pm.peers))
	for _, peer := range pm.peers {
		peers = append(peers, peer)
	}
	return peers
}

func (pm *PeerManager) AddPeer(siteConfig SiteConfig, endpoint string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// build the allowed IPs list from the remote subnets and aliases and add them to the peer
	allowedIPs := make([]string, 0, len(siteConfig.RemoteSubnets)+len(siteConfig.Aliases))
	allowedIPs = append(allowedIPs, siteConfig.RemoteSubnets...)
	for _, alias := range siteConfig.Aliases {
		allowedIPs = append(allowedIPs, alias.AliasAddress+"/32")
	}
	siteConfig.AllowedIps = allowedIPs

	// Register claims for all allowed IPs and determine which ones this peer will own
	ownedIPs := make([]string, 0, len(allowedIPs))
	for _, ip := range allowedIPs {
		pm.claimAllowedIP(siteConfig.SiteId, ip)
		// Check if this peer became the owner
		if pm.allowedIPOwners[ip] == siteConfig.SiteId {
			ownedIPs = append(ownedIPs, ip)
		}
	}

	// Create a config with only the owned IPs for WireGuard
	wgConfig := siteConfig
	wgConfig.AllowedIps = ownedIPs

	if err := ConfigurePeer(pm.device, wgConfig, pm.privateKey, endpoint); err != nil {
		return err
	}

	if err := network.AddRouteForServerIP(siteConfig.ServerIP, pm.interfaceName); err != nil {
		logger.Error("Failed to add route for server IP: %v", err)
	}
	if err := network.AddRoutes(siteConfig.RemoteSubnets, pm.interfaceName); err != nil {
		logger.Error("Failed to add routes for remote subnets: %v", err)
	}
	for _, alias := range siteConfig.Aliases {
		address := net.ParseIP(alias.AliasAddress)
		if address == nil {
			continue
		}
		pm.dnsProxy.AddDNSRecord(alias.Alias, address)
	}

	monitorAddress := strings.Split(siteConfig.ServerIP, "/")[0]
	monitorPeer := net.JoinHostPort(monitorAddress, strconv.Itoa(int(siteConfig.ServerPort+1))) // +1 for the monitor port

	err := pm.peerMonitor.AddPeer(siteConfig.SiteId, monitorPeer)
	if err != nil {
		logger.Warn("Failed to setup monitoring for site %d: %v", siteConfig.SiteId, err)
	} else {
		logger.Info("Started monitoring for site %d at %s", siteConfig.SiteId, monitorPeer)
	}

	pm.peers[siteConfig.SiteId] = siteConfig
	return nil
}

func (pm *PeerManager) RemovePeer(siteId int) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	peer, exists := pm.peers[siteId]
	if !exists {
		return fmt.Errorf("peer with site ID %d not found", siteId)
	}

	if err := RemovePeer(pm.device, siteId, peer.PublicKey); err != nil {
		return err
	}

	if err := network.RemoveRouteForServerIP(peer.ServerIP, pm.interfaceName); err != nil {
		logger.Error("Failed to remove route for server IP: %v", err)
	}

	if err := network.RemoveRoutes(peer.RemoteSubnets); err != nil {
		logger.Error("Failed to remove routes for remote subnets: %v", err)
	}

	// For aliases
	for _, alias := range peer.Aliases {
		address := net.ParseIP(alias.AliasAddress)
		if address == nil {
			continue
		}
		pm.dnsProxy.RemoveDNSRecord(alias.Alias, address)
	}

	// Release all IP claims and promote other peers as needed
	// Collect promotions first to avoid modifying while iterating
	type promotion struct {
		newOwner int
		cidr     string
	}
	var promotions []promotion

	for _, ip := range peer.AllowedIps {
		newOwner, promoted := pm.releaseAllowedIP(siteId, ip)
		if promoted && newOwner >= 0 {
			promotions = append(promotions, promotion{newOwner: newOwner, cidr: ip})
		}
	}

	// Apply promotions - update WireGuard config for newly promoted peers
	// Group by peer to avoid multiple config updates
	promotedPeers := make(map[int]bool)
	for _, p := range promotions {
		promotedPeers[p.newOwner] = true
		logger.Info("Promoted peer %d to owner of IP %s", p.newOwner, p.cidr)
	}

	for promotedPeerId := range promotedPeers {
		if promotedPeer, exists := pm.peers[promotedPeerId]; exists {
			// Build the list of IPs this peer now owns
			ownedIPs := pm.getOwnedAllowedIPs(promotedPeerId)
			wgConfig := promotedPeer
			wgConfig.AllowedIps = ownedIPs
			if err := ConfigurePeer(pm.device, wgConfig, pm.privateKey, promotedPeer.Endpoint); err != nil {
				logger.Error("Failed to update promoted peer %d: %v", promotedPeerId, err)
			}
		}
	}

	// Stop monitoring this peer
	pm.peerMonitor.RemovePeer(siteId)
	logger.Info("Stopped monitoring for site %d", siteId)

	delete(pm.peers, siteId)
	return nil
}

func (pm *PeerManager) UpdatePeer(siteConfig SiteConfig, endpoint string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	oldPeer, exists := pm.peers[siteConfig.SiteId]
	if !exists {
		return fmt.Errorf("peer with site ID %d not found", siteConfig.SiteId)
	}

	// If public key changed, remove old peer first
	if siteConfig.PublicKey != oldPeer.PublicKey {
		if err := RemovePeer(pm.device, siteConfig.SiteId, oldPeer.PublicKey); err != nil {
			logger.Error("Failed to remove old peer: %v", err)
		}
	}

	// Build the new allowed IPs list
	newAllowedIPs := make([]string, 0, len(siteConfig.RemoteSubnets)+len(siteConfig.Aliases))
	newAllowedIPs = append(newAllowedIPs, siteConfig.RemoteSubnets...)
	for _, alias := range siteConfig.Aliases {
		newAllowedIPs = append(newAllowedIPs, alias.AliasAddress+"/32")
	}
	siteConfig.AllowedIps = newAllowedIPs

	// Handle allowed IP claim changes
	oldAllowedIPs := make(map[string]bool)
	for _, ip := range oldPeer.AllowedIps {
		oldAllowedIPs[ip] = true
	}
	newAllowedIPsSet := make(map[string]bool)
	for _, ip := range newAllowedIPs {
		newAllowedIPsSet[ip] = true
	}

	// Track peers that need WireGuard config updates due to promotions
	peersToUpdate := make(map[int]bool)

	// Release claims for removed IPs and handle promotions
	for ip := range oldAllowedIPs {
		if !newAllowedIPsSet[ip] {
			newOwner, promoted := pm.releaseAllowedIP(siteConfig.SiteId, ip)
			if promoted && newOwner >= 0 {
				peersToUpdate[newOwner] = true
				logger.Info("Promoted peer %d to owner of IP %s", newOwner, ip)
			}
		}
	}

	// Add claims for new IPs
	for ip := range newAllowedIPsSet {
		if !oldAllowedIPs[ip] {
			pm.claimAllowedIP(siteConfig.SiteId, ip)
		}
	}

	// Build the list of IPs this peer owns for WireGuard config
	ownedIPs := pm.getOwnedAllowedIPs(siteConfig.SiteId)
	wgConfig := siteConfig
	wgConfig.AllowedIps = ownedIPs

	if err := ConfigurePeer(pm.device, wgConfig, pm.privateKey, endpoint); err != nil {
		return err
	}

	// Update WireGuard config for any promoted peers
	for promotedPeerId := range peersToUpdate {
		if promotedPeer, exists := pm.peers[promotedPeerId]; exists {
			promotedOwnedIPs := pm.getOwnedAllowedIPs(promotedPeerId)
			promotedWgConfig := promotedPeer
			promotedWgConfig.AllowedIps = promotedOwnedIPs
			if err := ConfigurePeer(pm.device, promotedWgConfig, pm.privateKey, promotedPeer.Endpoint); err != nil {
				logger.Error("Failed to update promoted peer %d: %v", promotedPeerId, err)
			}
		}
	}

	// Handle remote subnet route changes
	// Calculate added and removed subnets
	oldSubnets := make(map[string]bool)
	for _, s := range oldPeer.RemoteSubnets {
		oldSubnets[s] = true
	}
	newSubnets := make(map[string]bool)
	for _, s := range siteConfig.RemoteSubnets {
		newSubnets[s] = true
	}

	var addedSubnets []string
	var removedSubnets []string

	for s := range newSubnets {
		if !oldSubnets[s] {
			addedSubnets = append(addedSubnets, s)
		}
	}
	for s := range oldSubnets {
		if !newSubnets[s] {
			removedSubnets = append(removedSubnets, s)
		}
	}

	// Remove routes for removed subnets
	if len(removedSubnets) > 0 {
		if err := network.RemoveRoutes(removedSubnets); err != nil {
			logger.Error("Failed to remove routes: %v", err)
		}
	}

	// Add routes for added subnets
	if len(addedSubnets) > 0 {
		if err := network.AddRoutes(addedSubnets, pm.interfaceName); err != nil {
			logger.Error("Failed to add routes: %v", err)
		}
	}

	// Update aliases
	// Remove old aliases
	for _, alias := range oldPeer.Aliases {
		address := net.ParseIP(alias.AliasAddress)
		if address == nil {
			continue
		}
		pm.dnsProxy.RemoveDNSRecord(alias.Alias, address)
	}
	// Add new aliases
	for _, alias := range siteConfig.Aliases {
		address := net.ParseIP(alias.AliasAddress)
		if address == nil {
			continue
		}
		pm.dnsProxy.AddDNSRecord(alias.Alias, address)
	}

	pm.peers[siteConfig.SiteId] = siteConfig
	return nil
}

// claimAllowedIP registers a peer's claim to an allowed IP.
// If no other peer owns it in WireGuard, this peer becomes the owner.
// Must be called with lock held.
func (pm *PeerManager) claimAllowedIP(siteId int, cidr string) {
	// Add to claims
	if pm.allowedIPClaims[cidr] == nil {
		pm.allowedIPClaims[cidr] = make(map[int]bool)
	}
	pm.allowedIPClaims[cidr][siteId] = true

	// If no owner yet, this peer becomes the owner
	if _, hasOwner := pm.allowedIPOwners[cidr]; !hasOwner {
		pm.allowedIPOwners[cidr] = siteId
	}
}

// releaseAllowedIP removes a peer's claim to an allowed IP.
// If this peer was the owner, it promotes another claimant to owner.
// Returns the new owner's siteId (or -1 if no new owner) and whether promotion occurred.
// Must be called with lock held.
func (pm *PeerManager) releaseAllowedIP(siteId int, cidr string) (newOwner int, promoted bool) {
	// Remove from claims
	if claims, exists := pm.allowedIPClaims[cidr]; exists {
		delete(claims, siteId)
		if len(claims) == 0 {
			delete(pm.allowedIPClaims, cidr)
		}
	}

	// Check if this peer was the owner
	owner, isOwned := pm.allowedIPOwners[cidr]
	if !isOwned || owner != siteId {
		return -1, false // Not the owner, nothing to promote
	}

	// This peer was the owner, need to find a new owner
	delete(pm.allowedIPOwners, cidr)

	// Find another claimant to promote
	if claims, exists := pm.allowedIPClaims[cidr]; exists && len(claims) > 0 {
		for claimantId := range claims {
			pm.allowedIPOwners[cidr] = claimantId
			return claimantId, true
		}
	}

	return -1, false
}

// getOwnedAllowedIPs returns the list of allowed IPs that a peer currently owns in WireGuard.
// Must be called with lock held.
func (pm *PeerManager) getOwnedAllowedIPs(siteId int) []string {
	var owned []string
	for cidr, owner := range pm.allowedIPOwners {
		if owner == siteId {
			owned = append(owned, cidr)
		}
	}
	return owned
}

// addAllowedIp adds an IP (subnet) to the allowed IPs list of a peer
// and updates WireGuard configuration if this peer owns the IP.
// Must be called with lock held.
func (pm *PeerManager) addAllowedIp(siteId int, ip string) error {
	peer, exists := pm.peers[siteId]
	if !exists {
		return fmt.Errorf("peer with site ID %d not found", siteId)
	}

	// Check if IP already exists in AllowedIps
	for _, allowedIp := range peer.AllowedIps {
		if allowedIp == ip {
			return nil // Already exists
		}
	}

	// Register our claim to this IP
	pm.claimAllowedIP(siteId, ip)

	peer.AllowedIps = append(peer.AllowedIps, ip)
	pm.peers[siteId] = peer

	// Only update WireGuard if we own this IP
	if pm.allowedIPOwners[ip] == siteId {
		if err := ConfigurePeer(pm.device, peer, pm.privateKey, peer.Endpoint); err != nil {
			return err
		}
	}

	return nil
}

// removeAllowedIp removes an IP (subnet) from the allowed IPs list of a peer
// and updates WireGuard configuration. If this peer owned the IP, it promotes
// another peer that also claims this IP. Must be called with lock held.
func (pm *PeerManager) removeAllowedIp(siteId int, cidr string) error {
	peer, exists := pm.peers[siteId]
	if !exists {
		return fmt.Errorf("peer with site ID %d not found", siteId)
	}

	found := false

	// Remove from AllowedIps
	newAllowedIps := make([]string, 0, len(peer.AllowedIps))
	for _, allowedIp := range peer.AllowedIps {
		if allowedIp == cidr {
			found = true
			continue
		}
		newAllowedIps = append(newAllowedIps, allowedIp)
	}

	if !found {
		return nil // Not found
	}

	peer.AllowedIps = newAllowedIps
	pm.peers[siteId] = peer

	// Release our claim and check if we need to promote another peer
	newOwner, promoted := pm.releaseAllowedIP(siteId, cidr)

	// Update WireGuard for this peer (to remove the IP from its config)
	if err := ConfigurePeer(pm.device, peer, pm.privateKey, peer.Endpoint); err != nil {
		return err
	}

	// If another peer was promoted to owner, update their WireGuard config
	if promoted && newOwner >= 0 {
		if newOwnerPeer, exists := pm.peers[newOwner]; exists {
			if err := ConfigurePeer(pm.device, newOwnerPeer, pm.privateKey, newOwnerPeer.Endpoint); err != nil {
				logger.Error("Failed to promote peer %d for IP %s: %v", newOwner, cidr, err)
			} else {
				logger.Info("Promoted peer %d to owner of IP %s", newOwner, cidr)
			}
		}
	}

	return nil
}

// AddRemoteSubnet adds an IP (subnet) to the allowed IPs list of a peer
func (pm *PeerManager) AddRemoteSubnet(siteId int, cidr string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	peer, exists := pm.peers[siteId]
	if !exists {
		return fmt.Errorf("peer with site ID %d not found", siteId)
	}

	// Check if IP already exists in RemoteSubnets
	for _, subnet := range peer.RemoteSubnets {
		if subnet == cidr {
			return nil // Already exists
		}
	}

	peer.RemoteSubnets = append(peer.RemoteSubnets, cidr)
	pm.peers[siteId] = peer // Save before calling addAllowedIp which reads from pm.peers

	// Add to allowed IPs
	if err := pm.addAllowedIp(siteId, cidr); err != nil {
		return err
	}

	// Add route
	if err := network.AddRoutes([]string{cidr}, pm.interfaceName); err != nil {
		return err
	}

	return nil
}

// RemoveRemoteSubnet removes an IP (subnet) from the allowed IPs list of a peer
func (pm *PeerManager) RemoveRemoteSubnet(siteId int, ip string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	peer, exists := pm.peers[siteId]
	if !exists {
		return fmt.Errorf("peer with site ID %d not found", siteId)
	}

	found := false

	// Remove from RemoteSubnets
	newSubnets := make([]string, 0, len(peer.RemoteSubnets))
	for _, subnet := range peer.RemoteSubnets {
		if subnet == ip {
			found = true
			continue
		}
		newSubnets = append(newSubnets, subnet)
	}

	if !found {
		return nil // Not found
	}

	peer.RemoteSubnets = newSubnets
	pm.peers[siteId] = peer // Save before calling removeAllowedIp which reads from pm.peers

	// Remove from allowed IPs (this also handles promotion of other peers)
	if err := pm.removeAllowedIp(siteId, ip); err != nil {
		return err
	}

	// Remove route
	if err := network.RemoveRoutes([]string{ip}); err != nil {
		return err
	}

	return nil
}

// AddAlias adds an alias to a peer
func (pm *PeerManager) AddAlias(siteId int, alias Alias) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	peer, exists := pm.peers[siteId]
	if !exists {
		return fmt.Errorf("peer with site ID %d not found", siteId)
	}

	peer.Aliases = append(peer.Aliases, alias)
	pm.peers[siteId] = peer

	address := net.ParseIP(alias.AliasAddress)
	if address != nil {
		pm.dnsProxy.AddDNSRecord(alias.Alias, address)
	}

	// Add an allowed IP for the alias
	if err := pm.addAllowedIp(siteId, alias.AliasAddress+"/32"); err != nil {
		return err
	}

	return nil
}

// RemoveAlias removes an alias from a peer
func (pm *PeerManager) RemoveAlias(siteId int, aliasName string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	peer, exists := pm.peers[siteId]
	if !exists {
		return fmt.Errorf("peer with site ID %d not found", siteId)
	}

	var aliasToRemove *Alias
	newAliases := make([]Alias, 0, len(peer.Aliases))
	for _, a := range peer.Aliases {
		if a.Alias == aliasName {
			aliasToRemove = &a
			continue
		}
		newAliases = append(newAliases, a)
	}

	if aliasToRemove != nil {
		address := net.ParseIP(aliasToRemove.AliasAddress)
		if address != nil {
			pm.dnsProxy.RemoveDNSRecord(aliasName, address)
		}
	}

	// remove the allowed IP for the alias
	if err := pm.removeAllowedIp(siteId, aliasToRemove.AliasAddress+"/32"); err != nil {
		return err
	}

	peer.Aliases = newAliases
	pm.peers[siteId] = peer

	return nil
}

// HandleFailover handles failover to the relay server when a peer is disconnected
func (pm *PeerManager) HandleFailover(siteId int, relayEndpoint string) {
	pm.mu.RLock()
	peer, exists := pm.peers[siteId]
	pm.mu.RUnlock()

	if !exists {
		logger.Error("Cannot handle failover: peer with site ID %d not found", siteId)
		return
	}

	// Check for IPv6 and format the endpoint correctly
	formattedEndpoint := relayEndpoint
	if strings.Contains(relayEndpoint, ":") {
		formattedEndpoint = fmt.Sprintf("[%s]", relayEndpoint)
	}

	// Update only the endpoint for this peer (update_only preserves other settings)
	wgConfig := fmt.Sprintf(`public_key=%s
update_only=true
endpoint=%s:21820`, peer.PublicKey, formattedEndpoint)

	err := pm.device.IpcSet(wgConfig)
	if err != nil {
		logger.Error("Failed to configure WireGuard device: %v\n", err)
		return
	}

	logger.Info("Adjusted peer %d to point to relay!\n", siteId)
}

// Start starts the peer monitor
func (pm *PeerManager) Start() {
	if pm.peerMonitor != nil {
		pm.peerMonitor.Start()
	}
}

// Stop stops the peer monitor
func (pm *PeerManager) Stop() {
	if pm.peerMonitor != nil {
		pm.peerMonitor.Stop()
	}
}

// Close stops the peer monitor and cleans up resources
func (pm *PeerManager) Close() {
	if pm.peerMonitor != nil {
		pm.peerMonitor.Close()
		pm.peerMonitor = nil
	}
}

// SetHolepunchStatusCallback sets the callback for holepunch status changes
func (pm *PeerManager) SetHolepunchStatusCallback(callback HolepunchStatusCallback) {
	if pm.peerMonitor != nil {
		pm.peerMonitor.SetHolepunchStatusCallback(callback)
	}
}
