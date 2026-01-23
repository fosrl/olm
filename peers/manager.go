package peers

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/fosrl/newt/bind"
	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/network"
	"github.com/fosrl/newt/util"
	"github.com/fosrl/olm/api"
	olmDevice "github.com/fosrl/olm/device"
	"github.com/fosrl/olm/dns"
	"github.com/fosrl/olm/peers/monitor"
	"github.com/fosrl/olm/websocket"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

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
	WSClient  *websocket.Client
	APIServer *api.API
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
	APIServer       *api.API
	
	PersistentKeepalive int
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
		APIServer:       config.APIServer,
	}

	// Create the peer monitor
	pm.peerMonitor = monitor.NewPeerMonitor(
		config.WSClient,
		config.MiddleDev,
		config.LocalIP,
		config.SharedBind,
		config.APIServer,
	)

	return pm
}

func (pm *PeerManager) GetPeer(siteId int) (SiteConfig, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	peer, ok := pm.peers[siteId]
	return peer, ok
}

// GetPeerMonitor returns the internal peer monitor instance
func (pm *PeerManager) GetPeerMonitor() *monitor.PeerMonitor {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.peerMonitor
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

func (pm *PeerManager) AddPeer(siteConfig SiteConfig) error {
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

	if err := ConfigurePeer(pm.device, wgConfig, pm.privateKey, pm.peerMonitor.IsPeerRelayed(siteConfig.SiteId), pm.PersistentKeepalive); err != nil {
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

	err := pm.peerMonitor.AddPeer(siteConfig.SiteId, monitorPeer, siteConfig.Endpoint) // always use the real site endpoint for hole punch monitoring
	if err != nil {
		logger.Warn("Failed to setup monitoring for site %d: %v", siteConfig.SiteId, err)
	} else {
		logger.Info("Started monitoring for site %d at %s", siteConfig.SiteId, monitorPeer)
	}

	pm.peers[siteConfig.SiteId] = siteConfig

	pm.APIServer.AddPeerStatus(siteConfig.SiteId, siteConfig.Name, false, 0, siteConfig.Endpoint, false)

	// Perform rapid initial holepunch test (outside of lock to avoid blocking)
	// This quickly determines if holepunch is viable and triggers relay if not
	go pm.performRapidInitialTest(siteConfig.SiteId, siteConfig.Endpoint)

	return nil
}

// UpdateAllPeersPersistentKeepalive updates the persistent keepalive interval for all peers at once
// without recreating them. Returns a map of siteId to error for any peers that failed to update.
func (pm *PeerManager) UpdateAllPeersPersistentKeepalive(interval int) map[int]error {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	pm.PersistentKeepalive = interval

	errors := make(map[int]error)

	for siteId, peer := range pm.peers {
		err := UpdatePersistentKeepalive(pm.device, peer.PublicKey, interval)
		if err != nil {
			errors[siteId] = err
		}
	}

	if len(errors) == 0 {
		return nil
	}
	return errors
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

	// Only remove routes for subnets that aren't used by other peers
	for _, subnet := range peer.RemoteSubnets {
		subnetStillInUse := false
		for otherSiteId, otherPeer := range pm.peers {
			if otherSiteId == siteId {
				continue // Skip the peer being removed
			}
			for _, otherSubnet := range otherPeer.RemoteSubnets {
				if otherSubnet == subnet {
					subnetStillInUse = true
					break
				}
			}
			if subnetStillInUse {
				break
			}
		}
		if !subnetStillInUse {
			if err := network.RemoveRoutes([]string{subnet}); err != nil {
				logger.Error("Failed to remove route for remote subnet %s: %v", subnet, err)
			}
		}
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
			if err := ConfigurePeer(pm.device, wgConfig, pm.privateKey, pm.peerMonitor.IsPeerRelayed(promotedPeerId), pm.PersistentKeepalive); err != nil {
				logger.Error("Failed to update promoted peer %d: %v", promotedPeerId, err)
			}
		}
	}

	// Stop monitoring this peer
	pm.peerMonitor.RemovePeer(siteId)
	logger.Info("Stopped monitoring for site %d", siteId)

	pm.APIServer.RemovePeerStatus(siteId)

	delete(pm.peers, siteId)
	return nil
}

func (pm *PeerManager) UpdatePeer(siteConfig SiteConfig) error {
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

	if err := ConfigurePeer(pm.device, wgConfig, pm.privateKey, pm.peerMonitor.IsPeerRelayed(siteConfig.SiteId), pm.PersistentKeepalive); err != nil {
		return err
	}

	// Update WireGuard config for any promoted peers
	for promotedPeerId := range peersToUpdate {
		if promotedPeer, exists := pm.peers[promotedPeerId]; exists {
			promotedOwnedIPs := pm.getOwnedAllowedIPs(promotedPeerId)
			promotedWgConfig := promotedPeer
			promotedWgConfig.AllowedIps = promotedOwnedIPs
			if err := ConfigurePeer(pm.device, promotedWgConfig, pm.privateKey, pm.peerMonitor.IsPeerRelayed(promotedPeerId), pm.PersistentKeepalive); err != nil {
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

	// Remove routes for removed subnets (only if no other peer needs them)
	for _, subnet := range removedSubnets {
		subnetStillInUse := false
		for otherSiteId, otherPeer := range pm.peers {
			if otherSiteId == siteConfig.SiteId {
				continue // Skip the current peer (already updated)
			}
			for _, otherSubnet := range otherPeer.RemoteSubnets {
				if otherSubnet == subnet {
					subnetStillInUse = true
					break
				}
			}
			if subnetStillInUse {
				break
			}
		}
		if !subnetStillInUse {
			if err := network.RemoveRoutes([]string{subnet}); err != nil {
				logger.Error("Failed to remove route for subnet %s: %v", subnet, err)
			}
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

	pm.peerMonitor.UpdateHolepunchEndpoint(siteConfig.SiteId, siteConfig.Endpoint)

	monitorAddress := strings.Split(siteConfig.ServerIP, "/")[0]
	monitorPeer := net.JoinHostPort(monitorAddress, strconv.Itoa(int(siteConfig.ServerPort+1))) // +1 for the monitor port
	pm.peerMonitor.UpdatePeerEndpoint(siteConfig.SiteId, monitorPeer)                           // +1 for monitor port

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
		if err := AddAllowedIP(pm.device, peer.PublicKey, ip); err != nil {
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

	// Build the list of IPs this peer currently owns for the replace operation
	ownedIPs := pm.getOwnedAllowedIPs(siteId)
	// Also include the server IP which is always owned
	serverIP := strings.Split(peer.ServerIP, "/")[0] + "/32"
	hasServerIP := false
	for _, ip := range ownedIPs {
		if ip == serverIP {
			hasServerIP = true
			break
		}
	}
	if !hasServerIP {
		ownedIPs = append([]string{serverIP}, ownedIPs...)
	}

	// Update WireGuard for this peer using replace_allowed_ips
	if err := RemoveAllowedIP(pm.device, peer.PublicKey, ownedIPs); err != nil {
		return err
	}

	// If another peer was promoted to owner, add the IP to their WireGuard config
	if promoted && newOwner >= 0 {
		if newOwnerPeer, exists := pm.peers[newOwner]; exists {
			if err := AddAllowedIP(pm.device, newOwnerPeer.PublicKey, cidr); err != nil {
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

	// Check if any other peer still has this subnet before removing the route
	subnetStillInUse := false
	for otherSiteId, otherPeer := range pm.peers {
		if otherSiteId == siteId {
			continue // Skip the current peer (already updated above)
		}
		for _, subnet := range otherPeer.RemoteSubnets {
			if subnet == ip {
				subnetStillInUse = true
				break
			}
		}
		if subnetStillInUse {
			break
		}
	}

	// Only remove route if no other peer needs it
	if !subnetStillInUse {
		if err := network.RemoveRoutes([]string{ip}); err != nil {
			return err
		}
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

	peer.Aliases = newAliases
	pm.peers[siteId] = peer

	// Check if any other alias is still using this IP address before removing from allowed IPs
	ipStillInUse := false
	aliasIP := aliasToRemove.AliasAddress + "/32"
	for _, a := range newAliases {
		if a.AliasAddress+"/32" == aliasIP {
			ipStillInUse = true
			break
		}
	}

	// Only remove the allowed IP if no other alias is using it
	if !ipStillInUse {
		if err := pm.removeAllowedIp(siteId, aliasIP); err != nil {
			return err
		}
	}

	return nil
}

// RelayPeer handles failover to the relay server when a peer is disconnected
func (pm *PeerManager) RelayPeer(siteId int, relayEndpoint string, relayPort uint16) {
	pm.mu.Lock()
	peer, exists := pm.peers[siteId]
	if exists {
		// Store the relay endpoint
		peer.RelayEndpoint = relayEndpoint
		pm.peers[siteId] = peer
	}
	pm.mu.Unlock()

	if !exists {
		logger.Error("Cannot handle failover: peer with site ID %d not found", siteId)
		return
	}

	// Check for IPv6 and format the endpoint correctly
	formattedEndpoint := relayEndpoint
	if strings.Contains(relayEndpoint, ":") {
		formattedEndpoint = fmt.Sprintf("[%s]", relayEndpoint)
	}

	if relayPort == 0 {
		relayPort = 21820 // fall back to 21820 for backward compatibility
	}

	// Update only the endpoint for this peer (update_only preserves other settings)
	wgConfig := fmt.Sprintf(`public_key=%s
update_only=true
endpoint=%s:%d`, util.FixKey(peer.PublicKey), formattedEndpoint, relayPort)

	err := pm.device.IpcSet(wgConfig)
	if err != nil {
		logger.Error("Failed to configure WireGuard device: %v\n", err)
		return
	}

	// Mark the peer as relayed in the monitor
	if pm.peerMonitor != nil {
		pm.peerMonitor.MarkPeerRelayed(siteId, true)
	}

	logger.Info("Adjusted peer %d to point to relay!\n", siteId)
}

// performRapidInitialTest performs a rapid holepunch test for a newly added peer.
// If the test fails, it immediately requests relay to minimize connection delay.
// This runs in a goroutine to avoid blocking AddPeer.
func (pm *PeerManager) performRapidInitialTest(siteId int, endpoint string) {
	if pm.peerMonitor == nil {
		return
	}

	// Perform rapid test - this takes ~1-2 seconds max
	holepunchViable := pm.peerMonitor.RapidTestPeer(siteId, endpoint)

	if !holepunchViable {
		// Holepunch failed rapid test, request relay immediately
		logger.Info("Rapid test failed for site %d, requesting relay", siteId)
		if err := pm.peerMonitor.RequestRelay(siteId); err != nil {
			logger.Error("Failed to request relay for site %d: %v", siteId, err)
		}
	} else {
		logger.Info("Rapid test passed for site %d, using direct connection", siteId)
	}
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

// MarkPeerRelayed marks a peer as currently using relay
func (pm *PeerManager) MarkPeerRelayed(siteID int, relayed bool) {
	pm.mu.Lock()
	if peer, exists := pm.peers[siteID]; exists {
		if relayed {
			// We're being relayed, store the current endpoint as the original
			// (RelayEndpoint is set by HandleFailover)
		} else {
			// Clear relay endpoint when switching back to direct
			peer.RelayEndpoint = ""
			pm.peers[siteID] = peer
		}
	}
	pm.mu.Unlock()

	if pm.peerMonitor != nil {
		pm.peerMonitor.MarkPeerRelayed(siteID, relayed)
	}
}

// UnRelayPeer switches a peer from relay back to direct connection
func (pm *PeerManager) UnRelayPeer(siteId int, endpoint string) error {
	pm.mu.Lock()
	peer, exists := pm.peers[siteId]
	if exists {
		// Store the relay endpoint
		peer.Endpoint = endpoint
		pm.peers[siteId] = peer
	}
	pm.mu.Unlock()

	if !exists {
		logger.Error("Cannot handle failover: peer with site ID %d not found", siteId)
		return nil
	}

	// Update WireGuard to use the direct endpoint
	wgConfig := fmt.Sprintf(`public_key=%s
update_only=true
endpoint=%s`, util.FixKey(peer.PublicKey), endpoint)

	err := pm.device.IpcSet(wgConfig)
	if err != nil {
		logger.Error("Failed to switch peer %d to direct connection: %v", siteId, err)
		return err
	}

	// Mark as not relayed in monitor
	if pm.peerMonitor != nil {
		pm.peerMonitor.MarkPeerRelayed(siteId, false)
	}

	logger.Info("Switched peer %d back to direct connection at %s", siteId, endpoint)
	return nil
}
