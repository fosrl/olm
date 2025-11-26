package peers

import (
	"fmt"
	"net"
	"sync"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/network"
	"github.com/fosrl/olm/dns"
	"github.com/fosrl/olm/peermonitor"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type PeerManager struct {
	mu            sync.RWMutex
	device        *device.Device
	peers         map[int]SiteConfig
	peerMonitor   *peermonitor.PeerMonitor
	dnsProxy      *dns.DNSProxy
	interfaceName string
	privateKey    wgtypes.Key
}

func NewPeerManager(dev *device.Device, monitor *peermonitor.PeerMonitor, dnsProxy *dns.DNSProxy, interfaceName string, privateKey wgtypes.Key) *PeerManager {
	return &PeerManager{
		device:        dev,
		peers:         make(map[int]SiteConfig),
		peerMonitor:   monitor,
		dnsProxy:      dnsProxy,
		interfaceName: interfaceName,
		privateKey:    privateKey,
	}
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

	if err := ConfigurePeer(pm.device, siteConfig, pm.privateKey, endpoint, pm.peerMonitor); err != nil {
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

	if err := RemovePeer(pm.device, siteId, peer.PublicKey, pm.peerMonitor); err != nil {
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
		if err := RemovePeer(pm.device, siteConfig.SiteId, oldPeer.PublicKey, pm.peerMonitor); err != nil {
			logger.Error("Failed to remove old peer: %v", err)
		}
	}

	if err := ConfigurePeer(pm.device, siteConfig, pm.privateKey, endpoint, pm.peerMonitor); err != nil {
		return err
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

// addAllowedIp adds an IP (subnet) to the allowed IPs list of a peer
// and updates WireGuard configuration. Must be called with lock held.
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

	peer.AllowedIps = append(peer.AllowedIps, ip)

	// Update WireGuard
	if err := ConfigurePeer(pm.device, peer, pm.privateKey, peer.Endpoint, pm.peerMonitor); err != nil {
		return err
	}

	pm.peers[siteId] = peer
	return nil
}

// removeAllowedIp removes an IP (subnet) from the allowed IPs list of a peer
// and updates WireGuard configuration. Must be called with lock held.
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

	// Update WireGuard
	if err := ConfigurePeer(pm.device, peer, pm.privateKey, peer.Endpoint, pm.peerMonitor); err != nil {
		return err
	}

	pm.peers[siteId] = peer
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

	// Remove from allowed IPs
	if err := pm.removeAllowedIp(siteId, ip); err != nil {
		return err
	}

	// Remove route
	if err := network.RemoveRoutes([]string{ip}); err != nil {
		return err
	}

	pm.peers[siteId] = peer

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
