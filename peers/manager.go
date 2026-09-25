package peers

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

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
	PublicDNS []string
	// DisableRoutes stops the manager from adding/removing routes in the
	// system routing table for server IPs and remote subnets. Gateway routes
	// are unaffected.
	DisableRoutes bool
}

type PeerManager struct {
	mu            sync.RWMutex
	device        *device.Device
	peers         map[int]SiteConfig
	peerMonitor   *monitor.PeerMonitor
	dnsProxy      *dns.DNSProxy
	interfaceName string
	// localIP is our own address on the site tunnel (as opposed to any exit
	// node's secondary address that may also be present on the interface).
	// Routes for site peers are pinned to it on darwin - see AddRoutesWithSource.
	localIP    string
	privateKey wgtypes.Key
	// allowedIPOwners tracks which peer currently "owns" each allowed IP in WireGuard
	// key is the CIDR string, value is the siteId that has it configured in WG
	allowedIPOwners map[string]int
	// allowedIPClaims tracks all peers that claim each allowed IP
	// key is the CIDR string, value is a set of siteIds that want this IP
	allowedIPClaims map[string]map[int]bool
	APIServer       *api.API
	publicDNS       []string
	disableRoutes   bool

	PersistentKeepalive int

	routeOptimizerStop chan struct{}
	optimizerTrigger   chan struct{}

	// lastOwnerChange tracks, per allowed-IP CIDR, when ownership was last transferred.
	// Used to enforce a cooldown so routes don't flap between two similarly-performing sites.
	lastOwnerChange map[string]time.Time

	// Gateway (full-tunnel/default-route) state. gatewaySiteIds is business
	// intent - the current candidate set - not WireGuard ownership, which is
	// tracked the same way as any other shared CIDR via allowedIPOwners/
	// allowedIPClaims (see gatewayCIDR). gatewayExcludedIPs is a refcount so a
	// destination referenced by more than one thing (or re-added while
	// already excluded) is only actually un-excluded once nothing references
	// it any more. gatewayControlIP is the control-plane (Pangolin server)
	// endpoint, resolved once at activation and excluded for the lifetime of
	// the gateway so the management connection doesn't depend on the current
	// gateway-owner site's own uplink. gatewaySiteResourceId is the numeric
	// ID (not the niceId, which can be renamed) of the gateway-mode site
	// resource the candidate set was selected from, so server-pushed
	// add/remove/disable updates (see UpdateGatewaySites) are only applied when
	// they concern that resource and not some other gateway resource that
	// happens to share a site.
	gatewayActive         bool
	gatewaySiteResourceId int
	gatewaySiteIds        map[int]bool
	gatewayExcludedIPs    map[string]int
	gatewayControlIP      string

	// gatewayExtraEndpoints tracks "host:port" (or already-resolved "ip:port")
	// endpoints registered by callers outside the normal site-peer lifecycle -
	// currently hole-punch exit node probing endpoints and a connected exit
	// node's own WireGuard endpoint (see olm's OnTokenUpdate handler and
	// connectExitNode) - that must stay off the gateway route the same way a
	// site peer's own endpoint does, so hole punching / the exit node
	// connection still originates from the local network rather than looping
	// through the tunnel. Business intent, independent of gatewayActive - see
	// AddGatewayBypassEndpoint/RemoveGatewayBypassEndpoint.
	gatewayExtraEndpoints map[string]bool
}

// gatewayCIDR is the WireGuard AllowedIPs claim key for "this site is the
// gateway (full-tunnel/default-route)". It is never added to
// SiteConfig.RemoteSubnets/AllowedIps and never sent over the wire - it only
// ever lives in allowedIPOwners/allowedIPClaims, exactly like a shared remote
// subnet, so it is never clobbered by AddPeer/UpdatePeer recomputing
// SiteConfig.AllowedIps from scratch.
const gatewayCIDR = "0.0.0.0/0"

const (
	// routeSwitchRTTMargin requires a candidate site's RTT to be at least this much
	// better (as a fraction) than the current owner's before we consider it worth
	// switching, so two similarly-performing sites don't flap back and forth.
	routeSwitchRTTMargin = 0.20 // candidate must be >=20% faster

	// routeSwitchMinAbsMargin is a floor on the RTT improvement required, so the
	// percentage margin above doesn't become meaningless at very low RTTs (e.g. a
	// 1ms vs 0.8ms "20% improvement" shouldn't trigger a switch).
	routeSwitchMinAbsMargin = 5 * time.Millisecond

	// routeSwitchCooldown is the minimum time to wait after transferring ownership
	// of a route before it can be transferred again, unless the current owner's
	// connection quality degrades (disconnects or falls back to relay).
	routeSwitchCooldown = 30 * time.Second
)

// normalizeServerRouteDestination converts the bare IPv4 address returned by
// Pangolin's site configuration into the host CIDR expected by Newt's route
// helpers. Pangolin 1.21 returns values such as "100.90.128.4", while the
// Darwin route and NetworkSettings implementations require "100.90.128.4/32".
// Preserve already-CIDR values and invalid values so the downstream helper can
// report its normal validation error.
func normalizeServerRouteDestination(serverIP string) string {
	if strings.Contains(serverIP, "/") {
		return serverIP
	}

	ip := net.ParseIP(serverIP)
	if ip == nil || ip.To4() == nil {
		return serverIP
	}

	return ip.To4().String() + "/32"
}

// NewPeerManager creates a new PeerManager with an internal PeerMonitor
func NewPeerManager(config PeerManagerConfig) *PeerManager {
	pm := &PeerManager{
		device:                config.Device,
		peers:                 make(map[int]SiteConfig),
		dnsProxy:              config.DNSProxy,
		interfaceName:         config.InterfaceName,
		localIP:               config.LocalIP,
		privateKey:            config.PrivateKey,
		allowedIPOwners:       make(map[string]int),
		allowedIPClaims:       make(map[string]map[int]bool),
		APIServer:             config.APIServer,
		publicDNS:             config.PublicDNS,
		disableRoutes:         config.DisableRoutes,
		lastOwnerChange:       make(map[string]time.Time),
		gatewaySiteIds:        make(map[int]bool),
		gatewayExcludedIPs:    make(map[string]int),
		gatewayExtraEndpoints: make(map[string]bool),
	}

	// Create the peer monitor
	pm.peerMonitor = monitor.NewPeerMonitor(
		config.WSClient,
		config.MiddleDev,
		config.LocalIP,
		config.SharedBind,
		config.APIServer,
		config.PublicDNS,
	)

	pm.optimizerTrigger = make(chan struct{}, 1)

	pm.peerMonitor.SetLocalConnectionCallbacks(pm.LocalPeer, pm.UnLocalPeer)

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

// SetExitNode starts (or updates) ICMP connectivity monitoring of the given exit node.
// tunnelIP is the secondary address assigned to us for this exit node, which the ping
// probe must be sourced from since the exit node's WireGuard peer entry only accepts
// traffic from that address.
func (pm *PeerManager) SetExitNode(serverIP, tunnelIP string) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	if pm.peerMonitor != nil {
		pm.peerMonitor.SetExitNode(serverIP, tunnelIP)
	}
}

// ClearExitNode stops ICMP connectivity monitoring of the exit node
func (pm *PeerManager) ClearExitNode() {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	if pm.peerMonitor != nil {
		pm.peerMonitor.ClearExitNode()
	}
}

// SetPublicDNS replaces the DNS servers used to resolve WireGuard peer
// endpoints and hole-punch targets.  The servers must be in "host:port" format
// (e.g. "8.8.8.8:53").  The change takes effect for all future peer
// configuration calls; existing WireGuard peers are not re-resolved.
func (pm *PeerManager) SetPublicDNS(servers []string) {
	pm.mu.Lock()
	pm.publicDNS = servers
	mon := pm.peerMonitor
	pm.mu.Unlock()

	if mon != nil {
		mon.SetPublicDNS(servers)
	}
}

// resolveEndpointIPLocked resolves a raw "host[:port]" endpoint string (as
// stored on SiteConfig.Endpoint/RelayEndpoint, or passed directly to
// RelayPeer/UnRelayPeer) to its bare IP address, for gateway bypass-route
// purposes. Must be called with pm.mu held (uses pm.publicDNS).
func (pm *PeerManager) resolveEndpointIPLocked(endpoint string) (string, bool) {
	if endpoint == "" {
		return "", false
	}
	resolved, err := util.ResolveDomainUpstream(formatEndpoint(endpoint), pm.publicDNS)
	if err != nil {
		logger.Warn("Gateway: failed to resolve endpoint %q for bypass route: %v", endpoint, err)
		return "", false
	}
	host, _, err := net.SplitHostPort(resolved)
	if err != nil {
		host = resolved
	}
	return host, true
}

// resolveActiveEndpointIPLocked resolves the endpoint peer is currently using
// (per its own Endpoint/RelayEndpoint fields and the peer monitor's relayed
// flag) to a bare IP, for gateway bypass-route purposes. Returns ("", false)
// for an active local endpoint - on-link traffic never traverses the OS
// default route, so it needs no bypass route. Must be called with pm.mu held.
func (pm *PeerManager) resolveActiveEndpointIPLocked(peer SiteConfig) (string, bool) {
	if peer.ActiveLocalEndpoint != "" {
		return "", false
	}
	endpoint := peer.Endpoint
	if pm.peerMonitor != nil && pm.peerMonitor.IsPeerRelayed(peer.SiteId) && peer.RelayEndpoint != "" {
		endpoint = peer.RelayEndpoint
	}
	return pm.resolveEndpointIPLocked(endpoint)
}

// excludeEndpointLocked adds a bypass route for ip if this is its first
// reference, or just bumps the refcount if something is already excluding
// it (gatewayExcludedIPs). No-op for an empty ip (the "no endpoint yet" /
// "active local endpoint" case from the resolve helpers above). Must be
// called with pm.mu held.
func (pm *PeerManager) excludeEndpointLocked(ip string) {
	if ip == "" {
		return
	}
	if pm.gatewayExcludedIPs[ip] == 0 {
		if err := network.AddBypassRouteForDestination(ip); err != nil {
			logger.Error("Gateway: failed to add bypass route for %s: %v", ip, err)
		}
	}
	pm.gatewayExcludedIPs[ip]++
}

// unexcludeEndpointLocked reverses excludeEndpointLocked: decrements the
// refcount and only actually removes the bypass route once nothing
// references ip any more. Must be called with pm.mu held.
func (pm *PeerManager) unexcludeEndpointLocked(ip string) {
	if ip == "" {
		return
	}
	if pm.gatewayExcludedIPs[ip] <= 1 {
		delete(pm.gatewayExcludedIPs, ip)
		if err := network.RemoveBypassRouteForDestination(ip); err != nil {
			logger.Error("Gateway: failed to remove bypass route for %s: %v", ip, err)
		}
		return
	}
	pm.gatewayExcludedIPs[ip]--
}

// activateGatewayLocked performs the one-time setup for gateway mode:
// resolving and excluding the control-plane endpoint and every
// currently-tracked peer's active endpoint (so none of them can be captured
// by the default-route-equivalent installed at the end), then installing
// that route. Must be called with pm.mu held, and only once (guarded by
// pm.gatewayActive in the caller).
func (pm *PeerManager) activateGatewayLocked(controlEndpointHost string) error {
	if ip, ok := pm.resolveEndpointIPLocked(controlEndpointHost); ok {
		pm.gatewayControlIP = ip
		pm.excludeEndpointLocked(ip)
	} else if controlEndpointHost != "" {
		logger.Warn("Gateway: failed to resolve control endpoint %q for bypass route", controlEndpointHost)
	}

	for _, peer := range pm.peers {
		if ip, ok := pm.resolveActiveEndpointIPLocked(peer); ok {
			pm.excludeEndpointLocked(ip)
		}
	}

	for hostport := range pm.gatewayExtraEndpoints {
		if ip, ok := pm.resolveEndpointIPLocked(hostport); ok {
			pm.excludeEndpointLocked(ip)
		}
	}

	if err := network.AddGatewayDefaultRoute(pm.interfaceName, pm.localIP); err != nil {
		return fmt.Errorf("failed to install gateway route: %v", err)
	}

	return nil
}

// deactivateGatewayLocked reverses activateGatewayLocked: removes the
// default-route-equivalent, then every remaining bypass route (including the
// control endpoint), and resets gateway exclusion state. Must be called with
// pm.mu held.
func (pm *PeerManager) deactivateGatewayLocked() {
	if err := network.RemoveGatewayDefaultRoute(pm.interfaceName); err != nil {
		logger.Error("Gateway: failed to remove gateway route: %v", err)
	}

	for ip := range pm.gatewayExcludedIPs {
		if err := network.RemoveBypassRouteForDestination(ip); err != nil {
			logger.Error("Gateway: failed to remove bypass route for %s: %v", ip, err)
		}
	}
	pm.gatewayExcludedIPs = make(map[string]int)
	pm.gatewayControlIP = ""
}

// claimGatewayClaimLocked registers siteId's claim to the gateway CIDR via
// the same generic ownership machinery used for shared remote subnets
// (claimAllowedIP), then pushes an incremental WireGuard AllowedIPs update if
// this claim made siteId the owner. Deliberately bypasses
// addAllowedIp/SiteConfig.AllowedIps - see gatewayCIDR's doc comment. Must be
// called with pm.mu held.
func (pm *PeerManager) claimGatewayClaimLocked(siteId int) {
	pm.claimAllowedIP(siteId, gatewayCIDR)
	if pm.allowedIPOwners[gatewayCIDR] != siteId {
		return
	}
	peer, exists := pm.peers[siteId]
	if !exists {
		return
	}
	if err := AddAllowedIP(pm.device, peer.PublicKey, gatewayCIDR); err != nil {
		logger.Error("Gateway: failed to claim %s for site %d: %v", gatewayCIDR, siteId, err)
	}
}

// releaseGatewayClaimLocked reverses claimGatewayClaimLocked. If siteId was
// the owner, promotes another candidate the same way releaseAllowedIP/
// transferOwnership already do for shared remote subnets. Must be called
// with pm.mu held.
func (pm *PeerManager) releaseGatewayClaimLocked(siteId int) {
	wasOwner := pm.allowedIPOwners[gatewayCIDR] == siteId
	newOwner, promoted := pm.releaseAllowedIP(siteId, gatewayCIDR)

	if wasOwner {
		if peer, exists := pm.peers[siteId]; exists {
			remaining := pm.getWireGuardAllowedIPs(siteId)
			if err := RemoveAllowedIP(pm.device, peer.PublicKey, remaining); err != nil {
				logger.Error("Gateway: failed to release %s from site %d: %v", gatewayCIDR, siteId, err)
			}
		}
	}

	if promoted && newOwner >= 0 {
		if peer, exists := pm.peers[newOwner]; exists {
			if err := AddAllowedIP(pm.device, peer.PublicKey, gatewayCIDR); err != nil {
				logger.Error("Gateway: failed to promote site %d to owner of %s: %v", newOwner, gatewayCIDR, err)
			}
		}
	}
}

// SetGateway designates siteIds as the gateway (full-tunnel/default-route)
// candidate set, selected from the gateway site resource siteResourceId (the
// server only tells us about changes to that one resource - see
// UpdateGatewaySites). Every siteId must already be a tracked peer, or the
// call is rejected outright (no partial application). On first activation this
// installs the OS-level gateway route plus every bypass route needed so the
// tunnel's own traffic (control-plane endpoint, every tracked peer's active
// endpoint) isn't captured by it; subsequent calls only change which sites
// may own the "0.0.0.0/0" WireGuard AllowedIP, via the existing generic
// claim/optimizer machinery - exactly like remote subnets. controlEndpointHost
// is the Pangolin server host olm is registered against (bare host, port
// optional); always excluded regardless of which sites are selected.
func (pm *PeerManager) SetGateway(siteResourceId int, siteIds []int, controlEndpointHost string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if siteResourceId <= 0 {
		return fmt.Errorf("a valid gateway site resource ID must be provided")
	}
	if len(siteIds) == 0 {
		return fmt.Errorf("at least one site ID must be provided")
	}

	var missing []int
	for _, id := range siteIds {
		if _, ok := pm.peers[id]; !ok {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("site IDs not tracked as peers: %v", missing)
	}

	if !pm.gatewayActive {
		if err := pm.activateGatewayLocked(controlEndpointHost); err != nil {
			return err
		}
		pm.gatewayActive = true
	}

	newSet := make(map[int]bool, len(siteIds))
	for _, id := range siteIds {
		newSet[id] = true
	}
	for id := range pm.gatewaySiteIds {
		if !newSet[id] {
			pm.releaseGatewayClaimLocked(id)
		}
	}
	for id := range newSet {
		if !pm.gatewaySiteIds[id] {
			pm.claimGatewayClaimLocked(id)
		}
	}
	pm.gatewaySiteIds = newSet
	pm.gatewaySiteResourceId = siteResourceId

	logger.Info("Gateway set to sites %v (site resource %d)", siteIds, siteResourceId)
	return nil
}

// GetGatewayState returns whether gateway mode is active, the site resource ID
// it was selected from, and the current candidate site IDs (sorted).
func (pm *PeerManager) GetGatewayState() (active bool, siteResourceId int, siteIds []int) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.gatewayActive, pm.gatewaySiteResourceId, pm.gatewaySiteIdsSortedLocked()
}

// gatewaySiteIdsSortedLocked returns the gateway candidate set as a sorted
// slice, for stable status output. Must be called with pm.mu held.
func (pm *PeerManager) gatewaySiteIdsSortedLocked() []int {
	ids := make([]int, 0, len(pm.gatewaySiteIds))
	for id := range pm.gatewaySiteIds {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}

// UpdateGatewaySites applies a server-pushed change to the gateway candidate
// set: addedSiteIds/removedSiteIds are the sites that were added to / removed
// from the gateway site resource siteResourceId. It is a no-op (matched=false)
// unless gateway mode is active AND was selected from that exact resource, so
// a site added to some other gateway resource is never pulled into the
// candidate set. If the update leaves the candidate set empty, gateway mode is
// cleared entirely (an installed default route with no owning peer would just
// blackhole traffic). Sites that aren't tracked peers yet are recorded as
// intent only - AddPeer claims the gateway CIDR for them once their peer
// arrives (the server sends the peer add and this update independently, so
// either order is possible). Returns the resulting gateway state.
func (pm *PeerManager) UpdateGatewaySites(siteResourceId int, addedSiteIds, removedSiteIds []int) (matched bool, active bool, siteIds []int) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if !pm.gatewayActive || pm.gatewaySiteResourceId != siteResourceId {
		return false, pm.gatewayActive, pm.gatewaySiteIdsSortedLocked()
	}

	removed := make(map[int]bool, len(removedSiteIds))
	for _, id := range removedSiteIds {
		removed[id] = true
	}

	// Work out the resulting set first so we can tell up front if it would be
	// empty, and so removed wins over added if a message lists an ID in both.
	newSet := make(map[int]bool, len(pm.gatewaySiteIds)+len(addedSiteIds))
	for id := range pm.gatewaySiteIds {
		if !removed[id] {
			newSet[id] = true
		}
	}
	for _, id := range addedSiteIds {
		if !removed[id] {
			newSet[id] = true
		}
	}

	if len(newSet) == 0 {
		logger.Info("Gateway: all sites removed from site resource %d, clearing gateway", siteResourceId)
		pm.clearGatewayLocked()
		return true, false, nil
	}

	// Claim added sites BEFORE releasing removed ones, so a swap doesn't leave
	// a window with no owner of the gateway CIDR (same ordering rationale as
	// handleWgPeerUpdateData).
	for id := range newSet {
		if pm.gatewaySiteIds[id] {
			continue
		}
		pm.gatewaySiteIds[id] = true
		if _, tracked := pm.peers[id]; tracked {
			pm.claimGatewayClaimLocked(id)
		}
	}
	for id := range removed {
		if !pm.gatewaySiteIds[id] {
			continue
		}
		delete(pm.gatewaySiteIds, id)
		pm.releaseGatewayClaimLocked(id)
	}

	logger.Info("Gateway sites for site resource %d are now %v", siteResourceId, pm.gatewaySiteIdsSortedLocked())
	return true, true, pm.gatewaySiteIdsSortedLocked()
}

// ClearGatewayForResource fully clears gateway state, but only if gateway mode
// was selected from the site resource siteResourceId (e.g. that resource was
// deleted, disabled, or this client lost access to it). Returns whether it
// matched and cleared.
func (pm *PeerManager) ClearGatewayForResource(siteResourceId int) bool {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if !pm.gatewayActive || pm.gatewaySiteResourceId != siteResourceId {
		return false
	}
	pm.clearGatewayLocked()
	return true
}

// clearGatewayLocked is ClearGateway's body, split out so Close() (which
// already holds pm.mu) can reuse it without re-locking. Must be called with
// pm.mu held.
func (pm *PeerManager) clearGatewayLocked() {
	if !pm.gatewayActive {
		return
	}
	for id := range pm.gatewaySiteIds {
		pm.releaseGatewayClaimLocked(id)
	}
	pm.gatewaySiteIds = make(map[int]bool)
	pm.gatewaySiteResourceId = 0
	pm.deactivateGatewayLocked()
	pm.gatewayActive = false
	logger.Info("Gateway cleared")
}

// ClearGateway fully removes gateway state: releases every candidate's
// claim, tears down the OS-level gateway route, and removes every bypass
// route. No-op if gateway is not currently active.
func (pm *PeerManager) ClearGateway() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.clearGatewayLocked()
	return nil
}

// AddGatewayBypassEndpoint registers hostport (a "host:port" string, or an
// already-resolved "ip:port") as needing protection from the gateway
// default-route-equivalent, for endpoints outside the normal site-peer
// lifecycle - hole-punch exit node probing endpoints and a connected exit
// node's own WireGuard endpoint. If gateway mode is currently active, the
// bypass route is installed immediately; otherwise this only records intent,
// applied the next time gateway activates. Safe to call repeatedly with the
// same hostport (idempotent).
func (pm *PeerManager) AddGatewayBypassEndpoint(hostport string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.gatewayExtraEndpoints[hostport] {
		return
	}
	pm.gatewayExtraEndpoints[hostport] = true

	if pm.gatewayActive {
		if ip, ok := pm.resolveEndpointIPLocked(hostport); ok {
			pm.excludeEndpointLocked(ip)
		}
	}
}

// RemoveGatewayBypassEndpoint reverses AddGatewayBypassEndpoint. Safe to call
// on a hostport that was never registered (no-op).
func (pm *PeerManager) RemoveGatewayBypassEndpoint(hostport string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if !pm.gatewayExtraEndpoints[hostport] {
		return
	}
	delete(pm.gatewayExtraEndpoints, hostport)

	if pm.gatewayActive {
		if ip, ok := pm.resolveEndpointIPLocked(hostport); ok {
			pm.unexcludeEndpointLocked(ip)
		}
	}
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

// addRoutes/removeRoutes/addServerRoute/removeServerRoute wrap the system
// route helpers for site traffic (server IPs and remote subnets) and are a
// no-op when route management is disabled. They deliberately do NOT cover the
// gateway default-route-equivalent or its bypass routes, which are always
// installed regardless (see activateGatewayLocked).
func (pm *PeerManager) addRoutes(subnets []string) error {
	if pm.disableRoutes {
		return nil
	}
	return network.AddRoutesWithSource(subnets, pm.interfaceName, pm.localIP)
}

func (pm *PeerManager) removeRoutes(subnets []string) error {
	if pm.disableRoutes {
		return nil
	}
	return network.RemoveRoutes(subnets, pm.interfaceName)
}

func (pm *PeerManager) addServerRoute(serverIP string) error {
	if pm.disableRoutes {
		return nil
	}
	return network.AddRouteForServerIPWithSource(normalizeServerRouteDestination(serverIP), pm.interfaceName, pm.localIP)
}

func (pm *PeerManager) removeServerRoute(serverIP string) error {
	if pm.disableRoutes {
		return nil
	}
	return network.RemoveRouteForServerIPWithSource(normalizeServerRouteDestination(serverIP), pm.interfaceName, pm.localIP)
}

// The DNS proxy is not created when aliases are disabled, so every alias
// record operation must tolerate a nil proxy.
func (pm *PeerManager) addDNSRecord(alias string, address net.IP, siteId int) {
	if pm.dnsProxy != nil {
		pm.dnsProxy.AddDNSRecord(alias, address, siteId)
	}
}

func (pm *PeerManager) removeDNSRecord(alias string, address net.IP) {
	if pm.dnsProxy != nil {
		pm.dnsProxy.RemoveDNSRecord(alias, address)
	}
}

func (pm *PeerManager) removeDNSRecordForSite(alias string, address net.IP, siteId int) {
	if pm.dnsProxy != nil {
		pm.dnsProxy.RemoveDNSRecordForSite(alias, address, siteId)
	}
}

func (pm *PeerManager) AddPeer(siteConfig SiteConfig) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for _, alias := range siteConfig.Aliases {
		address := net.ParseIP(alias.AliasAddress)
		if address == nil {
			continue
		}
		pm.addDNSRecord(alias.Alias, address, siteConfig.SiteId)
	}

	if siteConfig.PublicKey == "" {
		logger.Debug("Skip adding site %d because no pub key", siteConfig.SiteId)
		return nil
	}

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

	// If this site is a gateway candidate, claim the gateway CIDR the same
	// way as any other shared allowed IP - this must happen even for a
	// re-add (e.g. server-directed peer churn while gateway mode is active),
	// or the site would silently lose its claim.
	if pm.gatewaySiteIds[siteConfig.SiteId] {
		pm.claimAllowedIP(siteConfig.SiteId, gatewayCIDR)
		if pm.allowedIPOwners[gatewayCIDR] == siteConfig.SiteId {
			ownedIPs = append(ownedIPs, gatewayCIDR)
		}
	}

	// Create a config with only the owned IPs for WireGuard
	wgConfig := siteConfig
	wgConfig.AllowedIps = ownedIPs

	if err := ConfigurePeer(pm.device, wgConfig, pm.privateKey, pm.peerMonitor.IsPeerRelayed(siteConfig.SiteId), pm.PersistentKeepalive, pm.publicDNS); err != nil {
		return err
	}

	if err := pm.addServerRoute(siteConfig.ServerIP); err != nil {
		logger.Error("Failed to add route for server IP: %v", err)
	}
	if err := pm.addRoutes(siteConfig.RemoteSubnets); err != nil {
		logger.Error("Failed to add routes for remote subnets: %v", err)
	}

	monitorAddress := strings.Split(siteConfig.ServerIP, "/")[0]
	monitorPeer := net.JoinHostPort(monitorAddress, strconv.Itoa(int(siteConfig.ServerPort+1))) // +1 for the monitor port

	err := pm.peerMonitor.AddPeer(siteConfig.SiteId, monitorPeer, siteConfig.Endpoint, siteConfig.LocalEndpoints) // always use the real site endpoint for hole punch monitoring
	if err != nil {
		logger.Warn("Failed to setup monitoring for site %d: %v", siteConfig.SiteId, err)
	} else {
		logger.Info("Started monitoring for site %d at %s", siteConfig.SiteId, monitorPeer)
	}

	pm.peers[siteConfig.SiteId] = siteConfig

	// Independent of gateway candidacy: while gateway mode is active, every
	// tracked site (not just the current candidates) needs its own endpoint
	// protected from the default-route-equivalent, so a newly/JIT-connected
	// site is covered too.
	if pm.gatewayActive {
		if ip, ok := pm.resolveActiveEndpointIPLocked(siteConfig); ok {
			pm.excludeEndpointLocked(ip)
		}
	}

	pm.APIServer.AddPeerStatus(siteConfig.SiteId, siteConfig.Name, false, 0, siteConfig.Endpoint, false, false)

	// Perform rapid initial holepunch test (outside of lock to avoid blocking)
	// This quickly determines if holepunch is viable and triggers relay if not
	go pm.performRapidInitialTest(siteConfig.SiteId, siteConfig.Endpoint, siteConfig.LocalEndpoints)

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

	if err := pm.removeServerRoute(peer.ServerIP); err != nil {
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
			if err := pm.removeRoutes([]string{subnet}); err != nil {
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
		pm.removeDNSRecord(alias.Alias, address)
	}

	// Release all IP claims and promote other peers as needed. Scan
	// allowedIPClaims directly (rather than peer.AllowedIps) so this also
	// releases claims that never entered SiteConfig.AllowedIps - e.g. the
	// gateway CIDR (see gatewayCIDR's doc comment) - otherwise removing a
	// gateway-candidate peer would leak its claim forever.
	// Collect promotions first to avoid modifying while iterating
	type promotion struct {
		newOwner int
		cidr     string
	}
	var promotions []promotion

	var claimedCIDRs []string
	for cidr, claimants := range pm.allowedIPClaims {
		if claimants[siteId] {
			claimedCIDRs = append(claimedCIDRs, cidr)
		}
	}
	for _, ip := range claimedCIDRs {
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
			if err := ConfigurePeer(pm.device, wgConfig, pm.privateKey, pm.peerMonitor.IsPeerRelayed(promotedPeerId), pm.PersistentKeepalive, pm.publicDNS); err != nil {
				logger.Error("Failed to update promoted peer %d: %v", promotedPeerId, err)
			}
		}
	}

	// Stop monitoring this peer
	pm.peerMonitor.RemovePeer(siteId)
	logger.Info("Stopped monitoring for site %d", siteId)

	pm.APIServer.RemovePeerStatus(siteId)

	// Deliberately leave siteId in pm.gatewaySiteIds (if present) rather than
	// deleting it here: it is business intent, separate from the WG-level
	// claim already released above via the allowedIPClaims scan (which is
	// what actually matters for ownership/optimizeRoutes), and keeping it
	// lets AddPeer transparently re-establish the claim if this is a
	// remove+re-add churn rather than a real removal. A stale entry for a
	// site that never comes back is harmless - the next SetGateway/
	// ClearGateway call reconciles it, and releaseGatewayClaimLocked already
	// no-ops safely for a site with no remaining claim or peer.
	if pm.gatewayActive {
		if ip, ok := pm.resolveActiveEndpointIPLocked(peer); ok {
			pm.unexcludeEndpointLocked(ip)
		}
	}

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

	// Preserve the currently active local endpoint (if any) across updates so an in-progress
	// local connection isn't disrupted by an unrelated site update.
	siteConfig.ActiveLocalEndpoint = oldPeer.ActiveLocalEndpoint

	// Snapshot the old active endpoint now, before anything changes, for the
	// gateway bypass-route churn at the end of this function.
	var oldEndpointIP string
	var haveOldEndpointIP bool
	if pm.gatewayActive {
		oldEndpointIP, haveOldEndpointIP = pm.resolveActiveEndpointIPLocked(oldPeer)
	}

	// Update aliases
	// Remove old aliases
	for _, alias := range oldPeer.Aliases {
		address := net.ParseIP(alias.AliasAddress)
		if address == nil {
			continue
		}
		pm.removeDNSRecord(alias.Alias, address)
	}
	// Add new aliases
	for _, alias := range siteConfig.Aliases {
		address := net.ParseIP(alias.AliasAddress)
		if address == nil {
			continue
		}
		pm.addDNSRecord(alias.Alias, address, siteConfig.SiteId)
	}

	if siteConfig.PublicKey == "" {
		logger.Debug("Skip updating site %d because no pub key", siteConfig.SiteId)
		return nil
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

	if err := ConfigurePeer(pm.device, wgConfig, pm.privateKey, pm.peerMonitor.IsPeerRelayed(siteConfig.SiteId), pm.PersistentKeepalive, pm.publicDNS); err != nil {
		return err
	}

	// Update WireGuard config for any promoted peers
	for promotedPeerId := range peersToUpdate {
		if promotedPeer, exists := pm.peers[promotedPeerId]; exists {
			promotedOwnedIPs := pm.getOwnedAllowedIPs(promotedPeerId)
			promotedWgConfig := promotedPeer
			promotedWgConfig.AllowedIps = promotedOwnedIPs
			if err := ConfigurePeer(pm.device, promotedWgConfig, pm.privateKey, pm.peerMonitor.IsPeerRelayed(promotedPeerId), pm.PersistentKeepalive, pm.publicDNS); err != nil {
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
			if err := pm.removeRoutes([]string{subnet}); err != nil {
				logger.Error("Failed to remove route for subnet %s: %v", subnet, err)
			}
		}
	}

	// Add routes for added subnets
	if len(addedSubnets) > 0 {
		if err := pm.addRoutes(addedSubnets); err != nil {
			logger.Error("Failed to add routes: %v", err)
		}
	}

	pm.peerMonitor.UpdateHolepunchEndpoint(siteConfig.SiteId, siteConfig.Endpoint)
	pm.peerMonitor.UpdateLocalEndpoints(siteConfig.SiteId, siteConfig.LocalEndpoints)

	monitorAddress := strings.Split(siteConfig.ServerIP, "/")[0]
	monitorPeer := net.JoinHostPort(monitorAddress, strconv.Itoa(int(siteConfig.ServerPort+1))) // +1 for the monitor port
	pm.peerMonitor.UpdatePeerEndpoint(siteConfig.SiteId, monitorPeer)                           // +1 for monitor port

	if pm.gatewayActive {
		newIP, haveNewIP := pm.resolveActiveEndpointIPLocked(siteConfig)
		if haveNewIP {
			pm.excludeEndpointLocked(newIP)
		}
		if haveOldEndpointIP && oldEndpointIP != newIP {
			pm.unexcludeEndpointLocked(oldEndpointIP)
		}
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
			delete(pm.lastOwnerChange, cidr)
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
	if err := pm.addRoutes([]string{cidr}); err != nil {
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
		if err := pm.removeRoutes([]string{ip}); err != nil {
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
		pm.addDNSRecord(alias.Alias, address, siteId)
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

	if aliasToRemove == nil {
		// Alias already gone (e.g. duplicate/stale remove message) - nothing to do
		return nil
	}

	address := net.ParseIP(aliasToRemove.AliasAddress)
	if address != nil {
		pm.removeDNSRecordForSite(aliasName, address, siteId)
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
	if exists && peer.ActiveLocalEndpoint != "" {
		pm.mu.Unlock()
		logger.Info("Ignoring relay request for site %d: local connection is active", siteId)
		return
	}
	if exists && pm.gatewayActive {
		// Exclude the endpoint we're switching to before unexcluding the one
		// we're switching from, so there's never a window with no bypass
		// route for whichever endpoint is actually in use.
		oldIP, haveOld := pm.resolveActiveEndpointIPLocked(peer)
		if newIP, ok := pm.resolveEndpointIPLocked(relayEndpoint); ok {
			pm.excludeEndpointLocked(newIP)
			if haveOld && oldIP != newIP {
				pm.unexcludeEndpointLocked(oldIP)
			}
		} else if haveOld {
			pm.unexcludeEndpointLocked(oldIP)
		}
	}
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
// It races a test of the public endpoint against a test of the local candidate endpoints
// (if any) and waits for both to finish before acting, so we never request relay only to
// have it immediately superseded by a local connection (or vice versa). Local wins if it's
// viable at all; otherwise relay is requested only if the public endpoint isn't viable.
// This runs in a goroutine to avoid blocking AddPeer - the peer already starts out pointed
// at the public endpoint (set synchronously in AddPeer), so this just settles the peer onto
// its steady-state connection within ~1-2 seconds.
func (pm *PeerManager) performRapidInitialTest(siteId int, endpoint string, localEndpoints []string) {
	// Snapshot the monitor once under lock and use only the local copy from here on -
	// pm.peerMonitor can be concurrently nil'd out by Close()/Stop() (e.g. the tunnel
	// tears down right after a peer was added), and re-reading the field later in this
	// goroutine would race with that.
	pm.mu.RLock()
	peerMonitor := pm.peerMonitor
	pm.mu.RUnlock()
	if peerMonitor == nil {
		return
	}

	var wg sync.WaitGroup
	var localWinner string
	var holepunchViable bool

	if len(localEndpoints) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			localWinner = peerMonitor.RapidTestLocalEndpoints(siteId, localEndpoints)
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		holepunchViable = peerMonitor.RapidTestPeer(siteId, endpoint)
	}()

	wg.Wait()

	if localWinner != "" {
		logger.Info("Rapid test: local connection viable for site %d, switching to %s", siteId, localWinner)
		pm.LocalPeer(siteId, localWinner)
		return
	}

	if !holepunchViable {
		// Holepunch failed rapid test, request relay immediately
		logger.Info("Rapid test failed for site %d, requesting relay", siteId)
		if err := peerMonitor.RequestRelay(siteId); err != nil {
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
	pm.startRouteOptimizer()
}

// Stop stops the peer monitor
func (pm *PeerManager) Stop() {
	pm.stopRouteOptimizer()
	if pm.peerMonitor != nil {
		pm.peerMonitor.Stop()
	}
}

// Close stops the peer monitor and cleans up resources
func (pm *PeerManager) Close() {
	pm.stopRouteOptimizer()

	pm.mu.Lock()
	// Bypass routes live on the physical interface, not the tun interface, so
	// unlike tunnel routes they don't disappear for free when the tun device
	// is torn down - they must be explicitly removed here or they leak.
	pm.clearGatewayLocked()
	peerMonitor := pm.peerMonitor
	pm.peerMonitor = nil
	pm.mu.Unlock()

	if peerMonitor != nil {
		peerMonitor.Close()
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
	if exists && peer.ActiveLocalEndpoint != "" {
		pm.mu.Unlock()
		logger.Info("Ignoring unrelay request for site %d: local connection is active", siteId)
		return nil
	}
	if exists && pm.gatewayActive {
		// Same add-new-before-remove-old ordering as RelayPeer.
		oldIP, haveOld := pm.resolveActiveEndpointIPLocked(peer)
		if newIP, ok := pm.resolveEndpointIPLocked(endpoint); ok {
			pm.excludeEndpointLocked(newIP)
			if haveOld && oldIP != newIP {
				pm.unexcludeEndpointLocked(oldIP)
			}
		} else if haveOld {
			pm.unexcludeEndpointLocked(oldIP)
		}
	}
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

// LocalPeer switches a peer to a local network endpoint discovered by the peer monitor.
// Local endpoints take priority over both the public endpoint and the relay, so this
// bypasses relay/public-endpoint bookkeeping entirely and just updates the WireGuard
// endpoint directly.
func (pm *PeerManager) LocalPeer(siteId int, localEndpoint string) {
	pm.mu.Lock()
	peer, exists := pm.peers[siteId]
	if exists {
		peer.ActiveLocalEndpoint = localEndpoint
		pm.peers[siteId] = peer
	}
	pm.mu.Unlock()

	if !exists {
		logger.Error("Cannot switch to local connection: peer with site ID %d not found", siteId)
		return
	}

	// Update only the endpoint for this peer (update_only preserves other settings)
	wgConfig := fmt.Sprintf(`public_key=%s
update_only=true
endpoint=%s`, util.FixKey(peer.PublicKey), localEndpoint)

	if err := pm.device.IpcSet(wgConfig); err != nil {
		logger.Error("Failed to switch peer %d to local connection: %v", siteId, err)
		return
	}

	if pm.APIServer != nil {
		pm.APIServer.UpdatePeerLocalStatus(siteId, localEndpoint, true)
	}

	logger.Info("Switched peer %d to local connection at %s", siteId, localEndpoint)
}

// UnLocalPeer switches a peer away from its active local endpoint back to the public
// endpoint, resuming the normal public/relay monitoring logic from scratch (which will
// re-trigger relay on its own if the public endpoint also turns out to be unreachable).
func (pm *PeerManager) UnLocalPeer(siteId int) {
	pm.mu.Lock()
	peer, exists := pm.peers[siteId]
	publicDNS := pm.publicDNS
	if exists {
		peer.ActiveLocalEndpoint = ""
		pm.peers[siteId] = peer
	}
	pm.mu.Unlock()

	if !exists {
		logger.Error("Cannot fall back from local connection: peer with site ID %d not found", siteId)
		return
	}

	resolved, err := util.ResolveDomainUpstream(formatEndpoint(peer.Endpoint), publicDNS)
	if err != nil {
		logger.Error("Failed to resolve fallback endpoint for peer %d: %v", siteId, err)
		return
	}

	if err := pm.UnRelayPeer(siteId, resolved); err != nil {
		logger.Error("Failed to fall back peer %d from local connection: %v", siteId, err)
		return
	}

	if pm.APIServer != nil {
		pm.APIServer.UpdatePeerLocalStatus(siteId, resolved, false)
	}
}

// isBetterConnection returns true if connection quality (a) is better than (b).
// Priority: connected > disconnected, then direct > relayed, then lower RTT.
func isBetterConnection(aConn bool, aRelay bool, aRTT time.Duration,
	bConn bool, bRelay bool, bRTT time.Duration) bool {
	if aConn != bConn {
		return aConn // connected beats disconnected
	}
	if !aConn {
		return false // both offline, no preference
	}
	if aRelay != bRelay {
		return !aRelay // direct beats relayed
	}
	// Same connectivity class: prefer lower RTT
	if aRTT == 0 {
		return false // unknown RTT, don't displace
	}
	if bRTT == 0 {
		return true // current has no RTT data, prefer known
	}
	return aRTT < bRTT
}

// selectBestOwner returns the siteId of the best site to own the given IP,
// based on connection quality. Must be called with pm.mu held.
func (pm *PeerManager) selectBestOwner(claims map[int]bool) int {
	bestSiteId := -1
	var bestConn, bestRelay bool
	var bestRTT time.Duration

	for siteId := range claims {
		conn, relay, rtt := pm.peerMonitor.GetConnectionQuality(siteId)
		if bestSiteId < 0 || isBetterConnection(conn, relay, rtt, bestConn, bestRelay, bestRTT) {
			bestSiteId = siteId
			bestConn = conn
			bestRelay = relay
			bestRTT = rtt
		}
	}
	return bestSiteId
}

// shouldSwitchOwner decides whether ownership of cidr should move from the current
// owner to the candidate. It applies hysteresis so two sites with roughly equal
// performance don't flap back and forth:
//   - A switch driven by connectivity class (connected vs not, direct vs relayed) is
//     always allowed immediately - these are correctness issues, not noise.
//   - A switch driven purely by RTT requires both a minimum improvement margin and
//     that the cooldown since the last switch of this route has elapsed.
//
// Must be called with pm.mu held.
func (pm *PeerManager) shouldSwitchOwner(cidr string, currentSiteId, candidateSiteId int) bool {
	curConn, curRelay, curRTT := pm.peerMonitor.GetConnectionQuality(currentSiteId)
	candConn, candRelay, candRTT := pm.peerMonitor.GetConnectionQuality(candidateSiteId)

	// Connectivity-class differences (up/down, direct/relayed) are not subject to
	// hysteresis - always act on them so we don't stay stuck on a broken route.
	if curConn != candConn || curRelay != candRelay {
		return true
	}
	if !curConn {
		return false // both down, nothing to do
	}

	// Same connectivity class: only switch on a meaningful, sustained RTT win.
	if candRTT == 0 || curRTT == 0 {
		return false
	}
	minImprovement := time.Duration(float64(curRTT) * routeSwitchRTTMargin)
	if minImprovement < routeSwitchMinAbsMargin {
		minImprovement = routeSwitchMinAbsMargin
	}
	if candRTT > curRTT-minImprovement {
		return false // not enough of an improvement to be worth switching
	}

	if lastChange, ok := pm.lastOwnerChange[cidr]; ok {
		if time.Since(lastChange) < routeSwitchCooldown {
			return false // switched too recently, avoid flapping
		}
	}

	return true
}

// getWireGuardAllowedIPs returns the full set of IPs that should be in WireGuard
// for a peer: server IP /32 plus all shared IPs it currently owns.
// Must be called with pm.mu held.
func (pm *PeerManager) getWireGuardAllowedIPs(siteId int) []string {
	peer, exists := pm.peers[siteId]
	if !exists {
		return nil
	}
	serverIP := strings.Split(peer.ServerIP, "/")[0] + "/32"
	ips := []string{serverIP}
	for cidr, owner := range pm.allowedIPOwners {
		if owner == siteId {
			ips = append(ips, cidr)
		}
	}
	return ips
}

// transferOwnership moves WireGuard ownership of cidr from fromSiteId to toSiteId.
// Must be called with pm.mu held.
func (pm *PeerManager) transferOwnership(cidr string, fromSiteId int, toSiteId int) error {
	// Update owner map first
	pm.allowedIPOwners[cidr] = toSiteId

	// Remove cidr from old owner's WireGuard allowed IPs
	if fromPeer, exists := pm.peers[fromSiteId]; exists {
		remaining := pm.getWireGuardAllowedIPs(fromSiteId) // cidr is no longer in owners, so it won't appear here
		if err := RemoveAllowedIP(pm.device, fromPeer.PublicKey, remaining); err != nil {
			// Revert
			pm.allowedIPOwners[cidr] = fromSiteId
			return fmt.Errorf("remove IP %s from site %d: %v", cidr, fromSiteId, err)
		}
	}

	// Add cidr to new owner's WireGuard allowed IPs
	if toPeer, exists := pm.peers[toSiteId]; exists {
		if err := AddAllowedIP(pm.device, toPeer.PublicKey, cidr); err != nil {
			return fmt.Errorf("add IP %s to site %d: %v", cidr, toSiteId, err)
		}
	}

	return nil
}

// optimizeRoutes evaluates all shared IPs and reassigns ownership to the best site.
func (pm *PeerManager) optimizeRoutes() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for cidr, claims := range pm.allowedIPClaims {
		if len(claims) <= 1 {
			continue // No competition, nothing to optimize
		}

		currentOwner, hasOwner := pm.allowedIPOwners[cidr]
		bestOwner := pm.selectBestOwner(claims)

		if bestOwner < 0 {
			continue
		}
		if hasOwner && currentOwner == bestOwner {
			continue // Already on the best site
		}

		if !hasOwner {
			// No current owner, just assign
			pm.allowedIPOwners[cidr] = bestOwner
			pm.lastOwnerChange[cidr] = time.Now()
			if toPeer, exists := pm.peers[bestOwner]; exists {
				if err := AddAllowedIP(pm.device, toPeer.PublicKey, cidr); err != nil {
					logger.Error("Failed to assign IP %s to site %d: %v", cidr, bestOwner, err)
				}
			}
			continue
		}

		if !pm.shouldSwitchOwner(cidr, currentOwner, bestOwner) {
			continue // Not a big enough or sustained enough improvement, avoid flapping
		}

		logger.Info("Route optimizer: moving %s from site %d to site %d", cidr, currentOwner, bestOwner)
		if err := pm.transferOwnership(cidr, currentOwner, bestOwner); err != nil {
			logger.Error("Failed to transfer ownership of %s from site %d to site %d: %v",
				cidr, currentOwner, bestOwner, err)
		} else {
			pm.lastOwnerChange[cidr] = time.Now()
		}
	}
}

// startRouteOptimizer registers the status-change callback and launches the optimizer goroutine.
func (pm *PeerManager) startRouteOptimizer() {
	pm.routeOptimizerStop = make(chan struct{})

	// Trigger optimization whenever any peer's connection status changes
	if pm.peerMonitor != nil {
		pm.peerMonitor.SetStatusChangeCallback(func(_ int) {
			select {
			case pm.optimizerTrigger <- struct{}{}:
			default:
			}
		})
	}

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-pm.routeOptimizerStop:
				return
			case <-pm.optimizerTrigger:
				pm.optimizeRoutes()
			case <-ticker.C:
				pm.optimizeRoutes()
			}
		}
	}()
}

// stopRouteOptimizer stops the route optimizer goroutine if it is running.
func (pm *PeerManager) stopRouteOptimizer() {
	if pm.routeOptimizerStop != nil {
		close(pm.routeOptimizerStop)
		pm.routeOptimizerStop = nil
	}
}
