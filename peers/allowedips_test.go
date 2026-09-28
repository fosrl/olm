package peers

import (
	"strings"
	"testing"
	"time"

	"github.com/fosrl/newt/network"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// newTestDevice returns a real *device.Device backed by an in-memory channel
// TUN (golang.zx2c4.com/wireguard/tun/tuntest) and a standard UDP bind - no
// OS TUN interface or elevated privileges required, so this is safe to run
// as a normal unit test. Used to exercise the real AddAllowedIP/
// RemoveAllowedIP/ConfigurePeer IPC calls that suppressResourceRoutesLocked/
// restoreResourceRoutesLocked make, which a hand-rolled PeerManager with
// device left nil (see newGatewayTestManager/newExitNodeTestManager) can't
// safely call.
func newTestDevice(t *testing.T) (*device.Device, wgtypes.Key) {
	t.Helper()
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}

	dev := device.NewDevice(tuntest.NewChannelTUN().TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "test: "))
	t.Cleanup(dev.Close)

	if err := dev.IpcSet("private_key=" + hexKey(privateKey) + "\n"); err != nil {
		t.Fatalf("failed to set device private key: %v", err)
	}

	return dev, privateKey
}

func hexKey(k wgtypes.Key) string {
	b := [32]byte(k)
	const hextable = "0123456789abcdef"
	out := make([]byte, 64)
	for i, c := range b {
		out[i*2] = hextable[c>>4]
		out[i*2+1] = hextable[c&0x0f]
	}
	return string(out)
}

// TestSuppressRestoreResourceRoutesStripsWireGuardAllowedIPs is the
// counterpart to TestSetGatewaySuppressesResourceRoutesInNetworkSettings,
// but for WireGuard's own AllowedIPs rather than the OS routing table/
// NetworkSettings: it verifies suppressResourceRoutesLocked/
// restoreResourceRoutesLocked actually add/remove the site peer's resource
// CIDRs (remote subnet, alias) from WireGuard itself - not just the system
// route - so that nothing reaching the tunnel interface directly (e.g. a
// mobile netstack/FD consumer bypassing the OS route table) can still reach
// a suppressed resource via WireGuard's own crypto-key routing. The server
// IP allowed-ip entry must survive throughout, since it's what keeps the
// site's own control/monitoring traffic (pings, handshakes) alive while
// suppressed.
func TestSuppressRestoreResourceRoutesStripsWireGuardAllowedIPs(t *testing.T) {
	network.ClearNetworkSettings()
	defer network.ClearNetworkSettings()

	dev, privKey := newTestDevice(t)
	peerKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey (peer): %v", err)
	}
	peerPubKey := peerKey.PublicKey()

	pm := &PeerManager{
		device:                            dev,
		peers:                             make(map[int]SiteConfig),
		allowedIPOwners:                   make(map[string]int),
		allowedIPClaims:                   make(map[string]map[int]bool),
		lastOwnerChange:                   make(map[string]time.Time),
		gatewaySiteIds:                    make(map[int]bool),
		gatewayExcludedIPs:                make(map[string]int),
		gatewayExtraEndpoints:             make(map[string]bool),
		privateKey:                        privKey,
		interfaceName:                     "fake0",
		localIP:                           "100.90.128.8",
		disableRoutesAndAliasesOnExitNode: true,
	}

	site := SiteConfig{
		SiteId:        5,
		PublicKey:     peerPubKey.String(),
		Endpoint:      "127.0.0.1:1", // never dialed - IpcSet doesn't connect
		ServerIP:      "100.90.128.1/20",
		RemoteSubnets: []string{"172.18.21.32/24"},
	}

	// Directly claim ownership and push the peer's full AllowedIPs, mirroring
	// what AddPeer does, without needing the rest of AddPeer's machinery
	// (DNS proxy, peer monitor, holepunch test) that isn't relevant here.
	pm.peers[5] = site
	pm.claimAllowedIP(5, "172.18.21.32/24")
	wgConfig := site
	wgConfig.AllowedIps = []string{"172.18.21.32/24"}
	if err := ConfigurePeer(dev, wgConfig, privKey, false, 0, nil); err != nil {
		t.Fatalf("seed ConfigurePeer: %v", err)
	}

	before, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet before suppress: %v", err)
	}
	if !strings.Contains(before, "172.18.21.0/24") {
		t.Fatalf("test setup broken: seeded allowed_ip missing before suppress:\n%s", before)
	}
	if !strings.Contains(before, "100.90.128.1/32") {
		t.Fatalf("test setup broken: server IP allowed_ip missing before suppress:\n%s", before)
	}

	pm.mu.Lock()
	pm.suppressResourceRoutesLocked()
	pm.mu.Unlock()

	after, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet after suppress: %v", err)
	}
	if strings.Contains(after, "172.18.21.0/24") {
		t.Fatalf("resource allowed_ip still present in WireGuard after suppression (exit node active):\n%s", after)
	}
	if !strings.Contains(after, "100.90.128.1/32") {
		t.Fatalf("server IP allowed_ip must survive suppression (needed for site monitoring/liveness):\n%s", after)
	}

	pm.mu.Lock()
	pm.restoreResourceRoutesLocked()
	pm.mu.Unlock()

	restored, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet after restore: %v", err)
	}
	if !strings.Contains(restored, "172.18.21.0/24") {
		t.Fatalf("resource allowed_ip not restored in WireGuard after restore:\n%s", restored)
	}
	if !strings.Contains(restored, "100.90.128.1/32") {
		t.Fatalf("server IP allowed_ip missing after restore:\n%s", restored)
	}
}

// TestShouldPushAllowedIPLockedAndOwnershipFilteringWhileSuppressed covers
// the "tunnel starts with an exit node already active" case at the unit
// level: getOwnedAllowedIPs/getWireGuardAllowedIPs (what AddPeer's inline
// ownership computation, addAllowedIp, the route optimizer, etc. all defer
// to - see shouldPushAllowedIPLocked) must exclude a resource CIDR while
// suppressed even though the underlying claim/ownership is registered
// normally, and must always keep the gateway CIDR.
func TestShouldPushAllowedIPLockedAndOwnershipFilteringWhileSuppressed(t *testing.T) {
	pm := &PeerManager{
		peers:                             make(map[int]SiteConfig),
		allowedIPOwners:                   make(map[string]int),
		allowedIPClaims:                   make(map[string]map[int]bool),
		disableRoutesAndAliasesOnExitNode: true,
	}
	pm.peers[5] = SiteConfig{SiteId: 5, ServerIP: "100.90.128.1/20"}

	pm.claimAllowedIP(5, "172.18.21.0/24")
	pm.claimAllowedIP(5, gatewayCIDR)

	if !pm.shouldPushAllowedIPLocked(gatewayCIDR) {
		t.Fatalf("gateway CIDR must always be pushable")
	}
	if !pm.shouldPushAllowedIPLocked("172.18.21.0/24") {
		t.Fatalf("resource CIDR must be pushable while not suppressed")
	}
	owned := pm.getOwnedAllowedIPs(5)
	if len(owned) != 2 {
		t.Fatalf("expected both claimed CIDRs owned before suppression, got %v", owned)
	}

	pm.resourceRoutesSuppressed = true

	if pm.shouldPushAllowedIPLocked("172.18.21.0/24") {
		t.Fatalf("resource CIDR must not be pushable while suppressed")
	}
	if !pm.shouldPushAllowedIPLocked(gatewayCIDR) {
		t.Fatalf("gateway CIDR must still be pushable while suppressed")
	}

	owned = pm.getOwnedAllowedIPs(5)
	if len(owned) != 1 || owned[0] != gatewayCIDR {
		t.Fatalf("expected only the gateway CIDR owned while suppressed, got %v", owned)
	}

	wgIPs := pm.getWireGuardAllowedIPs(5)
	want := map[string]bool{"100.90.128.1/32": true, gatewayCIDR: true}
	if len(wgIPs) != len(want) {
		t.Fatalf("expected server IP + gateway CIDR only while suppressed, got %v", wgIPs)
	}
	for _, ip := range wgIPs {
		if !want[ip] {
			t.Fatalf("unexpected allowed IP %q while suppressed: %v", ip, wgIPs)
		}
	}

	pm.resourceRoutesSuppressed = false
	owned = pm.getOwnedAllowedIPs(5)
	if len(owned) != 2 {
		t.Fatalf("expected both claimed CIDRs owned again after restore, got %v", owned)
	}
}
