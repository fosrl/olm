//go:build (linux && !android) || freebsd

package dns

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"

	dbus "github.com/godbus/dbus/v5"
)

const (
	networkManagerDest                   = "org.freedesktop.NetworkManager"
	networkManagerDbusObjectNode         = "/org/freedesktop/NetworkManager"
	networkManagerDbusGetDeviceByIPIface = networkManagerDest + ".GetDeviceByIpIface"
	networkManagerDbusDeviceInterface    = "org.freedesktop.NetworkManager.Device"
	networkManagerDbusDeviceGetApplied   = networkManagerDbusDeviceInterface + ".GetAppliedConnection"
	networkManagerDbusDeviceReapply      = networkManagerDbusDeviceInterface + ".Reapply"
	networkManagerDbusIPv4Key            = "ipv4"
	networkManagerDbusDNSKey             = "dns"
	networkManagerDbusDNSPriorityKey     = "dns-priority"
	networkManagerDbusPrimaryDNSPriority = int32(-500)
)

type networkManagerConnSettings map[string]map[string]dbus.Variant
type networkManagerConfigVersion uint64

// NetworkManagerDNSConfigurator manages DNS settings using NetworkManager D-Bus API
type NetworkManagerDNSConfigurator struct {
	ifaceName      string
	dbusLinkObject dbus.ObjectPath
	originalState  *DNSState
}

// NewNetworkManagerDNSConfigurator creates a new NetworkManager DNS configurator
func NewNetworkManagerDNSConfigurator(ifaceName string) (*NetworkManagerDNSConfigurator, error) {
	// Get the D-Bus link object for this interface
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, fmt.Errorf("connect to system bus: %w", err)
	}
	defer conn.Close()

	obj := conn.Object(networkManagerDest, networkManagerDbusObjectNode)

	var linkPath string
	if err := obj.Call(networkManagerDbusGetDeviceByIPIface, 0, ifaceName).Store(&linkPath); err != nil {
		return nil, fmt.Errorf("get device by interface: %w", err)
	}

	return &NetworkManagerDNSConfigurator{
		ifaceName:      ifaceName,
		dbusLinkObject: dbus.ObjectPath(linkPath),
	}, nil
}

// Name returns the configurator name
func (n *NetworkManagerDNSConfigurator) Name() string {
	return "networkmanager-dbus"
}

// SetDNS sets the DNS servers and returns the original servers
func (n *NetworkManagerDNSConfigurator) SetDNS(servers []netip.Addr) ([]netip.Addr, error) {
	// Get current DNS settings before overriding
	originalServers, err := n.GetCurrentDNS()
	if err != nil {
		return nil, fmt.Errorf("get current DNS: %w", err)
	}

	// Store original state
	n.originalState = &DNSState{
		OriginalServers:  originalServers,
		ConfiguratorName: n.Name(),
	}

	// Apply new DNS servers
	if err := n.applyDNSServers(servers); err != nil {
		return nil, fmt.Errorf("apply DNS servers: %w", err)
	}

	return originalServers, nil
}

// RestoreDNS restores the original DNS configuration
func (n *NetworkManagerDNSConfigurator) RestoreDNS() error {
	if n.originalState == nil {
		return fmt.Errorf("no original state to restore")
	}

	// Restore original DNS servers
	if err := n.applyDNSServers(n.originalState.OriginalServers); err != nil {
		return fmt.Errorf("restore DNS servers: %w", err)
	}

	return nil
}

// GetCurrentDNS returns the currently configured DNS servers
func (n *NetworkManagerDNSConfigurator) GetCurrentDNS() ([]netip.Addr, error) {
	connSettings, _, err := n.getAppliedConnectionSettings()
	if err != nil {
		return nil, fmt.Errorf("get connection settings: %w", err)
	}

	return n.extractDNSServers(connSettings), nil
}

// applyDNSServers applies DNS server configuration via NetworkManager
func (n *NetworkManagerDNSConfigurator) applyDNSServers(servers []netip.Addr) error {
	connSettings, configVersion, err := n.getAppliedConnectionSettings()
	if err != nil {
		return fmt.Errorf("get connection settings: %w", err)
	}

	// Convert DNS servers to NetworkManager format (uint32 little-endian)
	var dnsServers []uint32
	for _, server := range servers {
		if server.Is4() {
			dnsServers = append(dnsServers, binary.LittleEndian.Uint32(server.AsSlice()))
		}
	}

	if len(dnsServers) == 0 {
		return fmt.Errorf("no valid IPv4 DNS servers provided")
	}

	// Update DNS settings
	connSettings[networkManagerDbusIPv4Key][networkManagerDbusDNSKey] = dbus.MakeVariant(dnsServers)
	connSettings[networkManagerDbusIPv4Key][networkManagerDbusDNSPriorityKey] = dbus.MakeVariant(networkManagerDbusPrimaryDNSPriority)

	// Reapply connection settings
	if err := n.reApplyConnectionSettings(connSettings, configVersion); err != nil {
		return fmt.Errorf("reapply connection settings: %w", err)
	}

	return nil
}

// getAppliedConnectionSettings retrieves current NetworkManager connection settings
func (n *NetworkManagerDNSConfigurator) getAppliedConnectionSettings() (networkManagerConnSettings, networkManagerConfigVersion, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, 0, fmt.Errorf("connect to system bus: %w", err)
	}
	defer conn.Close()

	obj := conn.Object(networkManagerDest, n.dbusLinkObject)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var connSettings networkManagerConnSettings
	var configVersion networkManagerConfigVersion

	if err := obj.CallWithContext(ctx, networkManagerDbusDeviceGetApplied, 0, uint32(0)).Store(&connSettings, &configVersion); err != nil {
		return nil, 0, fmt.Errorf("get applied connection: %w", err)
	}

	return connSettings, configVersion, nil
}

// reApplyConnectionSettings applies new connection settings via NetworkManager
func (n *NetworkManagerDNSConfigurator) reApplyConnectionSettings(connSettings networkManagerConnSettings, configVersion networkManagerConfigVersion) error {
	conn, err := dbus.SystemBus()
	if err != nil {
		return fmt.Errorf("connect to system bus: %w", err)
	}
	defer conn.Close()

	obj := conn.Object(networkManagerDest, n.dbusLinkObject)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := obj.CallWithContext(ctx, networkManagerDbusDeviceReapply, 0, connSettings, configVersion, uint32(0)).Store(); err != nil {
		return fmt.Errorf("reapply connection: %w", err)
	}

	return nil
}

// extractDNSServers extracts DNS servers from connection settings
func (n *NetworkManagerDNSConfigurator) extractDNSServers(connSettings networkManagerConnSettings) []netip.Addr {
	var servers []netip.Addr

	ipv4Settings, ok := connSettings[networkManagerDbusIPv4Key]
	if !ok {
		return servers
	}

	dnsVariant, ok := ipv4Settings[networkManagerDbusDNSKey]
	if !ok {
		return servers
	}

	dnsServers, ok := dnsVariant.Value().([]uint32)
	if !ok {
		return servers
	}

	for _, dnsServer := range dnsServers {
		// Convert uint32 back to IP address
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, dnsServer)

		if addr, ok := netip.AddrFromSlice(buf); ok {
			servers = append(servers, addr)
		}
	}

	return servers
}

// IsNetworkManagerAvailable checks if NetworkManager is available and responsive
func IsNetworkManagerAvailable() bool {
	conn, err := dbus.SystemBus()
	if err != nil {
		return false
	}
	defer conn.Close()

	obj := conn.Object(networkManagerDest, networkManagerDbusObjectNode)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Try to ping NetworkManager
	if err := obj.CallWithContext(ctx, "org.freedesktop.DBus.Peer.Ping", 0).Store(); err != nil {
		return false
	}

	return true
}

// GetNetworkInterfaces returns available network interfaces
func GetNetworkInterfaces() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("get interfaces: %w", err)
	}

	var names []string
	for _, iface := range interfaces {
		// Skip loopback
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		names = append(names, iface.Name)
	}

	return names, nil
}
