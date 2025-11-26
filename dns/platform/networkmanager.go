//go:build (linux && !android) || freebsd

package dns

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/fosrl/newt/logger"
	dbus "github.com/godbus/dbus/v5"
)

const (
	networkManagerDest                     = "org.freedesktop.NetworkManager"
	networkManagerDbusObjectNode           = "/org/freedesktop/NetworkManager"
	networkManagerDbusDNSManagerObjectNode = networkManagerDbusObjectNode + "/DnsManager"
	networkManagerDbusDNSManagerInterface  = "org.freedesktop.NetworkManager.DnsManager"
	networkManagerDbusDNSManagerMode       = networkManagerDbusDNSManagerInterface + ".Mode"
	networkManagerDbusGetDeviceByIPIface   = networkManagerDest + ".GetDeviceByIpIface"
	networkManagerDbusDeviceInterface      = "org.freedesktop.NetworkManager.Device"
	networkManagerDbusDeviceGetApplied     = networkManagerDbusDeviceInterface + ".GetAppliedConnection"
	networkManagerDbusDeviceReapply        = networkManagerDbusDeviceInterface + ".Reapply"
	networkManagerDbusPrimaryConnection    = networkManagerDest + ".PrimaryConnection"
	networkManagerDbusActiveConnInterface  = "org.freedesktop.NetworkManager.Connection.Active"
	networkManagerDbusActiveConnDevices    = networkManagerDbusActiveConnInterface + ".Devices"
	networkManagerDbusIPv4Key              = "ipv4"
	networkManagerDbusIPv6Key              = "ipv6"
	networkManagerDbusDNSKey               = "dns"
	networkManagerDbusDNSSearchKey         = "dns-search"
	networkManagerDbusDNSPriorityKey       = "dns-priority"
	networkManagerDbusPrimaryDNSPriority   = int32(-500)
)

type networkManagerConnSettings map[string]map[string]dbus.Variant
type networkManagerConfigVersion uint64

// cleanDeprecatedSettings removes deprecated settings that are still returned by
// GetAppliedConnection but can't be reapplied
func (s networkManagerConnSettings) cleanDeprecatedSettings() {
	for _, key := range []string{"addresses", "routes"} {
		if ipv4Settings, ok := s[networkManagerDbusIPv4Key]; ok {
			delete(ipv4Settings, key)
		}
		if ipv6Settings, ok := s[networkManagerDbusIPv6Key]; ok {
			delete(ipv6Settings, key)
		}
	}
}

// NetworkManagerDNSConfigurator manages DNS settings using NetworkManager D-Bus API
// Note: This configures DNS on the PRIMARY active connection, not on tunnel interfaces
// which are typically unmanaged by NetworkManager
type NetworkManagerDNSConfigurator struct {
	ifaceName      string
	dbusLinkObject dbus.ObjectPath
	originalState  *DNSState
}

// NewNetworkManagerDNSConfigurator creates a new NetworkManager DNS configurator
// It finds the primary active connection's device to configure DNS on
func NewNetworkManagerDNSConfigurator(ifaceName string) (*NetworkManagerDNSConfigurator, error) {
	// First, try to get the primary connection's device
	// This is what we should configure DNS on, not the tunnel interface
	primaryDevice, err := getPrimaryConnectionDevice()
	if err != nil {
		logger.Warn("Could not get primary connection device: %v, trying specified interface", err)
		// Fall back to trying the specified interface
		primaryDevice, err = getDeviceByInterface(ifaceName)
		if err != nil {
			return nil, fmt.Errorf("get device for interface %s: %w", ifaceName, err)
		}
	}

	logger.Info("NetworkManager: using device %s for DNS configuration", primaryDevice)

	return &NetworkManagerDNSConfigurator{
		ifaceName:      ifaceName,
		dbusLinkObject: primaryDevice,
	}, nil
}

// getPrimaryConnectionDevice gets the device associated with NetworkManager's primary connection
func getPrimaryConnectionDevice() (dbus.ObjectPath, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return "", fmt.Errorf("connect to system bus: %w", err)
	}
	defer conn.Close()

	// Get the primary connection path
	nmObj := conn.Object(networkManagerDest, networkManagerDbusObjectNode)
	primaryConnVariant, err := nmObj.GetProperty(networkManagerDbusPrimaryConnection)
	if err != nil {
		return "", fmt.Errorf("get primary connection: %w", err)
	}

	primaryConnPath, ok := primaryConnVariant.Value().(dbus.ObjectPath)
	if !ok || primaryConnPath == "/" || primaryConnPath == "" {
		return "", fmt.Errorf("no primary connection available")
	}

	logger.Debug("NetworkManager primary connection: %s", primaryConnPath)

	// Get the devices for this active connection
	activeConnObj := conn.Object(networkManagerDest, primaryConnPath)
	devicesVariant, err := activeConnObj.GetProperty(networkManagerDbusActiveConnDevices)
	if err != nil {
		return "", fmt.Errorf("get active connection devices: %w", err)
	}

	devices, ok := devicesVariant.Value().([]dbus.ObjectPath)
	if !ok || len(devices) == 0 {
		return "", fmt.Errorf("no devices for primary connection")
	}

	logger.Debug("NetworkManager primary connection device: %s", devices[0])
	return devices[0], nil
}

// getDeviceByInterface gets the device path for a specific interface name
func getDeviceByInterface(ifaceName string) (dbus.ObjectPath, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return "", fmt.Errorf("connect to system bus: %w", err)
	}
	defer conn.Close()

	obj := conn.Object(networkManagerDest, networkManagerDbusObjectNode)

	var linkPath string
	if err := obj.Call(networkManagerDbusGetDeviceByIPIface, 0, ifaceName).Store(&linkPath); err != nil {
		return "", fmt.Errorf("get device by interface: %w", err)
	}

	return dbus.ObjectPath(linkPath), nil
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
// Note: NetworkManager may not have DNS settings on the interface level
// if DNS is being managed globally, so this may return empty
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

	// Clean deprecated settings that can't be reapplied
	connSettings.cleanDeprecatedSettings()

	// Ensure IPv4 settings map exists
	if connSettings[networkManagerDbusIPv4Key] == nil {
		connSettings[networkManagerDbusIPv4Key] = make(map[string]dbus.Variant)
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

	// Set dns-search with "~." to make this a catch-all DNS route
	// This is critical for NetworkManager to route all DNS queries through our server
	// See: https://wiki.gnome.org/Projects/NetworkManager/DNS
	connSettings[networkManagerDbusIPv4Key][networkManagerDbusDNSSearchKey] = dbus.MakeVariant([]string{"~."})

	logger.Info("NetworkManager: applying DNS servers %v with priority %d and search domains [~.]",
		servers, networkManagerDbusPrimaryDNSPriority)

	// Reapply connection settings
	if err := n.reApplyConnectionSettings(connSettings, configVersion); err != nil {
		return fmt.Errorf("reapply connection settings: %w", err)
	}

	logger.Info("NetworkManager: successfully applied DNS configuration to interface %s", n.ifaceName)

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
// Returns empty slice if no DNS is configured on this interface
func (n *NetworkManagerDNSConfigurator) extractDNSServers(connSettings networkManagerConnSettings) []netip.Addr {
	var servers []netip.Addr

	ipv4Settings, ok := connSettings[networkManagerDbusIPv4Key]
	if !ok {
		return servers
	}

	dnsVariant, ok := ipv4Settings[networkManagerDbusDNSKey]
	if !ok {
		// DNS not configured on this interface - this is normal
		return servers
	}

	dnsServers, ok := dnsVariant.Value().([]uint32)
	if !ok || dnsServers == nil {
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
		logger.Debug("NetworkManager ping failed: %v", err)
		return false
	}

	return true
}

// GetNetworkManagerDNSMode returns the DNS mode NetworkManager is using
// Possible values: "dnsmasq", "systemd-resolved", "unbound", "default", etc.
func GetNetworkManagerDNSMode() (string, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return "", fmt.Errorf("connect to system bus: %w", err)
	}
	defer conn.Close()

	obj := conn.Object(networkManagerDest, networkManagerDbusDNSManagerObjectNode)

	variant, err := obj.GetProperty(networkManagerDbusDNSManagerMode)
	if err != nil {
		return "", fmt.Errorf("get DNS mode property: %w", err)
	}

	mode, ok := variant.Value().(string)
	if !ok {
		return "", fmt.Errorf("DNS mode is not a string")
	}

	return mode, nil
}

// IsNetworkManagerDNSModeSupported checks if NetworkManager's DNS mode
// allows direct DNS configuration via D-Bus
func IsNetworkManagerDNSModeSupported() bool {
	mode, err := GetNetworkManagerDNSMode()
	if err != nil {
		logger.Debug("Failed to get NetworkManager DNS mode: %v", err)
		return false
	}

	logger.Debug("NetworkManager DNS mode: %s", mode)

	// These modes support D-Bus DNS configuration
	switch mode {
	case "dnsmasq", "unbound", "default":
		return true
	case "systemd-resolved":
		// When NM delegates to systemd-resolved, we should use systemd-resolved directly
		logger.Warn("NetworkManager is using systemd-resolved mode - consider using systemd-resolved configurator instead")
		return false
	default:
		logger.Warn("Unknown NetworkManager DNS mode: %s", mode)
		return true // Try anyway
	}
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
