//go:build (linux && !android) || freebsd

package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	dbus "github.com/godbus/dbus/v5"
)

const (
	// NetworkManager D-Bus constants
	networkManagerDest                        = "org.freedesktop.NetworkManager"
	networkManagerDbusObjectNode              = "/org/freedesktop/NetworkManager"
	networkManagerDbusDNSManagerInterface     = "org.freedesktop.NetworkManager.DnsManager"
	networkManagerDbusDNSManagerObjectNode    = networkManagerDbusObjectNode + "/DnsManager"
	networkManagerDbusDNSManagerModeProperty  = networkManagerDbusDNSManagerInterface + ".Mode"
	networkManagerDbusVersionProperty         = "org.freedesktop.NetworkManager.Version"
	networkManagerDbusActiveConnsProperty     = networkManagerDest + ".ActiveConnections"
	networkManagerDbusActiveInterface         = "org.freedesktop.NetworkManager.Connection.Active"
	networkManagerDbusActiveIP4ConfigProperty = networkManagerDbusActiveInterface + ".Ip4Config"
	networkManagerDbusActiveIP6ConfigProperty = networkManagerDbusActiveInterface + ".Ip6Config"
	networkManagerDbusActiveDevicesProperty   = networkManagerDbusActiveInterface + ".Devices"
	networkManagerDbusIP4ConfigInterface      = "org.freedesktop.NetworkManager.IP4Config"
	networkManagerDbusIP6ConfigInterface      = "org.freedesktop.NetworkManager.IP6Config"
	networkManagerDbusDeviceInterface         = "org.freedesktop.NetworkManager.Device"
	networkManagerDbusDeviceDhcp4ConfigProp   = networkManagerDbusDeviceInterface + ".Dhcp4Config"
	networkManagerDbusDeviceDhcp6ConfigProp   = networkManagerDbusDeviceInterface + ".Dhcp6Config"
	networkManagerDbusDhcp4ConfigInterface    = "org.freedesktop.NetworkManager.DHCP4Config"
	networkManagerDbusDhcp6ConfigInterface    = "org.freedesktop.NetworkManager.DHCP6Config"
	networkManagerDbusGetAppliedConnMethod    = networkManagerDbusDeviceInterface + ".GetAppliedConnection"

	// NetworkManager dispatcher script path
	networkManagerDispatcherDir  = "/etc/NetworkManager/dispatcher.d"
	networkManagerConfDir        = "/etc/NetworkManager/conf.d"
	networkManagerDNSConfFile    = "olm-dns.conf"
	networkManagerDispatcherFile = "01-olm-dns"
)

// NetworkManagerDNSConfigurator manages DNS settings using NetworkManager configuration files
// This approach works with unmanaged interfaces by modifying NetworkManager's global DNS settings
type NetworkManagerDNSConfigurator struct {
	ifaceName     string
	originalState *DNSState
	confPath      string
	dispatchPath  string
}

// NewNetworkManagerDNSConfigurator creates a new NetworkManager DNS configurator
func NewNetworkManagerDNSConfigurator(ifaceName string) (*NetworkManagerDNSConfigurator, error) {
	if ifaceName == "" {
		return nil, fmt.Errorf("interface name is required")
	}

	// Check that NetworkManager conf.d directory exists
	if _, err := os.Stat(networkManagerConfDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("NetworkManager conf.d directory not found: %s", networkManagerConfDir)
	}

	configurator := &NetworkManagerDNSConfigurator{
		ifaceName:    ifaceName,
		confPath:     networkManagerConfDir + "/" + networkManagerDNSConfFile,
		dispatchPath: networkManagerDispatcherDir + "/" + networkManagerDispatcherFile,
	}

	// Clean up any stale configuration from a previous unclean shutdown
	if err := configurator.CleanupUncleanShutdown(); err != nil {
		return nil, fmt.Errorf("cleanup unclean shutdown: %w", err)
	}

	return configurator, nil
}

// Name returns the configurator name
func (n *NetworkManagerDNSConfigurator) Name() string {
	return "network-manager"
}

// SetDNS sets the DNS servers and returns the original servers
func (n *NetworkManagerDNSConfigurator) SetDNS(servers []netip.Addr) ([]netip.Addr, error) {
	// Get current DNS settings before overriding
	originalServers, err := n.GetCurrentDNS()
	if err != nil {
		// If we can't get current DNS, proceed anyway
		originalServers = []netip.Addr{}
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
	// Remove our configuration file
	if err := os.Remove(n.confPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove DNS config file: %w", err)
	}

	// Reload NetworkManager to apply the change
	if err := n.reloadNetworkManager(); err != nil {
		return fmt.Errorf("reload NetworkManager: %w", err)
	}

	return nil
}

// CleanupUncleanShutdown removes any DNS configuration left over from a previous crash
// For NetworkManager, we check if our config file exists and remove it if so.
// This ensures that if the process crashed while DNS was configured, the stale
// configuration is removed on the next startup.
func (n *NetworkManagerDNSConfigurator) CleanupUncleanShutdown() error {
	// Check if our config file exists from a previous session
	if _, err := os.Stat(n.confPath); os.IsNotExist(err) {
		// No config file, nothing to clean up
		return nil
	}

	// Remove the stale configuration file
	if err := os.Remove(n.confPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale DNS config file: %w", err)
	}

	// Reload NetworkManager to apply the change
	if err := n.reloadNetworkManager(); err != nil {
		return fmt.Errorf("reload NetworkManager after cleanup: %w", err)
	}

	return nil
}

// GetCurrentDNS returns the currently configured DNS servers by reading /etc/resolv.conf
func (n *NetworkManagerDNSConfigurator) GetCurrentDNS() ([]netip.Addr, error) {
	content, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("read resolv.conf: %w", err)
	}

	var servers []netip.Addr
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if addr, err := netip.ParseAddr(fields[1]); err == nil {
					servers = append(servers, addr)
				}
			}
		}
	}

	return servers, nil
}

// applyDNSServers applies DNS server configuration via NetworkManager config file
func (n *NetworkManagerDNSConfigurator) applyDNSServers(servers []netip.Addr) error {
	if len(servers) == 0 {
		return fmt.Errorf("no DNS servers provided")
	}

	// Build DNS server list
	var dnsServers []string
	for _, server := range servers {
		dnsServers = append(dnsServers, server.String())
	}

	// Create NetworkManager configuration file that sets global DNS
	// This overrides DNS for all connections
	configContent := fmt.Sprintf(`# Generated by Olm DNS Manager - DO NOT EDIT
# This file configures NetworkManager to use Olm's DNS proxy

[global-dns-domain-*]
servers=%s
`, strings.Join(dnsServers, ","))

	// Write the configuration file
	if err := os.WriteFile(n.confPath, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("write DNS config file: %w", err)
	}

	// Reload NetworkManager to apply the new configuration
	if err := n.reloadNetworkManager(); err != nil {
		// Try to clean up
		os.Remove(n.confPath)
		return fmt.Errorf("reload NetworkManager: %w", err)
	}

	return nil
}

// reloadNetworkManager tells NetworkManager to reload its configuration
func (n *NetworkManagerDNSConfigurator) reloadNetworkManager() error {
	conn, err := dbus.SystemBus()
	if err != nil {
		return fmt.Errorf("connect to system bus: %w", err)
	}
	defer conn.Close()

	obj := conn.Object(networkManagerDest, networkManagerDbusObjectNode)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Call Reload method with flags=0 (reload everything)
	// See: https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.html#gdbus-method-org-freedesktop-NetworkManager.Reload
	err = obj.CallWithContext(ctx, networkManagerDest+".Reload", 0, uint32(0)).Store()
	if err != nil {
		return fmt.Errorf("call Reload: %w", err)
	}

	return nil
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

// IsNetworkManagerDNSModeSupported checks if NetworkManager's DNS mode is one we can work with
// Some DNS modes delegate to other systems (like systemd-resolved) which we should use directly
func IsNetworkManagerDNSModeSupported() bool {
	conn, err := dbus.SystemBus()
	if err != nil {
		return false
	}
	defer conn.Close()

	obj := conn.Object(networkManagerDest, networkManagerDbusDNSManagerObjectNode)

	modeVariant, err := obj.GetProperty(networkManagerDbusDNSManagerModeProperty)
	if err != nil {
		// If we can't get the mode, assume it's not supported
		return false
	}

	mode, ok := modeVariant.Value().(string)
	if !ok {
		return false
	}

	// If NetworkManager is delegating DNS to systemd-resolved, we should use
	// systemd-resolved directly for better control
	switch mode {
	case "systemd-resolved":
		// NetworkManager is delegating to systemd-resolved
		// We should use systemd-resolved configurator instead
		return false
	case "dnsmasq", "unbound":
		// NetworkManager is using a local resolver that it controls
		// We can configure DNS through NetworkManager
		return true
	case "default", "none", "":
		// NetworkManager is managing DNS directly or not at all
		// We can configure DNS through NetworkManager
		return true
	default:
		// Unknown mode, try to use it
		return true
	}
}

// GetNetworkManagerDNSMode returns the current DNS mode of NetworkManager
func GetNetworkManagerDNSMode() (string, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return "", fmt.Errorf("connect to system bus: %w", err)
	}
	defer conn.Close()

	obj := conn.Object(networkManagerDest, networkManagerDbusDNSManagerObjectNode)

	modeVariant, err := obj.GetProperty(networkManagerDbusDNSManagerModeProperty)
	if err != nil {
		return "", fmt.Errorf("get DNS mode property: %w", err)
	}

	mode, ok := modeVariant.Value().(string)
	if !ok {
		return "", errors.New("DNS mode is not a string")
	}

	return mode, nil
}

// GetNetworkManagerNameservers returns the DNS servers NetworkManager knows
// about for every active connection, read live via D-Bus.
//
// olm's own NetworkManager DNS override (see NetworkManagerDNSConfigurator)
// works by writing a [global-dns-domain-*] section to
// /etc/NetworkManager/conf.d/olm-dns.conf and reloading NetworkManager. That
// is NetworkManager's global DNS override mechanism: it replaces the DNS
// servers NetworkManager's DnsManager computes as "effective" system-wide,
// for every connection - not just what gets written to /etc/resolv.conf. So
// once olm's override is active, even each connection's merged
// IP4Config/IP6Config.NameserverData (the previous, sole source used here)
// can end up reporting olm's own proxy address instead of the real network
// DNS.
//
// To recover the real DNS regardless, this also reads two further sources
// that NetworkManager's DNS merging - and therefore olm's global-dns override
// - never touches, since both are populated independently of it:
//   - Dhcp4Config/Dhcp6Config.Options["*name_servers"]: the raw nameserver
//     list straight from the DHCP lease.
//   - Device.GetAppliedConnection()'s ipv4.dns/ipv6.dns: the DNS servers
//     explicitly configured on the connection profile itself, e.g. a static
//     DNS override set by the user directly in NetworkManager (the
//     NetworkManager equivalent of a manually-set Windows adapter DNS).
//
// IP4Config/IP6Config.NameserverData is still queried too, as a fallback for
// setups the other two don't cover. Any of olm's own address that leaks
// through any of these sources is expected to be dropped by the caller via
// SystemDNSMonitor.SetExcludeIP.
func GetNetworkManagerNameservers() ([]netip.Addr, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, fmt.Errorf("connect to system bus: %w", err)
	}
	defer conn.Close()

	nm := conn.Object(networkManagerDest, networkManagerDbusObjectNode)

	activeVariant, err := nm.GetProperty(networkManagerDbusActiveConnsProperty)
	if err != nil {
		return nil, fmt.Errorf("get active connections: %w", err)
	}
	activePaths, ok := activeVariant.Value().([]dbus.ObjectPath)
	if !ok {
		return nil, errors.New("ActiveConnections is not a list of object paths")
	}

	ipConfigSources := []struct {
		activeProperty string
		configIface    string
	}{
		{networkManagerDbusActiveIP4ConfigProperty, networkManagerDbusIP4ConfigInterface},
		{networkManagerDbusActiveIP6ConfigProperty, networkManagerDbusIP6ConfigInterface},
	}

	seen := make(map[netip.Addr]bool)
	var servers []netip.Addr
	add := func(addr netip.Addr) {
		addr = addr.Unmap()
		if !addr.IsValid() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
			return
		}
		if !seen[addr] {
			seen[addr] = true
			servers = append(servers, addr)
		}
	}

	for _, activePath := range activePaths {
		active := conn.Object(networkManagerDest, activePath)

		for _, src := range ipConfigSources {
			cfgVariant, err := active.GetProperty(src.activeProperty)
			if err != nil {
				continue
			}
			cfgPath, ok := cfgVariant.Value().(dbus.ObjectPath)
			if !ok || cfgPath == "" || cfgPath == "/" {
				continue
			}

			nsVariant, err := conn.Object(networkManagerDest, cfgPath).GetProperty(src.configIface + ".NameserverData")
			if err != nil {
				continue
			}
			entries, ok := nsVariant.Value().([]map[string]dbus.Variant)
			if !ok {
				continue
			}
			for _, entry := range entries {
				addrVariant, ok := entry["address"]
				if !ok {
					continue
				}
				addrStr, ok := addrVariant.Value().(string)
				if !ok {
					continue
				}
				if addr, err := netip.ParseAddr(addrStr); err == nil {
					add(addr)
				}
			}
		}

		devicesVariant, err := active.GetProperty(networkManagerDbusActiveDevicesProperty)
		if err != nil {
			continue
		}
		devicePaths, ok := devicesVariant.Value().([]dbus.ObjectPath)
		if !ok {
			continue
		}

		for _, devicePath := range devicePaths {
			device := conn.Object(networkManagerDest, devicePath)

			for _, addr := range dhcpLeaseNameservers(conn, device, networkManagerDbusDeviceDhcp4ConfigProp, networkManagerDbusDhcp4ConfigInterface, "domain_name_servers") {
				add(addr)
			}
			for _, addr := range dhcpLeaseNameservers(conn, device, networkManagerDbusDeviceDhcp6ConfigProp, networkManagerDbusDhcp6ConfigInterface, "dhcp6_name_servers") {
				add(addr)
			}
			for _, addr := range appliedConnectionNameservers(device) {
				add(addr)
			}
		}
	}

	return servers, nil
}

// dhcpLeaseNameservers reads a space-separated nameserver list out of a
// device's Dhcp4Config/Dhcp6Config Options, straight from the DHCP lease -
// data NetworkManager's DNS merging (and therefore olm's own global-dns
// override) never touches.
func dhcpLeaseNameservers(conn *dbus.Conn, device dbus.BusObject, configProperty, configIface, optionsKey string) []netip.Addr {
	cfgVariant, err := device.GetProperty(configProperty)
	if err != nil {
		return nil
	}
	cfgPath, ok := cfgVariant.Value().(dbus.ObjectPath)
	if !ok || cfgPath == "" || cfgPath == "/" {
		return nil
	}

	optsVariant, err := conn.Object(networkManagerDest, cfgPath).GetProperty(configIface + ".Options")
	if err != nil {
		return nil
	}
	opts, ok := optsVariant.Value().(map[string]dbus.Variant)
	if !ok {
		return nil
	}
	raw, ok := opts[optionsKey]
	if !ok {
		return nil
	}
	str, ok := raw.Value().(string)
	if !ok {
		return nil
	}

	var addrs []netip.Addr
	for _, field := range strings.Fields(str) {
		if addr, err := netip.ParseAddr(field); err == nil {
			addrs = append(addrs, addr)
		}
	}
	return addrs
}

// appliedConnectionNameservers reads the ipv4.dns/ipv6.dns servers configured
// on the device's currently-applied connection profile - e.g. a static DNS
// override set by the user directly in NetworkManager - independent of DHCP
// and of olm's own global-dns override.
func appliedConnectionNameservers(device dbus.BusObject) []netip.Addr {
	var settings map[string]map[string]dbus.Variant
	var versionID uint64
	if err := device.Call(networkManagerDbusGetAppliedConnMethod, 0, uint32(0)).Store(&settings, &versionID); err != nil {
		return nil
	}

	var addrs []netip.Addr

	if ipv4, ok := settings["ipv4"]; ok {
		if dnsVariant, ok := ipv4["dns"]; ok {
			if raw, ok := dnsVariant.Value().([]uint32); ok {
				for _, v := range raw {
					var b [4]byte
					// NetworkManager encodes IPv4 addresses in this setting as
					// network-byte-order bytes reinterpreted as a native uint32.
					binary.LittleEndian.PutUint32(b[:], v)
					addrs = append(addrs, netip.AddrFrom4(b))
				}
			}
		}
	}

	if ipv6, ok := settings["ipv6"]; ok {
		if dnsVariant, ok := ipv6["dns"]; ok {
			if raw, ok := dnsVariant.Value().([][]byte); ok {
				for _, b := range raw {
					if len(b) == 16 {
						var arr [16]byte
						copy(arr[:], b)
						addrs = append(addrs, netip.AddrFrom16(arr))
					}
				}
			}
		}
	}

	return addrs
}

// GetNetworkManagerVersion returns the version of NetworkManager
func GetNetworkManagerVersion() (string, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return "", fmt.Errorf("connect to system bus: %w", err)
	}
	defer conn.Close()

	obj := conn.Object(networkManagerDest, networkManagerDbusObjectNode)

	versionVariant, err := obj.GetProperty(networkManagerDbusVersionProperty)
	if err != nil {
		return "", fmt.Errorf("get version property: %w", err)
	}

	version, ok := versionVariant.Value().(string)
	if !ok {
		return "", errors.New("version is not a string")
	}

	return version, nil
}

// CleanupStaleNetworkManagerDNS removes any stale DNS configuration left by NetworkManager
// configurator from a previous unclean shutdown. This is a static function that can be called
// without creating a configurator instance, useful for cleanup before network operations.
func CleanupStaleNetworkManagerDNS() error {
	confPath := networkManagerConfDir + "/" + networkManagerDNSConfFile

	// Check if our config file exists from a previous session
	if _, err := os.Stat(confPath); os.IsNotExist(err) {
		// No config file, nothing to clean up
		return nil
	}

	// Remove the stale configuration file
	if err := os.Remove(confPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale DNS config file: %w", err)
	}

	// Try to reload NetworkManager if it's available
	if IsNetworkManagerAvailable() {
		conn, err := dbus.SystemBus()
		if err != nil {
			return fmt.Errorf("connect to system bus for reload: %w", err)
		}
		defer conn.Close()

		obj := conn.Object(networkManagerDest, networkManagerDbusObjectNode)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := obj.CallWithContext(ctx, networkManagerDest+".Reload", 0, uint32(0)).Store(); err != nil {
			return fmt.Errorf("reload NetworkManager after cleanup: %w", err)
		}
	}

	return nil
}
