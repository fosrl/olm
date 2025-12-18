//go:build (linux && !android) || freebsd

package dns

import (
	"context"
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
	networkManagerDest                       = "org.freedesktop.NetworkManager"
	networkManagerDbusObjectNode             = "/org/freedesktop/NetworkManager"
	networkManagerDbusDNSManagerInterface    = "org.freedesktop.NetworkManager.DnsManager"
	networkManagerDbusDNSManagerObjectNode   = networkManagerDbusObjectNode + "/DnsManager"
	networkManagerDbusDNSManagerModeProperty = networkManagerDbusDNSManagerInterface + ".Mode"
	networkManagerDbusVersionProperty        = "org.freedesktop.NetworkManager.Version"

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
