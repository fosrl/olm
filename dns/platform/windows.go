//go:build windows

package dns

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/tun"
)

var (
	dnsapi                  = syscall.NewLazyDLL("dnsapi.dll")
	dnsFlushResolverCacheFn = dnsapi.NewProc("DnsFlushResolverCache")
)

const (
	interfaceConfigPath           = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`
	interfaceConfigNameServer     = "NameServer"
	interfaceConfigDhcpNameServer = "DhcpNameServer"
)

// WindowsDNSConfigurator manages DNS settings on Windows using the registry
type WindowsDNSConfigurator struct {
	guid          string
	originalState *DNSState
}

// NewWindowsDNSConfigurator creates a new Windows DNS configurator
// Accepts a TUN device and extracts the GUID internally
func NewWindowsDNSConfigurator(tunDevice tun.Device) (*WindowsDNSConfigurator, error) {
	if tunDevice == nil {
		return nil, fmt.Errorf("TUN device is required")
	}

	guid, err := getInterfaceGUIDString(tunDevice)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface GUID: %w", err)
	}

	return &WindowsDNSConfigurator{
		guid: guid,
	}, nil
}

// newWindowsDNSConfiguratorFromGUID creates a configurator from a GUID string
// This is an internal function for use by DetectBestConfigurator
func newWindowsDNSConfiguratorFromGUID(guid string) (*WindowsDNSConfigurator, error) {
	if guid == "" {
		return nil, fmt.Errorf("interface GUID is required")
	}

	return &WindowsDNSConfigurator{
		guid: guid,
	}, nil
}

// Name returns the configurator name
func (w *WindowsDNSConfigurator) Name() string {
	return "windows-registry"
}

// SetDNS sets the DNS servers and returns the original servers
func (w *WindowsDNSConfigurator) SetDNS(servers []netip.Addr) ([]netip.Addr, error) {
	// Get current DNS settings before overriding
	originalServers, err := w.GetCurrentDNS()
	if err != nil {
		return nil, fmt.Errorf("get current DNS: %w", err)
	}

	// Store original state
	w.originalState = &DNSState{
		OriginalServers:  originalServers,
		ConfiguratorName: w.Name(),
	}

	// Set new DNS servers
	if err := w.setDNSServers(servers); err != nil {
		return nil, fmt.Errorf("set DNS servers: %w", err)
	}

	// Flush DNS cache
	if err := w.flushDNSCache(); err != nil {
		// Non-fatal, just log
		fmt.Printf("warning: failed to flush DNS cache: %v\n", err)
	}

	return originalServers, nil
}

// RestoreDNS restores the original DNS configuration
func (w *WindowsDNSConfigurator) RestoreDNS() error {
	if w.originalState == nil {
		return fmt.Errorf("no original state to restore")
	}

	// Clear the static DNS setting
	if err := w.clearDNSServers(); err != nil {
		return fmt.Errorf("clear DNS servers: %w", err)
	}

	// Flush DNS cache
	if err := w.flushDNSCache(); err != nil {
		fmt.Printf("warning: failed to flush DNS cache: %v\n", err)
	}

	return nil
}

// GetCurrentDNS returns the currently configured DNS servers
func (w *WindowsDNSConfigurator) GetCurrentDNS() ([]netip.Addr, error) {
	regKey, err := w.getInterfaceRegistryKey(registry.QUERY_VALUE)
	if err != nil {
		return nil, fmt.Errorf("get interface registry key: %w", err)
	}
	defer closeKey(regKey)

	// Try to get static DNS first
	nameServer, _, err := regKey.GetStringValue(interfaceConfigNameServer)
	if err == nil && nameServer != "" {
		return w.parseServerList(nameServer), nil
	}

	// Fall back to DHCP DNS
	dhcpNameServer, _, err := regKey.GetStringValue(interfaceConfigDhcpNameServer)
	if err == nil && dhcpNameServer != "" {
		return w.parseServerList(dhcpNameServer), nil
	}

	return []netip.Addr{}, nil
}

// setDNSServers sets the DNS servers in the registry
func (w *WindowsDNSConfigurator) setDNSServers(servers []netip.Addr) error {
	if len(servers) == 0 {
		return fmt.Errorf("no DNS servers provided")
	}

	regKey, err := w.getInterfaceRegistryKey(registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("get interface registry key: %w", err)
	}
	defer closeKey(regKey)

	// Build comma-separated or space-separated list of servers
	var serverList string
	for i, server := range servers {
		if i > 0 {
			serverList += ","
		}
		serverList += server.String()
	}

	if err := regKey.SetStringValue(interfaceConfigNameServer, serverList); err != nil {
		return fmt.Errorf("set NameServer: %w", err)
	}

	return nil
}

// clearDNSServers clears the static DNS server setting
func (w *WindowsDNSConfigurator) clearDNSServers() error {
	regKey, err := w.getInterfaceRegistryKey(registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("get interface registry key: %w", err)
	}
	defer closeKey(regKey)

	// Set empty string to revert to DHCP
	if err := regKey.SetStringValue(interfaceConfigNameServer, ""); err != nil {
		return fmt.Errorf("clear NameServer: %w", err)
	}

	return nil
}

// getInterfaceRegistryKey opens the registry key for the network interface
func (w *WindowsDNSConfigurator) getInterfaceRegistryKey(access uint32) (registry.Key, error) {
	regKeyPath := interfaceConfigPath + `\` + w.guid

	regKey, err := registry.OpenKey(registry.LOCAL_MACHINE, regKeyPath, access)
	if err != nil {
		return 0, fmt.Errorf("open HKEY_LOCAL_MACHINE\\%s: %w", regKeyPath, err)
	}

	return regKey, nil
}

// parseServerList parses a comma or space-separated list of DNS servers
func (w *WindowsDNSConfigurator) parseServerList(serverList string) []netip.Addr {
	var servers []netip.Addr

	// Split by comma or space
	parts := splitByDelimiters(serverList, []rune{',', ' '})

	for _, part := range parts {
		if addr, err := netip.ParseAddr(part); err == nil {
			servers = append(servers, addr)
		}
	}

	return servers
}

// flushDNSCache flushes the Windows DNS resolver cache
func (w *WindowsDNSConfigurator) flushDNSCache() error {
	// dnsFlushResolverCacheFn.Call() may panic if the func is not found
	defer func() {
		if rec := recover(); rec != nil {
			fmt.Printf("warning: DnsFlushResolverCache panicked: %v\n", rec)
		}
	}()

	ret, _, err := dnsFlushResolverCacheFn.Call()
	if ret == 0 {
		if err != nil && !errors.Is(err, syscall.Errno(0)) {
			return fmt.Errorf("DnsFlushResolverCache failed: %w", err)
		}
		return fmt.Errorf("DnsFlushResolverCache failed")
	}

	return nil
}

// splitByDelimiters splits a string by multiple delimiters
func splitByDelimiters(s string, delimiters []rune) []string {
	var result []string
	var current []rune

	for _, char := range s {
		isDelimiter := false
		for _, delim := range delimiters {
			if char == delim {
				isDelimiter = true
				break
			}
		}

		if isDelimiter {
			if len(current) > 0 {
				result = append(result, string(current))
				current = []rune{}
			}
		} else {
			current = append(current, char)
		}
	}

	if len(current) > 0 {
		result = append(result, string(current))
	}

	return result
}

// closeKey closes a registry key and logs errors
func closeKey(closer io.Closer) {
	if err := closer.Close(); err != nil {
		fmt.Printf("warning: failed to close registry key: %v\n", err)
	}
}

// getInterfaceGUIDString retrieves the GUID string for a Windows TUN interface
// This is required for registry-based DNS configuration on Windows
func getInterfaceGUIDString(tunDevice tun.Device) (string, error) {
	if tunDevice == nil {
		return "", fmt.Errorf("TUN device is nil")
	}

	// The wireguard-go Windows TUN device has a LUID() method
	// We need to use type assertion to access it
	type nativeTun interface {
		LUID() uint64
	}

	nativeDev, ok := tunDevice.(nativeTun)
	if !ok {
		return "", fmt.Errorf("TUN device does not support LUID retrieval (not a native Windows TUN device)")
	}

	luid := nativeDev.LUID()

	// Convert LUID to GUID using Windows API
	guid, err := luidToGUID(luid)
	if err != nil {
		return "", fmt.Errorf("failed to convert LUID to GUID: %w", err)
	}

	return guid, nil
}

// luidToGUID converts a Windows LUID (Locally Unique Identifier) to a GUID string
// using the Windows ConvertInterface* APIs
func luidToGUID(luid uint64) (string, error) {
	var guid windows.GUID

	// Load the iphlpapi.dll and get the ConvertInterfaceLuidToGuid function
	iphlpapi := windows.NewLazySystemDLL("iphlpapi.dll")
	convertLuidToGuid := iphlpapi.NewProc("ConvertInterfaceLuidToGuid")

	// Call the Windows API
	// NET_LUID is a 64-bit value on Windows
	ret, _, err := convertLuidToGuid.Call(
		uintptr(unsafe.Pointer(&luid)),
		uintptr(unsafe.Pointer(&guid)),
	)

	if ret != 0 {
		return "", fmt.Errorf("ConvertInterfaceLuidToGuid failed with code %d: %w", ret, err)
	}

	// Format the GUID as a string with curly braces
	guidStr := fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		guid.Data1, guid.Data2, guid.Data3,
		guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
		guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7])

	return guidStr, nil
}
