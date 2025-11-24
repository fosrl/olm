//go:build windows

package dns

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"syscall"

	"golang.org/x/sys/windows/registry"
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
// guid is the network interface GUID
func NewWindowsDNSConfigurator(guid string) (*WindowsDNSConfigurator, error) {
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
