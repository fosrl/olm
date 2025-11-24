//go:build (linux && !android) || freebsd

package dns

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// DetectBestConfigurator detects and returns the most appropriate DNS configurator for the system
// ifaceName is optional and only used for NetworkManager, systemd-resolved, and resolvconf
func DetectBestConfigurator(ifaceName string) (DNSConfigurator, error) {
	// Try systemd-resolved first (most modern)
	if IsSystemdResolvedAvailable() && ifaceName != "" {
		if configurator, err := NewSystemdResolvedDNSConfigurator(ifaceName); err == nil {
			return configurator, nil
		}
	}

	// Try NetworkManager (common on desktops)
	if IsNetworkManagerAvailable() && ifaceName != "" {
		if configurator, err := NewNetworkManagerDNSConfigurator(ifaceName); err == nil {
			return configurator, nil
		}
	}

	// Try resolvconf (common on older systems)
	if IsResolvconfAvailable() && ifaceName != "" {
		if configurator, err := NewResolvconfDNSConfigurator(ifaceName); err == nil {
			return configurator, nil
		}
	}

	// Fall back to direct file manipulation
	return NewFileDNSConfigurator()
}

// Helper functions for checking system state

// IsSystemdResolvedRunning checks if systemd-resolved is running
func IsSystemdResolvedRunning() bool {
	// Check if stub resolver is configured
	servers, err := readResolvConfDNS()
	if err != nil {
		return false
	}

	// systemd-resolved uses 127.0.0.53
	stubAddr := netip.MustParseAddr("127.0.0.53")
	for _, server := range servers {
		if server == stubAddr {
			return true
		}
	}

	return false
}

// readResolvConfDNS reads DNS servers from /etc/resolv.conf
func readResolvConfDNS() ([]netip.Addr, error) {
	content, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("read resolv.conf: %w", err)
	}

	var servers []netip.Addr
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

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

// GetSystemDNS returns the current system DNS servers
func GetSystemDNS() ([]netip.Addr, error) {
	return readResolvConfDNS()
}
