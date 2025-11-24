//go:build (linux && !android) || freebsd

package olm

import (
	"fmt"
	"net/netip"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/olm/dns"
	platform "github.com/fosrl/olm/dns/platform"
)

// SetupDNSOverride configures the system DNS to use the DNS proxy on Linux/FreeBSD
// Tries systemd-resolved, NetworkManager, resolvconf, or falls back to /etc/resolv.conf
func SetupDNSOverride(interfaceName string, dnsProxy *dns.DNSProxy) error {
	if dnsProxy == nil {
		return fmt.Errorf("DNS proxy is nil")
	}

	var err error

	// Try systemd-resolved first (most modern)
	if platform.IsSystemdResolvedAvailable() && interfaceName != "" {
		configurator, err = platform.NewSystemdResolvedDNSConfigurator(interfaceName)
		if err == nil {
			logger.Info("Using systemd-resolved DNS configurator")
			return setDNS(dnsProxy, configurator)
		}
		logger.Debug("systemd-resolved not available: %v", err)
	}

	// Try NetworkManager (common on desktops)
	if platform.IsNetworkManagerAvailable() && interfaceName != "" {
		configurator, err = platform.NewNetworkManagerDNSConfigurator(interfaceName)
		if err == nil {
			logger.Info("Using NetworkManager DNS configurator")
			return setDNS(dnsProxy, configurator)
		}
		logger.Debug("NetworkManager not available: %v", err)
	}

	// Try resolvconf (common on older systems)
	if platform.IsResolvconfAvailable() && interfaceName != "" {
		configurator, err = platform.NewResolvconfDNSConfigurator(interfaceName)
		if err == nil {
			logger.Info("Using resolvconf DNS configurator")
			return setDNS(dnsProxy, configurator)
		}
		logger.Debug("resolvconf not available: %v", err)
	}

	// Fall back to direct file manipulation
	configurator, err = platform.NewFileDNSConfigurator()
	if err != nil {
		return fmt.Errorf("failed to create file DNS configurator: %w", err)
	}

	logger.Info("Using file-based DNS configurator")
	return setDNS(dnsProxy, configurator)
}

// setDNS is a helper function to set DNS and log the results
func setDNS(dnsProxy *dns.DNSProxy, conf platform.DNSConfigurator) error {
	// Get current DNS servers before changing
	currentDNS, err := conf.GetCurrentDNS()
	if err != nil {
		logger.Warn("Could not get current DNS: %v", err)
	} else {
		logger.Info("Current DNS servers: %v", currentDNS)
	}

	// Set new DNS servers to point to our proxy
	newDNS := []netip.Addr{
		dnsProxy.GetProxyIP(),
	}

	logger.Info("Setting DNS servers to: %v", newDNS)
	originalDNS, err := conf.SetDNS(newDNS)
	if err != nil {
		return fmt.Errorf("failed to set DNS: %w", err)
	}

	logger.Info("Original DNS servers backed up: %v", originalDNS)
	return nil
}

// RestoreDNSOverride restores the original DNS configuration
func RestoreDNSOverride() error {
	if configurator == nil {
		logger.Debug("No DNS configurator to restore")
		return nil
	}

	logger.Info("Restoring original DNS configuration")
	if err := configurator.RestoreDNS(); err != nil {
		return fmt.Errorf("failed to restore DNS: %w", err)
	}

	logger.Info("DNS configuration restored successfully")
	return nil
}
