//go:build (linux && !android) || freebsd

package olm

import (
	"fmt"
	"net/netip"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/olm/dns"
	platform "github.com/fosrl/olm/dns/platform"
)

var configurator platform.DNSConfigurator

// SetupDNSOverride configures the system DNS to use the DNS proxy on Linux/FreeBSD
// Detects the DNS manager by reading /etc/resolv.conf and verifying runtime availability
func SetupDNSOverride(interfaceName string, dnsProxy *dns.DNSProxy) error {
	if dnsProxy == nil {
		return fmt.Errorf("DNS proxy is nil")
	}

	var err error

	// Detect which DNS manager is in use by checking /etc/resolv.conf and runtime availability
	managerType := platform.DetectDNSManager(interfaceName)
	logger.Info("Detected DNS manager: %s", managerType.String())

	// Create configurator based on detected manager
	switch managerType {
	case platform.SystemdResolvedManager:
		configurator, err = platform.NewSystemdResolvedDNSConfigurator(interfaceName)
		if err == nil {
			logger.Info("Using systemd-resolved DNS configurator")
			return setDNS(dnsProxy, configurator)
		}
		logger.Warn("Failed to create systemd-resolved configurator: %v, falling back", err)

	case platform.NetworkManagerManager:
		configurator, err = platform.NewNetworkManagerDNSConfigurator(interfaceName)
		if err == nil {
			logger.Info("Using NetworkManager DNS configurator")
			return setDNS(dnsProxy, configurator)
		}
		logger.Warn("Failed to create NetworkManager configurator: %v, falling back", err)

	case platform.ResolvconfManager:
		configurator, err = platform.NewResolvconfDNSConfigurator(interfaceName)
		if err == nil {
			logger.Info("Using resolvconf DNS configurator")
			return setDNS(dnsProxy, configurator)
		}
		logger.Warn("Failed to create resolvconf configurator: %v, falling back", err)
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
