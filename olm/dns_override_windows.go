//go:build windows

package olm

import (
	"fmt"
	"net/netip"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/olm/dns"
	platform "github.com/fosrl/olm/dns/platform"
)

// SetupDNSOverride configures the system DNS to use the DNS proxy on Windows
// Uses registry-based configuration (requires interface GUID)
func SetupDNSOverride(interfaceName string, dnsProxy *dns.DNSProxy) error {
	if dnsProxy == nil {
		return fmt.Errorf("DNS proxy is nil")
	}

	// On Windows, we need to get the interface GUID from the TUN device
	// The interfaceName parameter is ignored on Windows
	if tdev == nil {
		return fmt.Errorf("TUN device is not available")
	}

	guid, err := GetInterfaceGUIDString(tdev)
	if err != nil {
		return fmt.Errorf("failed to get interface GUID: %w", err)
	}

	logger.Info("Retrieved interface GUID: %s for interface name: %s", guid, interfaceName)

	configurator, err = platform.NewWindowsDNSConfigurator(guid)
	if err != nil {
		return fmt.Errorf("failed to create Windows DNS configurator: %w", err)
	}

	logger.Info("Using Windows registry DNS configurator for GUID: %s", guid)

	// Get current DNS servers before changing
	currentDNS, err := configurator.GetCurrentDNS()
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
	originalDNS, err := configurator.SetDNS(newDNS)
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
