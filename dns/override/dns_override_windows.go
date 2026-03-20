//go:build windows

package olm

import (
	"fmt"
	"net/netip"

	"github.com/fosrl/newt/logger"
	platform "github.com/fosrl/olm/dns/platform"
)

var configurator platform.DNSConfigurator

// SetupDNSOverride configures the system DNS to use the DNS proxy on Windows
// Uses registry-based configuration (automatically extracts interface GUID)
func SetupDNSOverride(interfaceName string, proxyIp netip.Addr) error {
	var err error
	configurator, err = platform.NewWindowsDNSConfigurator(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to create Windows DNS configurator: %w", err)
	}

	logger.Info("Using Windows registry DNS configurator for interface: %s", interfaceName)

	// Get current DNS servers before changing
	currentDNS, err := configurator.GetCurrentDNS()
	if err != nil {
		logger.Warn("Could not get current DNS: %v", err)
	} else {
		logger.Info("Current DNS servers: %v", currentDNS)
	}

	// Set new DNS servers to point to our proxy
	newDNS := []netip.Addr{
		proxyIp,
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

// CleanupStaleState removes any stale DNS configuration left over from a previous
// unclean shutdown (e.g., system crash, power loss while tunnel was active).
// This function should be called early during startup, before any network operations,
// to ensure DNS is working properly.
//
// On Windows, DNS configuration is tied to the interface GUID. When the WireGuard
// interface is recreated, it gets a new GUID, so there's no stale state to clean up.
func CleanupStaleState(interfaceName string) error {
	// Windows DNS configuration via registry is interface-specific.
	// When the WireGuard interface is recreated, it gets a new GUID,
	// so there's no leftover state to clean up from previous sessions.
	_ = interfaceName
	logger.Debug("Windows DNS cleanup: no stale state to clean (interface-specific)")
	return nil
}
