//go:build darwin && !ios

package olm

import (
	"fmt"
	"net/netip"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/olm/dns"
	platform "github.com/fosrl/olm/dns/platform"
)

var configurator platform.DNSConfigurator

// SetupDNSOverride configures the system DNS to use the DNS proxy on macOS
// Uses scutil for DNS configuration
func SetupDNSOverride(interfaceName string, dnsProxy *dns.DNSProxy) error {
	if dnsProxy == nil {
		return fmt.Errorf("DNS proxy is nil")
	}

	var err error
	configurator, err = platform.NewDarwinDNSConfigurator()
	if err != nil {
		return fmt.Errorf("failed to create Darwin DNS configurator: %w", err)
	}

	logger.Info("Using Darwin scutil DNS configurator")

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
