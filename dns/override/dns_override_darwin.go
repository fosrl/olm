//go:build darwin && !ios

package olm

import (
	"fmt"
	"net/netip"

	"github.com/fosrl/newt/logger"
	platform "github.com/fosrl/olm/dns/platform"
)

var configurator platform.DNSConfigurator

// SetupDNSOverride configures the system DNS to use the DNS proxy on macOS
// Uses scutil for DNS configuration
func SetupDNSOverride(interfaceName string, proxyIp netip.Addr) error {
	// Defensively clear any stale DNS state from a previous unclean shutdown
	// before installing the new override. This makes a second tunnel start
	// safe even if the previous client crashed without restoring DNS.
	if err := CleanupStaleState(interfaceName); err != nil {
		logger.Warn("Pre-setup stale DNS cleanup failed (continuing): %v", err)
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
// On macOS, this cleans up any scutil DNS keys that were created but not removed.
func CleanupStaleState(interfaceName string) error {
	_ = interfaceName
	if err := platform.CleanupStaleDarwinDNS(); err != nil {
		logger.Warn("Failed to cleanup stale Darwin DNS config: %v", err)
		return fmt.Errorf("Darwin DNS cleanup: %w", err)
	}

	logger.Info("Stale DNS state cleanup completed successfully")
	return nil
}

// ForceResetDNS forcibly clears any DNS override state, whether or not the
// current process installed it. This is intended for the "reset-dns" CLI
// command and for the watchdog process to recover from a stuck override
// left behind by a crashed client.
func ForceResetDNS(interfaceName string) error {
	logger.Info("Forcing DNS reset on Darwin (interface=%s)", interfaceName)

	// First clean up any persisted state from a previous session.
	cleanupErr := CleanupStaleState(interfaceName)

	// Then, if the current process happens to hold a live configurator,
	// instruct it to restore DNS as well so in-memory state is consistent.
	if configurator != nil {
		if err := configurator.RestoreDNS(); err != nil {
			logger.Warn("ForceResetDNS: in-memory restore failed: %v", err)
		}
		configurator = nil
	}

	// As a last-resort defense, sweep any scutil keys matching our naming
	// convention even if no state file exists.
	if err := platform.SweepOlmScutilKeys(); err != nil {
		logger.Warn("ForceResetDNS: scutil sweep failed: %v", err)
	}

	return cleanupErr
}
