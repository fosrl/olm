package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/fosrl/newt/logger"
	dnsOverride "github.com/fosrl/olm/dns/override"
)

const (
	defaultWatchdogInterval  = 5 * time.Second
	defaultWatchdogThreshold = 3
)

// runDNSWatchdogCommand handles the `olm watchdog` subcommand. The watchdog
// is meant to be spawned by an olm process after it installs a DNS
// override, and forcibly resets the system DNS if that parent dies before
// restoring it.
func runDNSWatchdogCommand(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("watchdog", flag.ContinueOnError)
	parentPID := fs.Int("parent-pid", 0, "PID of the olm process to monitor")
	socketPath := fs.String("socket", "", "Path to the olm API unix socket (optional)")
	interfaceName := fs.String("interface", "", "WireGuard interface name (used for cleanup)")
	interval := fs.Duration("interval", defaultWatchdogInterval, "Liveness check interval")
	threshold := fs.Int("threshold", defaultWatchdogThreshold, "Consecutive failures before DNS reset")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *parentPID <= 0 {
		return fmt.Errorf("--parent-pid is required and must be positive")
	}

	// Ensure logger is initialised for the watchdog process.
	logger.Init(nil)

	return dnsOverride.RunWatchdog(ctx, dnsOverride.WatchdogConfig{
		ParentPID:        *parentPID,
		SocketPath:       *socketPath,
		InterfaceName:    *interfaceName,
		CheckInterval:    *interval,
		FailureThreshold: *threshold,
	})
}

// runResetDNSCommand handles the `olm reset-dns` subcommand. It forcibly
// removes any DNS override state left behind on the system.
func runResetDNSCommand(args []string) error {
	fs := flag.NewFlagSet("reset-dns", flag.ContinueOnError)
	interfaceName := fs.String("interface", "olm", "WireGuard interface name")

	if err := fs.Parse(args); err != nil {
		return err
	}

	logger.Init(nil)

	if err := dnsOverride.ForceResetDNS(*interfaceName); err != nil {
		return err
	}

	fmt.Println("DNS reset complete")
	return nil
}
