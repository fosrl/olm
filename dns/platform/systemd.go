//go:build linux && !android

package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	dbus "github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

const (
	systemdResolvedDest              = "org.freedesktop.resolve1"
	systemdDbusObjectNode            = "/org/freedesktop/resolve1"
	systemdDbusManagerIface          = "org.freedesktop.resolve1.Manager"
	systemdDbusGetLinkMethod         = systemdDbusManagerIface + ".GetLink"
	systemdDbusFlushCachesMethod     = systemdDbusManagerIface + ".FlushCaches"
	systemdDbusLinkInterface         = "org.freedesktop.resolve1.Link"
	systemdDbusSetDNSMethod          = systemdDbusLinkInterface + ".SetDNS"
	systemdDbusSetDefaultRouteMethod = systemdDbusLinkInterface + ".SetDefaultRoute"
	systemdDbusSetDomainsMethod      = systemdDbusLinkInterface + ".SetDomains"
	systemdDbusSetDNSSECMethod       = systemdDbusLinkInterface + ".SetDNSSEC"
	systemdDbusSetDNSOverTLSMethod   = systemdDbusLinkInterface + ".SetDNSOverTLS"
	systemdDbusRevertMethod          = systemdDbusLinkInterface + ".Revert"

	// RootZone is the root DNS zone that matches all queries
	RootZone = "."
)

// systemdDbusDNSInput maps to (iay) dbus input for SetDNS method
type systemdDbusDNSInput struct {
	Family  int32
	Address []byte
}

// systemdDbusDomainsInput maps to (sb) dbus input for SetDomains method
type systemdDbusDomainsInput struct {
	Domain    string
	MatchOnly bool
}

// SystemdResolvedDNSConfigurator manages DNS settings using systemd-resolved D-Bus API
type SystemdResolvedDNSConfigurator struct {
	ifaceName      string
	dbusLinkObject dbus.ObjectPath
	originalState  *DNSState
}

// NewSystemdResolvedDNSConfigurator creates a new systemd-resolved DNS configurator
func NewSystemdResolvedDNSConfigurator(ifaceName string) (*SystemdResolvedDNSConfigurator, error) {
	// Get network interface
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("get interface: %w", err)
	}

	// Connect to D-Bus
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, fmt.Errorf("connect to system bus: %w", err)
	}
	defer conn.Close()

	obj := conn.Object(systemdResolvedDest, systemdDbusObjectNode)

	// Get the link object for this interface
	var linkPath string
	if err := obj.Call(systemdDbusGetLinkMethod, 0, iface.Index).Store(&linkPath); err != nil {
		return nil, fmt.Errorf("get link: %w", err)
	}

	config := &SystemdResolvedDNSConfigurator{
		ifaceName:      ifaceName,
		dbusLinkObject: dbus.ObjectPath(linkPath),
	}

	// Call cleanup function here
	if err := config.CleanupUncleanShutdown(); err != nil {
		fmt.Printf("warning: cleanup unclean shutdown failed: %v\n", err)
	}

	return config, nil
}

// Name returns the configurator name
func (s *SystemdResolvedDNSConfigurator) Name() string {
	return "systemd-resolved"
}

// SetDNS sets the DNS servers and returns the original servers
func (s *SystemdResolvedDNSConfigurator) SetDNS(servers []netip.Addr) ([]netip.Addr, error) {
	// Get current DNS settings before overriding
	originalServers, err := s.GetCurrentDNS()
	if err != nil {
		// If we can't get current DNS, proceed anyway
		originalServers = []netip.Addr{}
	}

	// Store original state
	s.originalState = &DNSState{
		OriginalServers:  originalServers,
		ConfiguratorName: s.Name(),
	}

	// Apply new DNS servers
	if err := s.applyDNSServers(servers); err != nil {
		return nil, fmt.Errorf("apply DNS servers: %w", err)
	}

	return originalServers, nil
}

// RestoreDNS restores the original DNS configuration
func (s *SystemdResolvedDNSConfigurator) RestoreDNS() error {
	// Call Revert method to restore systemd-resolved defaults
	conn, err := dbus.SystemBus()
	if err != nil {
		return fmt.Errorf("connect to system bus: %w", err)
	}
	defer conn.Close()

	obj := conn.Object(systemdResolvedDest, s.dbusLinkObject)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := obj.CallWithContext(ctx, systemdDbusRevertMethod, 0).Store(); err != nil {
		return fmt.Errorf("revert DNS settings: %w", err)
	}

	// Flush DNS cache after reverting
	if err := s.flushDNSCache(); err != nil {
		fmt.Printf("warning: failed to flush DNS cache: %v\n", err)
	}

	return nil
}

// CleanupUncleanShutdown removes any DNS configuration left over from a previous crash
// For systemd-resolved, the DNS configuration is tied to the network interface.
// When the interface is destroyed and recreated, systemd-resolved automatically
// clears the per-link DNS settings, so there's nothing to clean up.
func (s *SystemdResolvedDNSConfigurator) CleanupUncleanShutdown() error {
	// systemd-resolved DNS configuration is per-link and automatically cleared
	// when the link (interface) is destroyed. Since the WireGuard interface is
	// recreated on restart, there's no leftover state to clean up.
	return nil
}

// GetCurrentDNS returns the currently configured DNS servers
// Note: systemd-resolved doesn't easily expose current per-link DNS servers via D-Bus
// This is a placeholder that returns an empty list
func (s *SystemdResolvedDNSConfigurator) GetCurrentDNS() ([]netip.Addr, error) {
	// systemd-resolved's D-Bus API doesn't have a simple way to query current DNS servers
	// We would need to parse resolvectl status output or read from /run/systemd/resolve/
	// For now, return empty list
	return []netip.Addr{}, nil
}

// applyDNSServers applies DNS server configuration via systemd-resolved
func (s *SystemdResolvedDNSConfigurator) applyDNSServers(servers []netip.Addr) error {
	if len(servers) == 0 {
		return fmt.Errorf("no DNS servers provided")
	}

	// Convert servers to systemd-resolved format
	var dnsInputs []systemdDbusDNSInput
	for _, server := range servers {
		family := unix.AF_INET
		if server.Is6() {
			family = unix.AF_INET6
		}

		dnsInputs = append(dnsInputs, systemdDbusDNSInput{
			Family:  int32(family),
			Address: server.AsSlice(),
		})
	}

	// Connect to D-Bus
	conn, err := dbus.SystemBus()
	if err != nil {
		return fmt.Errorf("connect to system bus: %w", err)
	}
	defer conn.Close()

	obj := conn.Object(systemdResolvedDest, s.dbusLinkObject)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Call SetDNS method to set the DNS servers
	if err := obj.CallWithContext(ctx, systemdDbusSetDNSMethod, 0, dnsInputs).Store(); err != nil {
		return fmt.Errorf("set DNS servers: %w", err)
	}

	// Set this interface as the default route for DNS
	// This ensures all DNS queries prefer this interface
	if err := s.callLinkMethod(systemdDbusSetDefaultRouteMethod, true); err != nil {
		return fmt.Errorf("set default route: %w", err)
	}

	// Set the root zone "." as a match-only domain
	// This captures ALL DNS queries and routes them through this interface
	domainsInput := []systemdDbusDomainsInput{
		{
			Domain:    RootZone,
			MatchOnly: true,
		},
	}
	if err := s.callLinkMethod(systemdDbusSetDomainsMethod, domainsInput); err != nil {
		return fmt.Errorf("set domains: %w", err)
	}

	// Disable DNSSEC - we don't support it and it may be enabled by default
	if err := s.callLinkMethod(systemdDbusSetDNSSECMethod, "no"); err != nil {
		// Log warning but don't fail - this is optional
		fmt.Printf("warning: failed to disable DNSSEC: %v\n", err)
	}

	// Disable DNSOverTLS - we don't support it and it may be enabled by default
	if err := s.callLinkMethod(systemdDbusSetDNSOverTLSMethod, "no"); err != nil {
		// Log warning but don't fail - this is optional
		fmt.Printf("warning: failed to disable DNSOverTLS: %v\n", err)
	}

	// Flush DNS cache to ensure new settings take effect immediately
	if err := s.flushDNSCache(); err != nil {
		fmt.Printf("warning: failed to flush DNS cache: %v\n", err)
	}

	return nil
}

// callLinkMethod is a helper to call methods on the link object
func (s *SystemdResolvedDNSConfigurator) callLinkMethod(method string, value any) error {
	conn, err := dbus.SystemBus()
	if err != nil {
		return fmt.Errorf("connect to system bus: %w", err)
	}
	defer conn.Close()

	obj := conn.Object(systemdResolvedDest, s.dbusLinkObject)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if value != nil {
		if err := obj.CallWithContext(ctx, method, 0, value).Store(); err != nil {
			return fmt.Errorf("call %s: %w", method, err)
		}
	} else {
		if err := obj.CallWithContext(ctx, method, 0).Store(); err != nil {
			return fmt.Errorf("call %s: %w", method, err)
		}
	}

	return nil
}

// flushDNSCache flushes the systemd-resolved DNS cache
func (s *SystemdResolvedDNSConfigurator) flushDNSCache() error {
	conn, err := dbus.SystemBus()
	if err != nil {
		return fmt.Errorf("connect to system bus: %w", err)
	}
	defer conn.Close()

	obj := conn.Object(systemdResolvedDest, systemdDbusObjectNode)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := obj.CallWithContext(ctx, systemdDbusFlushCachesMethod, 0).Store(); err != nil {
		return fmt.Errorf("flush caches: %w", err)
	}

	return nil
}

// IsSystemdResolvedAvailable checks if systemd-resolved is available and responsive
func IsSystemdResolvedAvailable() bool {
	conn, err := dbus.SystemBus()
	if err != nil {
		return false
	}
	defer conn.Close()

	obj := conn.Object(systemdResolvedDest, systemdDbusObjectNode)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Try to ping systemd-resolved
	if err := obj.CallWithContext(ctx, "org.freedesktop.DBus.Peer.Ping", 0).Store(); err != nil {
		return false
	}

	return true
}
