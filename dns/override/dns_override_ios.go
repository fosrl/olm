//go:build ios

package olm

import "net/netip"

// SetupDNSOverride is a no-op on iOS as DNS configuration is handled by the system
func SetupDNSOverride(interfaceName string, proxyIp netip.Addr) error {
	return nil
}

// RestoreDNSOverride is a no-op on iOS as DNS configuration is handled by the system
func RestoreDNSOverride() error {
	return nil
}