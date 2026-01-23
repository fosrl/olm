//go:build android

package olm

import "net/netip"

// SetupDNSOverride is a no-op on Android
// Android handles DNS through the VpnService API at the Java/Kotlin layer
func SetupDNSOverride(interfaceName string, proxyIp netip.Addr) error {
	return nil
}

// RestoreDNSOverride is a no-op on Android
func RestoreDNSOverride() error {
	return nil
}