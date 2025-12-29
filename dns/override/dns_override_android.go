//go:build android

package olm

import (
	"github.com/fosrl/olm/dns"
)

// SetupDNSOverride is a no-op on Android
// Android handles DNS through the VpnService API at the Java/Kotlin layer
func SetupDNSOverride(interfaceName string, dnsProxy *dns.DNSProxy) error {
	return nil
}

// RestoreDNSOverride is a no-op on Android
func RestoreDNSOverride() error {
	return nil
}