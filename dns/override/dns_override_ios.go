//go:build ios

package olm

import (
	"github.com/fosrl/olm/dns"
)

// SetupDNSOverride is a no-op on iOS as DNS configuration is handled by the system
func SetupDNSOverride(interfaceName string, dnsProxy *dns.DNSProxy) error {
	return nil
}

// RestoreDNSOverride is a no-op on iOS as DNS configuration is handled by the system
func RestoreDNSOverride() error {
	return nil
}