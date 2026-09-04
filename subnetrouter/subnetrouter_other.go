//go:build !linux

package subnetrouter

import (
	"fmt"
	"net/netip"
)

// Enable always fails on non-Linux platforms: there is no nftables/netfilter
// to install SNAT rules into. Callers should log this as a warning, not
// treat it as fatal.
func Enable(interfaceName string, tunnelIP netip.Addr) error {
	return fmt.Errorf("subnet router is only supported on Linux")
}

// Disable is a no-op on non-Linux platforms, since Enable never succeeds
// there and so never leaves anything to clean up.
func Disable(interfaceName string) error {
	return nil
}
